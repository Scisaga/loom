package control

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"reflect"
	"strconv"
	"strings"
)

// CheckTransportReplacement verifies the original signed schema 3 bytes only
// for an explicitly requested, one-time forward replacement. It never returns
// a historical View, regenerates its runtime, or admits it to current decoding.
func CheckTransportReplacement(previousBytes []byte, next DeviceViewEnvelope, trusted BootstrapInvite, highWater []FactFrontier) error {
	if err := VerifyDeviceViewEnvelope(next, trusted); err != nil {
		return err
	}
	parsed, err := parseContractJSON(previousBytes, ContractDecodeLimits{MaxBytes: 5 << 20, MaxDepth: 128, MaxItems: 1 << 20})
	if err != nil || !bytes.Equal(previousBytes, appendContractJSON(nil, parsed)) {
		return errors.New("historical envelope is not bounded canonical JSON")
	}
	object, ok := parsed.(map[string]any)
	if !ok {
		return errors.New("historical envelope is not an object")
	}
	view, ok := object["view"].(map[string]any)
	if !ok {
		return errors.New("historical envelope has no View")
	}
	// The old signed execution sections remain opaque evidence. Only the
	// identity, member proof and authenticated progress are compared. This
	// closed top-level boundary deliberately has no old executable DTO.
	known := map[string]bool{"link_probe_credentials": true}
	viewType := reflect.TypeFor[DeviceView]()
	for i := range viewType.NumField() {
		name, option, _ := strings.Cut(viewType.Field(i).Tag.Get("json"), ",")
		if name == "network_id" {
			known[name] = true
			continue
		}
		known[name] = true
		if _, found := view[name]; !found && option != "omitempty" {
			return errors.New("historical View field is missing")
		}
	}
	for name := range view {
		if !known[name] {
			return errors.New("unknown historical View field or already current View")
		}
	}
	if network, present := view["network_id"]; present {
		if network != trusted.NetworkID {
			return errors.New("historical View network differs")
		}
		// Recognize only the retired independent-session projection. Its JSON is
		// inspected as opaque evidence and is never returned to a runtime decoder.
		profile, ok := view["runtime_profile"].(map[string]any)
		config, _ := profile["config"].(string)
		var retired struct {
			Endpoints []struct {
				Type string `json:"type"`
				Tag  string `json:"tag"`
			} `json:"endpoints"`
			DNS struct {
				FakeIP struct {
					Range string `json:"inet6_range"`
				} `json:"fakeip"`
			} `json:"dns"`
		}
		recognized := false
		if ok && json.Unmarshal([]byte(config), &retired) == nil {
			recognized = retired.DNS.FakeIP.Range == "2001:db8:8000::/49"
			for _, endpoint := range retired.Endpoints {
				recognized = recognized || endpoint.Type == "wireguard" && strings.HasPrefix(endpoint.Tag, "wg-send.") && ValidateID(strings.TrimPrefix(endpoint.Tag, "wg-send.")) == nil
			}
		}
		recognized = recognized || recognizeHistoricalSharedWG(view, config)
		if !recognized {
			return errors.New("historical View is not a retired WG projection")
		}
	}
	viewBody := appendContractJSON(nil, view)
	sum := sha256.Sum256(append([]byte("loom-device-view-digest-v3\x00"), viewBody...))
	if object["view_digest"] != "sha256:"+hex.EncodeToString(sum[:]) {
		return errors.New("historical View digest is invalid")
	}
	// Decode the unchanged envelope header with the current exact field set.
	// The replacement below is private scratch space, never signed or persisted.
	currentView, err := contractJSONValue(reflect.ValueOf(next.View))
	if err != nil {
		return err
	}
	object["view"] = currentView
	var previous DeviceViewEnvelope
	if err := assignContractJSON(object, reflect.ValueOf(&previous).Elem()); err != nil {
		return err
	}
	object["view"] = view
	previous.View = DeviceView{}
	for name, target := range map[string]any{
		"schema": &previous.View.Schema, "device_id": &previous.View.DeviceID,
		"device_public_key": &previous.View.DevicePublicKey, "platform": &previous.View.Platform,
		"responsibilities": &previous.View.Responsibilities, "endpoints": &previous.View.Endpoints,
	} {
		if err := DecodeCanonical(appendContractJSON(nil, view[name]), target, ContractDecodeLimits{MaxBytes: 5 << 20, MaxDepth: 128, MaxItems: 1 << 20}); err != nil {
			return err
		}
	}
	if previous.Schema != 3 || previous.View.Schema != 3 || previous.NetworkID != trusted.NetworkID || previous.GenesisDigest != trusted.GenesisDigest ||
		previous.View.DeviceID != trusted.Material.Payload.(Invite).DeviceID || ValidatePublicKey(previous.View.DevicePublicKey) != nil ||
		!validatePlatform(previous.View.Platform) || validateResponsibilities(previous.View.Responsibilities, true) != nil || validateFactFrontier(previous.FactFrontier) != nil {
		return errors.New("historical identity or authenticated progress is invalid")
	}
	config, err := VerifyControlProofExtension(previous.ControlProof, trusted.ControlProof, trusted.NetworkID, trusted.GenesisDigest)
	if err != nil {
		return err
	}
	member, found := proofMember(config, previous.IssuerControlID)
	keyID, err := KeyID(member.PublicKey)
	if !found || err != nil || keyID != previous.IssuerKeyID {
		return errors.New("historical signer is not a proven member")
	}
	proven := map[string]bool{}
	for _, member := range config.Members {
		id, _ := KeyID(member.PublicKey)
		proven[id] = true
	}
	for _, certificate := range previous.ControlProof.Successors {
		for _, seal := range certificate.Config.SealedKeys {
			if frontierFor(previous.FactFrontier, seal.KeyID) != seal {
				return errors.New("historical frontier differs from its certified seal")
			}
			proven[seal.KeyID] = true
		}
	}
	for _, prefix := range previous.FactFrontier {
		if !proven[prefix.KeyID] {
			return errors.New("historical frontier key is not proven")
		}
	}
	delete(object, "signature")
	key, _ := base64.RawURLEncoding.DecodeString(member.PublicKey)
	signature, err := base64.RawURLEncoding.DecodeString(previous.Signature)
	if err != nil || len(signature) != ed25519.SignatureSize || base64.RawURLEncoding.EncodeToString(signature) != previous.Signature ||
		!ed25519.Verify(ed25519.PublicKey(key), append([]byte(deviceViewDomain), appendContractJSON(nil, object)...), signature) {
		return errors.New("historical envelope signature is invalid")
	}
	return CheckDeviceViewAdvance(next, previous, highWater)
}

// This recognizes a finite historical shared-native shape as opaque signed
// evidence. It returns no executable DTO and is called only by the explicit
// replacement entry, never by current decoding, startup or synchronization.
func recognizeHistoricalSharedWG(view map[string]any, config string) bool {
	profile, ok := view["runtime_profile"].(map[string]any)
	if !ok || len(profile) != 2 || profile["kind"] != "sing_box" {
		return false
	}
	parsed, err := parseContractJSON([]byte(config), ContractDecodeLimits{MaxBytes: 5 << 20, MaxDepth: 128, MaxItems: 1 << 20})
	if err != nil || !bytes.Equal([]byte(config), appendContractJSON(nil, parsed)) {
		return false
	}
	document, ok := parsed.(map[string]any)
	if !ok {
		return false
	}
	for key := range document {
		if key != "outbounds" && key != "route" && key != "endpoints" && key != "dns" {
			return false
		}
	}
	if _, ok := document["outbounds"].([]any); !ok {
		return false
	}
	if _, ok := document["route"].(map[string]any); !ok {
		return false
	}
	resources := map[string]TransportResource{}
	var values []TransportResource
	if DecodeCanonical(appendContractJSON(nil, view["resources"]), &values, ContractDecodeLimits{MaxBytes: 5 << 20, MaxDepth: 32, MaxItems: 1 << 20}) != nil {
		return false
	}
	for _, value := range values {
		if _, exists := resources[value.ID]; exists {
			return false
		}
		resources[value.ID] = value
	}
	var links []NetworkLink
	if DecodeCanonical(appendContractJSON(nil, view["links"]), &links, ContractDecodeLimits{MaxBytes: 5 << 20, MaxDepth: 32, MaxItems: 1 << 20}) != nil || len(links) == 0 {
		return false
	}
	for i, link := range links {
		if ValidateDigest(link.ID) == nil || i > 0 && links[i-1].ID >= link.ID {
			return false
		}
		if _, _, _, err := linkResources(link, resources); err != nil {
			return false
		}
	}
	endpoints, ok := document["endpoints"].([]any)
	if !ok || len(endpoints) != 1 {
		return false
	}
	endpoint, ok := endpoints[0].(map[string]any)
	if !ok || endpoint["type"] != "wireguard" || endpoint["system"] != false {
		return false
	}
	for key := range endpoint {
		switch key {
		case "type", "tag", "system", "address", "source_routes", "peers", "listen_port", "private_key":
		default:
			return false
		}
	}
	owner, hasOwned, err := ownedWireGuard(values, stringContractValue(view["device_id"]))
	if err != nil {
		return false
	}
	if hasOwned {
		port, ok := endpoint["listen_port"].(json.Number)
		if !ok || port.String() != fmt.Sprint(owner.DialPort) || endpoint["tag"] != ResourceInboundTag(owner.ID) || endpoint["private_key"] != nil {
			return false
		}
	} else {
		private, ok := endpoint["private_key"].(string)
		key, err := base64.StdEncoding.DecodeString(private)
		defer clear(key)
		if !ok || err != nil || len(key) != 32 || base64.StdEncoding.EncodeToString(key) != private || endpoint["tag"] != wireGuardSharedCredential || endpoint["listen_port"] != nil {
			return false
		}
	}
	addresses, ok := endpoint["address"].([]any)
	if !ok || len(addresses) == 0 {
		return false
	}
	previous := ""
	for _, raw := range addresses {
		text, ok := raw.(string)
		prefix, err := netip.ParsePrefix(text)
		if !ok || err != nil || prefix.String() != text || !prefix.Addr().Is6() || !prefix.Addr().IsPrivate() || prefix.Bits() != 128 || text <= previous {
			return false
		}
		previous = text
	}
	routes, ok := endpoint["source_routes"].([]any)
	if !ok {
		return false
	}
	for _, raw := range routes {
		value, ok := raw.(map[string]any)
		if !ok || len(value) != 2 {
			return false
		}
		source, err := netip.ParseAddr(stringContractValue(value["source"]))
		destination, e := netip.ParsePrefix(stringContractValue(value["destination"]))
		if err != nil || e != nil || !source.Is6() || !source.IsPrivate() || !destination.Addr().Is6() || !destination.Addr().IsPrivate() || destination.Bits() != 64 && destination.Bits() != 128 {
			return false
		}
	}
	knownKeys := map[string]bool{}
	for _, resource := range values {
		if resource.Kind == "wireguard" {
			key, _ := base64.RawURLEncoding.DecodeString(*resource.Authentication.PublicKey)
			knownKeys[base64.StdEncoding.EncodeToString(key)] = true
		}
	}
	if raw, present := view["wireguard_peers"]; present {
		var incoming []WireGuardAccessPeer
		if DecodeCanonical(appendContractJSON(nil, raw), &incoming, ContractDecodeLimits{MaxBytes: 5 << 20, MaxDepth: 32, MaxItems: 1 << 20}) != nil {
			return false
		}
		for _, peer := range incoming {
			key, _ := base64.RawURLEncoding.DecodeString(peer.PublicKey)
			knownKeys[base64.StdEncoding.EncodeToString(key)] = true
		}
	}
	peers, ok := endpoint["peers"].([]any)
	if !ok || len(peers) == 0 {
		return false
	}
	seenKeys := map[string]bool{}
	for _, raw := range peers {
		peer, ok := raw.(map[string]any)
		if !ok {
			return false
		}
		for key := range peer {
			switch key {
			case "public_key", "allowed_ips", "address", "port", "persistent_keepalive_interval":
			default:
				return false
			}
		}
		public, ok := peer["public_key"].(string)
		key, err := base64.StdEncoding.DecodeString(public)
		if !ok || err != nil || len(key) != 32 || base64.StdEncoding.EncodeToString(key) != public || !knownKeys[public] || seenKeys[public] {
			return false
		}
		seenKeys[public] = true
		address, hasAddress := peer["address"]
		port, hasPort := peer["port"]
		if hasAddress != hasPort {
			return false
		}
		if hasAddress {
			host, ok := address.(string)
			n, okn := port.(json.Number)
			number, e := strconv.Atoi(n.String())
			if !ok || !okn || !contractHost(host) || e != nil || number < 1 || number > 65535 {
				return false
			}
		}
		if raw, present := peer["persistent_keepalive_interval"]; present {
			n, ok := raw.(json.Number)
			number, e := strconv.Atoi(n.String())
			if !ok || e != nil || number < 1 || number > 65535 {
				return false
			}
		}
		allowed, ok := peer["allowed_ips"].([]any)
		if !ok || len(allowed) == 0 {
			return false
		}
		for _, raw := range allowed {
			text, ok := raw.(string)
			prefix, err := netip.ParsePrefix(text)
			if !ok || err != nil || prefix.String() != text || prefix != prefix.Masked() || !prefix.Addr().IsGlobalUnicast() || prefix.Bits() != prefix.Addr().BitLen() && (!prefix.Addr().Is6() || !prefix.Addr().IsPrivate() || prefix.Bits() != 64) {
				return false
			}
		}
	}
	if hasOwned {
		dns, ok := document["dns"].(map[string]any)
		if !ok {
			return false
		}
		fake, ok := dns["fakeip"].(map[string]any)
		pool, err := WireGuardTargetPrefix(stringContractValue(view["network_id"]), owner)
		if !ok || err != nil || len(fake) != 2 || fake["enabled"] != true || fake["inet6_range"] != pool.String() {
			return false
		}
	}
	return true
}

func stringContractValue(value any) string { text, _ := value.(string); return text }

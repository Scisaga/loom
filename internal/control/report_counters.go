package control

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"reflect"
	"sort"
	"strings"
)

// WireGuardCounters is an original observation within a DeviceReport. Counters
// belong to one actual endpoint instance, not to each directed logical Link.
type WireGuardCounters struct {
	Interface  string                 `json:"interface"`
	Epoch      string                 `json:"epoch"`
	ObservedAt int64                  `json:"observed_at"`
	Peers      []WireGuardPeerCounter `json:"peers"`
}
type WireGuardPeerCounter struct {
	PublicKey string                 `json:"public_key"`
	RXBytes   U64                    `json:"rx_bytes"`
	TXBytes   U64                    `json:"tx_bytes"`
	Links     []WireGuardCounterLink `json:"links"`
}
type WireGuardCounterLink struct {
	LinkID     string `json:"link_id"`
	SpecDigest string `json:"spec_digest"`
}

func (value WireGuardCounters) Validate() error {
	epoch, err := hex.DecodeString(value.Epoch)
	if err != nil || len(epoch) != 16 || hex.EncodeToString(epoch) != value.Epoch || !validateTime(value.ObservedAt) || value.Peers == nil {
		return errors.New("WireGuard counter instance or sample is invalid")
	}
	if value.Interface != wireGuardSharedCredential && (!strings.HasPrefix(value.Interface, "resource:") || ValidateID(strings.TrimPrefix(value.Interface, "resource:")) != nil) {
		return errors.New("WireGuard counter interface is invalid")
	}
	links := map[string]bool{}
	for i, peer := range value.Peers {
		if validateWireGuardPublicKey(peer.PublicKey) != nil || peer.Links == nil || i > 0 && value.Peers[i-1].PublicKey >= peer.PublicKey {
			return errors.New("WireGuard counter peers are invalid or not uniquely sorted")
		}
		for j, link := range peer.Links {
			if ValidateID(link.LinkID) != nil || ValidateDigest(link.SpecDigest) != nil || links[link.LinkID] || j > 0 && peer.Links[j-1].LinkID >= link.LinkID {
				return errors.New("WireGuard counter Link binding is invalid or duplicated")
			}
			links[link.LinkID] = true
		}
	}
	return nil
}

// WireGuardCounterBindings takes only public peer fields from the certified
// renderer's existing projection. It neither exports nor derives private keys.
// Empty means the View has no WG endpoint. Counts are deliberately absent.
func WireGuardCounterBindings(view DeviceView) (string, []WireGuardPeerCounter, error) {
	if view.RuntimeProfile == nil {
		return "", nil, nil
	}
	var config struct {
		Endpoints []struct {
			Type  string `json:"type"`
			Tag   string `json:"tag"`
			Peers []struct {
				PublicKey string `json:"public_key"`
			} `json:"peers"`
		} `json:"endpoints"`
	}
	if json.Unmarshal([]byte(view.RuntimeProfile.Config), &config) != nil {
		return "", nil, errors.New("WG runtime projection is invalid")
	}
	tag := ""
	peers := []WireGuardPeerCounter{}
	for _, endpoint := range config.Endpoints {
		if endpoint.Type != "wireguard" {
			continue
		}
		if tag != "" {
			return "", nil, errors.New("WG counter scope requires one shared endpoint")
		}
		tag = endpoint.Tag
		for _, peer := range endpoint.Peers {
			key, err := base64.StdEncoding.DecodeString(peer.PublicKey)
			if err != nil || len(key) != 32 {
				return "", nil, errors.New("WG projected peer key is invalid")
			}
			peers = append(peers, WireGuardPeerCounter{PublicKey: base64.RawURLEncoding.EncodeToString(key), Links: []WireGuardCounterLink{}})
		}
	}
	resources := map[string]TransportResource{}
	for _, resource := range view.Resources {
		resources[resource.ID] = resource
	}
	for _, link := range view.Links {
		if link.FromNodeID != view.DeviceID && link.ToNodeID != view.DeviceID {
			continue
		}
		local, remote := resources[link.FromResourceID], resources[link.ResourceID]
		if link.ToNodeID == view.DeviceID {
			local, remote = remote, local
		}
		if local.Authentication.PublicKey == nil || remote.Authentication.PublicKey == nil || tag != ResourceInboundTag(local.ID) {
			return "", nil, errors.New("WG Link counter scope has no local resource")
		}
		spec, err := LinkSpecDigest(view, link.ID)
		if err != nil {
			return "", nil, err
		}
		found := false
		for i := range peers {
			if peers[i].PublicKey == *remote.Authentication.PublicKey {
				peers[i].Links = append(peers[i].Links, WireGuardCounterLink{LinkID: link.ID, SpecDigest: spec})
				found = true
				break
			}
		}
		if !found {
			return "", nil, errors.New("WG Link peer is absent from the applied projection")
		}
	}
	sort.Slice(peers, func(i, j int) bool { return peers[i].PublicKey < peers[j].PublicKey })
	for i := range peers {
		sort.Slice(peers[i].Links, func(a, b int) bool { return peers[i].Links[a].LinkID < peers[i].Links[b].LinkID })
	}
	return tag, peers, nil
}
func verifyWireGuardCounters(value *WireGuardCounters, view DeviceView) error {
	if value == nil {
		return nil
	}
	tag, expected, err := WireGuardCounterBindings(view)
	if err != nil || tag == "" || value.Interface != tag || len(value.Peers) != len(expected) {
		return errors.New("WG counters are outside the applied View")
	}
	for i, peer := range value.Peers {
		if peer.PublicKey != expected[i].PublicKey || !reflect.DeepEqual(peer.Links, expected[i].Links) {
			return errors.New("WG counter peer scope does not match the View")
		}
	}
	return nil
}

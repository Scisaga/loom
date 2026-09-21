package control

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"sort"
	"strings"

	"loom/internal/clientmodel"
)

func normalizedDataPlaneProtocol(value string) string {
	if value == "hy2" {
		return "hysteria2"
	}
	return value
}

// dataPlaneServerName is the stable certificate identity for a server.  The
// public endpoint and a WireGuard next-hop address are only transport
// addresses; neither is an authenticated identity and both may change while
// the same server certificate remains valid.
func dataPlaneServerName(nodeID string) string {
	return nodeID + ".node.internal"
}

func deriveRuntimeSecret(runtimeKey, deviceID, policyID, purpose string) (string, error) {
	key, err := base64.RawURLEncoding.DecodeString(runtimeKey)
	if err != nil || len(key) != 32 {
		return "", errors.New("runtime key is invalid")
	}
	// RFC 5869 HKDF-SHA256 with a fixed product domain. The salt is public;
	// separation comes from the device, policy and purpose-bound info value.
	extract := hmac.New(sha256.New, []byte("loom-runtime-key-v2"))
	extract.Write(key)
	prk := extract.Sum(nil)
	info := []byte(deviceID + "\x00" + policyID + "\x00" + purpose)
	expand := hmac.New(sha256.New, prk)
	expand.Write(info)
	expand.Write([]byte{1})
	return base64.RawURLEncoding.EncodeToString(expand.Sum(nil)), nil
}

func networkNode(intent *NetworkIntent, id string) (NetworkNode, bool) {
	if intent == nil {
		return NetworkNode{}, false
	}
	index := sort.Search(len(intent.Nodes), func(index int) bool { return intent.Nodes[index].ID >= id })
	if index == len(intent.Nodes) || intent.Nodes[index].ID != id {
		return NetworkNode{}, false
	}
	return intent.Nodes[index], true
}

func networkPolicy(intent *NetworkIntent, id string) (NetworkPolicy, bool) {
	if intent == nil {
		return NetworkPolicy{}, false
	}
	index := sort.Search(len(intent.Policies), func(index int) bool { return intent.Policies[index].ID >= id })
	if index == len(intent.Policies) || intent.Policies[index].ID != id {
		return NetworkPolicy{}, false
	}
	return intent.Policies[index], true
}

func networkLinkBetween(intent *NetworkIntent, left, right string) (NetworkLink, bool) {
	if intent == nil {
		return NetworkLink{}, false
	}
	if left > right {
		left, right = right, left
	}
	for _, link := range intent.Links {
		if link.From == left && link.To == right {
			return link, true
		}
	}
	return NetworkLink{}, false
}

func linkAddresses(link NetworkLink, local string) (localAddress, peerAddress string, ok bool) {
	switch local {
	case link.From:
		return link.FromAddress, strings.Split(link.ToAddress, "/")[0], true
	case link.To:
		return link.ToAddress, strings.Split(link.FromAddress, "/")[0], true
	default:
		return "", "", false
	}
}

func policyRelayChains(intent *NetworkIntent, policy NetworkPolicy, accessID, exit string) [][]string {
	if policy.MaxHops < 2 {
		return nil
	}
	chains := [][]string{}
	for _, entryID := range policy.AllowedServers {
		if entryID == exit || entryID == accessID {
			continue
		}
		entry, ok := networkNode(intent, entryID)
		if !ok || entry.Server == nil || !entry.Server.PublicDataIngress {
			continue
		}
		if _, ok := networkLinkBetween(intent, entryID, exit); ok {
			chains = append(chains, []string{entryID, exit})
		}
	}
	return chains
}

type runtimeOutbound struct {
	Type          string         `json:"type"`
	Tag           string         `json:"tag"`
	Outbounds     []string       `json:"outbounds,omitempty"`
	Server        string         `json:"server,omitempty"`
	ServerPort    int            `json:"server_port,omitempty"`
	Password      string         `json:"password,omitempty"`
	Detour        string         `json:"detour,omitempty"`
	BindInterface string         `json:"bind_interface,omitempty"`
	TLS           map[string]any `json:"tls,omitempty"`
}

func projectAuthorizationRuntime(projection Projection, authorization DeviceAuthorization) ([]RouteCandidate, *RuntimeProfile, error) {
	if authorization.Schema == enrollmentSchema {
		return append([]RouteCandidate(nil), authorization.Routes...), cloneRuntimeProfile(authorization.Runtime), nil
	}
	if authorization.Schema != enrollmentSchemaV2 || projection.NetworkIntent == nil {
		return nil, nil, errors.New("schema-2 authorization has no network intent")
	}
	node, found := networkNode(projection.NetworkIntent, authorization.DeviceID)
	if !found {
		return nil, nil, errors.New("schema-2 authorization has no certified network node")
	}
	if !contains(node.Roles, "access") {
		return nil, nil, nil
	}
	routes := []RouteCandidate{}
	for _, grant := range authorization.DestinationGrants {
		policy, found := networkPolicy(projection.NetworkIntent, grant)
		if !found {
			return nil, nil, errors.New("authorization references an unknown policy")
		}
		scope := "policy:" + policy.ID
		if policy.AllowDirect {
			routes = append(routes, RouteCandidate{ID: "route:" + policy.ID + ":direct", FinalExit: "direct", Scope: scope})
		} else if contains(policy.LocalEgressDevices, authorization.DeviceID) {
			routes = append(routes, RouteCandidate{ID: "route:" + policy.ID + ":local:" + authorization.DeviceID,
				FinalExit: "direct", Scope: scope})
		}
		for _, exit := range policy.AllowedExits {
			exitNode, found := networkNode(projection.NetworkIntent, exit)
			if !found || exitNode.Server == nil {
				return nil, nil, errors.New("policy exit is not a certified server")
			}
			if exit == authorization.DeviceID && contains(policy.LocalEgressDevices, authorization.DeviceID) {
				continue
			}
			if policy.MaxHops >= 1 && exitNode.Server.PublicDataIngress {
				routes = append(routes, RouteCandidate{ID: "route:" + policy.ID + ":" + exit, FinalExit: exit,
					Chain: []string{exit}, Scope: scope})
			}
			for _, chain := range policyRelayChains(projection.NetworkIntent, policy, authorization.DeviceID, exit) {
				routes = append(routes, RouteCandidate{ID: "route:" + policy.ID + ":" + strings.Join(chain, "+"),
					FinalExit: exit, Chain: chain, Scope: scope})
			}
			if policy.MaxHops >= 2 && contains(policy.AllowedServers, authorization.DeviceID) &&
				contains(node.Roles, "server") && node.Server != nil {
				if _, linked := networkLinkBetween(projection.NetworkIntent, authorization.DeviceID, exit); linked {
					chain := []string{authorization.DeviceID, exit}
					routes = append(routes, RouteCandidate{ID: "route:" + policy.ID + ":" + strings.Join(chain, "+"),
						FinalExit: exit, Chain: chain, Scope: scope})
				}
			}
		}
	}
	sort.Slice(routes, func(i, j int) bool { return routes[i].ID < routes[j].ID })
	apiSecret, err := deriveRuntimeSecret(authorization.RuntimeKey, authorization.DeviceID, "host", "local-api")
	if err != nil {
		return nil, nil, err
	}
	outbounds := make([]runtimeOutbound, 0, len(routes)*2+len(authorization.DestinationGrants))
	selectors := map[string][]string{}
	for _, route := range routes {
		selectors[route.Scope] = append(selectors[route.Scope], route.ID)
		if len(route.Chain) == 0 {
			outbounds = append(outbounds, runtimeOutbound{Type: "direct", Tag: route.ID})
			continue
		}
		var detour string
		for index, nodeID := range route.Chain {
			node, found := networkNode(projection.NetworkIntent, nodeID)
			if !found || node.Server == nil {
				return nil, nil, errors.New("route references a server without certified attributes")
			}
			if index == 0 && nodeID == authorization.DeviceID {
				if !contains(node.Roles, "server") || len(route.Chain) < 2 {
					return nil, nil, errors.New("route local WireGuard entry is not a hybrid server")
				}
				continue
			}
			tag := route.ID
			if index != len(route.Chain)-1 {
				tag = route.ID + "/hop:" + nodeID
			}
			password, deriveErr := deriveRuntimeSecret(authorization.RuntimeKey, authorization.DeviceID, route.Scope, "data:"+nodeID)
			if deriveErr != nil {
				return nil, nil, deriveErr
			}
			protocol := normalizedDataPlaneProtocol(node.Server.InboundProtocol)
			if protocol != "hysteria2" && protocol != "trojan" {
				return nil, nil, errors.New("route references an unsupported server protocol")
			}
			serverAddress := node.Server.PublicEndpoint
			bindInterface := ""
			if index == 0 {
				if !node.Server.PublicDataIngress {
					return nil, nil, errors.New("route first hop has no certified public data ingress")
				}
			} else {
				previousID := route.Chain[index-1]
				link, found := networkLinkBetween(projection.NetworkIntent, previousID, nodeID)
				if !found {
					return nil, nil, errors.New("route next hop has no certified WireGuard link")
				}
				_, peerAddress, ok := linkAddresses(link, previousID)
				if !ok {
					return nil, nil, errors.New("route WireGuard addresses are invalid")
				}
				serverAddress = peerAddress
				if previousID == authorization.DeviceID {
					bindInterface = "wg-" + nodeID
				}
			}
			serverName := node.Server.PublicEndpoint
			if authorization.RuntimeContract >= runtimeContractNodeTLS {
				serverName = dataPlaneServerName(node.ID)
			}
			outbounds = append(outbounds, runtimeOutbound{Type: protocol, Tag: tag,
				Server: serverAddress, ServerPort: node.Server.InboundPort, Password: password,
				Detour: detour, BindInterface: bindInterface,
				TLS: map[string]any{"enabled": true, "server_name": serverName}})
			detour = tag
		}
	}
	for scope, members := range selectors {
		sort.Strings(members)
		outbounds = append(outbounds, runtimeOutbound{Type: "selector", Tag: scope, Outbounds: members})
	}
	sort.Slice(outbounds, func(i, j int) bool { return outbounds[i].Tag < outbounds[j].Tag })
	document := struct {
		Inbounds     []map[string]any  `json:"inbounds"`
		Outbounds    []runtimeOutbound `json:"outbounds"`
		Experimental map[string]any    `json:"experimental"`
	}{
		Inbounds:  []map[string]any{{"type": "tun", "tag": "tun-in", "auto_route": true}},
		Outbounds: outbounds,
		Experimental: map[string]any{"clash_api": map[string]any{
			"external_controller": "127.0.0.1:61800", "secret": apiSecret,
		}},
	}
	body, err := json.Marshal(document)
	if err != nil {
		return nil, nil, err
	}
	config, err := clientmodel.CanonicalizeRuntimeConfig(body)
	if err != nil {
		return nil, nil, err
	}
	profile := &RuntimeProfile{Kind: "sing_box", Config: config}
	if err := profile.Validate(routes); err != nil {
		return nil, nil, err
	}
	return routes, profile, nil
}

func serverRuntimeUserName(deviceID, scope, serverID string) string {
	sum := sha256.Sum256([]byte(deviceID + "\x00" + scope + "\x00" + serverID))
	return "u-" + hex.EncodeToString(sum[:10])
}

func policyMatchers(intent *NetworkIntent, policyID string) []string {
	matchers := []string{}
	for _, service := range intent.Services {
		if service.Policy == policyID {
			matchers = append(matchers, service.Matchers...)
		}
	}
	sort.Strings(matchers)
	result := matchers[:0]
	for _, matcher := range matchers {
		if len(result) == 0 || result[len(result)-1] != matcher {
			result = append(result, matcher)
		}
	}
	return result
}

func deviceDNSAddresses(intent *NetworkIntent, deviceID string) []string {
	addresses := append([]string(nil), intent.DNS...)
	if node, found := networkNode(intent, deviceID); found {
		addresses = append(addresses, node.DNS...)
	}
	sort.Strings(addresses)
	result := addresses[:0]
	for _, address := range addresses {
		if len(result) == 0 || result[len(result)-1] != address {
			result = append(result, address)
		}
	}
	return result
}

func serverRuntimeACLKey(rule ServerRuntimeACL) string {
	return fmt.Sprintf("%s\x00%s\x00%s\x00%05d\x00%s\x00%s\x00%s", rule.User, rule.Action, rule.NextHost,
		rule.NextPort, rule.BindInterface, strings.Join(rule.DestinationMatchers, "\x00"), strings.Join(rule.DNSAddresses, "\x00"))
}

func projectServerWireGuard(intent *NetworkIntent, serverID string) ([]ServerWireGuardRuntime, error) {
	local, found := networkNode(intent, serverID)
	if !found || local.Server == nil {
		return nil, errors.New("server WireGuard projection has no certified node")
	}
	result := []ServerWireGuardRuntime{}
	for _, link := range intent.Links {
		peerID := ""
		if link.From == serverID {
			peerID = link.To
		} else if link.To == serverID {
			peerID = link.From
		} else {
			continue
		}
		peer, ok := networkNode(intent, peerID)
		if !ok || peer.Server == nil {
			return nil, errors.New("server WireGuard peer is not certified")
		}
		localAddress, peerAddress, ok := linkAddresses(link, serverID)
		if !ok {
			return nil, errors.New("server WireGuard link addresses are invalid")
		}
		initiator, acceptor, err := resolveLinkDirection(local, peer)
		if err != nil {
			return nil, err
		}
		allowedIP := link.ToAddress
		if serverID == link.To {
			allowedIP = link.FromAddress
		}
		value := ServerWireGuardRuntime{LinkID: link.ID, Interface: "wg-" + peerID, LocalAddress: localAddress,
			PeerID: peerID, PeerPublicKey: peer.Server.WGPublicKey, AllowedIP: allowedIP, ProbeTarget: peerAddress}
		if initiator == serverID {
			value.Mode = "initiator"
			value.Endpoint = net.JoinHostPort(peer.Server.PublicEndpoint, fmt.Sprint(link.ListenPort))
			value.PersistentKeepalive = 25
		} else if acceptor == serverID {
			value.Mode = "acceptor"
			value.ListenPort = link.ListenPort
		} else {
			return nil, errors.New("server WireGuard direction does not include local node")
		}
		result = append(result, value)
	}
	sort.Slice(result, func(i, j int) bool {
		return result[i].LinkID+"\x00"+result[i].PeerID < result[j].LinkID+"\x00"+result[j].PeerID
	})
	return result, nil
}

// projectServerRuntime derives the complete inbound user set and its narrow
// forwarding ACL from NetworkIntent + DeviceAuthorization. An intermediate
// hop may reach only the next certified server endpoint; a selected final exit
// receives an egress rule. No mutable registry participates in this result.
func projectServerRuntime(projection Projection, serverID string, server ServerIntent) (*ServerRuntimeProfile, error) {
	protocol := normalizedDataPlaneProtocol(server.InboundProtocol)
	if protocol != "hysteria2" && protocol != "trojan" {
		return nil, errors.New("server runtime protocol is unsupported")
	}
	users := map[string]ServerRuntimeUser{}
	rules := map[string]ServerRuntimeACL{}
	for _, authorization := range projection.DeviceAuthorizations {
		roles := authorization.Roles
		if authorization.Schema == enrollmentSchemaV2 {
			if node, ok := networkNode(projection.NetworkIntent, authorization.DeviceID); ok {
				roles = node.Roles
			}
		}
		if authorization.Schema != enrollmentSchemaV2 || !contains(roles, "access") {
			continue
		}
		routes, _, err := projectAuthorizationRuntime(projection, authorization)
		if err != nil {
			return nil, err
		}
		for _, route := range routes {
			for index, hop := range route.Chain {
				if hop != serverID {
					continue
				}
				if index == 0 && hop == authorization.DeviceID {
					// A hybrid access node originates this candidate directly on
					// its certified WG interface; there is no inbound credential
					// or ACL for traffic entering the same local process.
					continue
				}
				name := serverRuntimeUserName(authorization.DeviceID, route.Scope, serverID)
				password, err := deriveRuntimeSecret(authorization.RuntimeKey, authorization.DeviceID, route.Scope, "data:"+serverID)
				if err != nil {
					return nil, err
				}
				users[name] = ServerRuntimeUser{Name: name, Password: password}
				rule := ServerRuntimeACL{User: name}
				if index == len(route.Chain)-1 {
					if route.FinalExit != serverID || !server.EgressCapable {
						return nil, errors.New("route terminates at a server that is not an authorized exit")
					}
					rule.Action = "egress"
					policyID := strings.TrimPrefix(route.Scope, "policy:")
					rule.DestinationMatchers = policyMatchers(projection.NetworkIntent, policyID)
					if len(rule.DestinationMatchers) == 0 {
						return nil, errors.New("route exit policy has no certified service matchers")
					}
				} else {
					next, found := networkNode(projection.NetworkIntent, route.Chain[index+1])
					if !found || next.Server == nil {
						return nil, errors.New("server ACL references an unknown next hop")
					}
					link, found := networkLinkBetween(projection.NetworkIntent, serverID, next.ID)
					if !found {
						return nil, errors.New("server ACL next hop has no certified WireGuard link")
					}
					_, peerAddress, ok := linkAddresses(link, serverID)
					if !ok {
						return nil, errors.New("server ACL next-hop address is invalid")
					}
					rule.Action = "next_hop"
					rule.NextHost = peerAddress
					rule.NextPort = next.Server.InboundPort
					rule.BindInterface = "wg-" + next.ID
				}
				rules[serverRuntimeACLKey(rule)] = rule
				if rule.Action == "egress" && authorization.RuntimeContract >= runtimeContractDNSACL {
					dns := deviceDNSAddresses(projection.NetworkIntent, authorization.DeviceID)
					if len(dns) == 0 {
						return nil, errors.New("runtime DNS contract has no certified DNS addresses")
					}
					dnsRule := ServerRuntimeACL{User: name, Action: "egress", DNSAddresses: dns}
					rules[serverRuntimeACLKey(dnsRule)] = dnsRule
				}
			}
		}
	}
	wireGuard, err := projectServerWireGuard(projection.NetworkIntent, serverID)
	if err != nil {
		return nil, err
	}
	profile := &ServerRuntimeProfile{Kind: "sing_box", Protocol: protocol, ListenPort: server.InboundPort, WireGuard: wireGuard}
	for _, user := range users {
		profile.Users = append(profile.Users, user)
	}
	sort.Slice(profile.Users, func(i, j int) bool { return profile.Users[i].Name < profile.Users[j].Name })
	keys := make([]string, 0, len(rules))
	for key := range rules {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		profile.ACL = append(profile.ACL, rules[key])
	}
	return profile, profile.Validate()
}

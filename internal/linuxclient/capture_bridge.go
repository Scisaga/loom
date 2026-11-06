package linuxclient

import (
	"encoding/json"
	"errors"
	"slices"
	"strings"

	"loom/internal/clientmodel"
	"loom/internal/control"
)

const captureBridgeTag = "loom-capture"

// A hybrid's isolated capture submits an original target to the one process
// owning native transport sessions. This loopback adapter has no durable state
// and cannot choose a path or enlarge a Service's certified target boundary.
func bridgeHybridCapture(capture, server string, view control.DeviceView, secret string) (string, string, error) {
	var local, host map[string]any
	if json.Unmarshal([]byte(capture), &local) != nil || json.Unmarshal([]byte(server), &host) != nil || secret == "" {
		return "", "", errors.New("hybrid capture bridge inputs are invalid")
	}
	// The host process owns the shared native source selectors. The isolated
	// capture conveys only the original target and its independent scope.
	users, forward := []any{}, []any{}
	scopes := clientmodel.SelectorScopes(view)
	for _, scope := range scopes {
		users = append(users, map[string]any{"username": scope, "password": secret})
		forward = append(forward, map[string]any{"inbound": []string{captureBridgeTag}, "auth_user": []string{scope}, "outbound": scope})
	}
	forward = append(forward, map[string]any{"inbound": []string{captureBridgeTag}, "outbound": "reject"})
	hostRoute := host["route"].(map[string]any)
	hostRules := hostRoute["rules"].([]any)
	hostRoute["rules"] = append(forward, hostRules...)
	inbounds, _ := host["inbounds"].([]any)
	host["inbounds"] = append(inbounds, map[string]any{"type": "socks", "tag": captureBridgeTag, "listen": "127.0.0.1", "listen_port": 61802, "users": users})
	outbounds := []any{}
	for _, raw := range local["outbounds"].([]any) {
		outbound := raw.(map[string]any)
		tag, _ := outbound["tag"].(string)
		if slices.Contains(scopes, tag) {
			outbounds = append(outbounds, map[string]any{"type": "socks", "tag": tag, "server": "127.0.0.1", "server_port": 61802, "version": "5", "username": tag, "password": secret})
			continue
		}
		if outbound["execution"] != nil || outbound["hop"] != nil || strings.HasPrefix(tag, "transport:") || strings.HasPrefix(tag, "egress:") || strings.HasPrefix(tag, "forward:") || strings.HasPrefix(tag, "wg-base.") {
			continue
		}
		outbounds = append(outbounds, outbound)
	}
	local["outbounds"] = outbounds
	delete(local, "endpoints")
	inbounds = []any{}
	for _, raw := range local["inbounds"].([]any) {
		if raw.(map[string]any)["tag"] != control.LinkProbeInbound {
			inbounds = append(inbounds, raw)
		}
	}
	local["inbounds"] = inbounds
	filter := func(values []any) []any {
		result := []any{}
		for _, raw := range values {
			if !receiverRule(raw.(map[string]any)) {
				result = append(result, raw)
			}
		}
		return result
	}
	localRoute := local["route"].(map[string]any)
	localRoute["rules"] = filter(localRoute["rules"].([]any))
	if dns, ok := local["dns"].(map[string]any); ok {
		servers := []any{}
		for _, raw := range dns["servers"].([]any) {
			tag, _ := raw.(map[string]any)["tag"].(string)
			if !strings.HasPrefix(tag, "wg-") {
				servers = append(servers, raw)
			}
		}
		dns["servers"] = servers
		rules := []any{}
		existing, _ := dns["rules"].([]any)
		for _, raw := range filter(existing) {
			server, _ := raw.(map[string]any)["server"].(string)
			if !strings.HasPrefix(server, "wg-") {
				rules = append(rules, raw)
			}
		}
		dns["rules"] = rules
		delete(dns, "fakeip")
	}
	// The capture no longer owns WG target addresses. Its TUN domain pool is
	// added after the separation, while the server retains its execution pool.
	if exp, ok := local["experimental"].(map[string]any); ok {
		delete(exp, "cache_file")
	}
	// These are two deletable execution caches, never two accepted Views.
	if exp, ok := host["experimental"].(map[string]any); ok {
		if cache, ok := exp["cache_file"].(map[string]any); ok {
			cache["path"] = "native-dns.db"
		}
	}
	a, err := json.Marshal(local)
	if err != nil {
		return "", "", err
	}
	b, err := json.Marshal(host)
	return string(a), string(b), err
}

func receiverRule(rule map[string]any) bool {
	if inbounds, ok := rule["inbound"].([]any); ok {
		for _, raw := range inbounds {
			tag, _ := raw.(string)
			if strings.HasPrefix(tag, "resource:") || tag == control.LinkProbeInbound {
				return true
			}
		}
	}
	if nested, ok := rule["rules"].([]any); ok {
		for _, raw := range nested {
			if receiverRule(raw.(map[string]any)) {
				return true
			}
		}
	}
	return false
}

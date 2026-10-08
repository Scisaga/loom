package linuxclient

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// Each access-bearing interface owns one independent table. Its random name
// and comment share the existing interface generation token; no new authority
// or permission can be recovered from this disposable cleanup handle.
func wireGuardFilterName(owned wireGuardOwnedLink) string {
	return "loom_wg_" + strings.TrimPrefix(owned.alias, "loom-runtime:")
}

func wireGuardNFT(options Options) string {
	if options.NFT != "" {
		return options.NFT
	}
	return "/usr/sbin/nft"
}

func wireGuardFilterObjects(owned wireGuardOwnedLink) []map[string]any {
	if !owned.hasAccessPeers() {
		return nil
	}
	table := wireGuardFilterName(owned)
	objects := []map[string]any{{"table": map[string]any{"family": "inet", "name": table, "comment": owned.alias}}}
	match := func(left any, right any) any {
		return map[string]any{"match": map[string]any{"op": "==", "left": left, "right": right}}
	}
	meta := func(key string) any { return map[string]any{"meta": map[string]any{"key": key}} }
	payload := func(protocol, field string) any {
		return map[string]any{"payload": map[string]any{"protocol": protocol, "field": field}}
	}
	for _, chain := range []string{"input", "forward", "output"} {
		objects = append(objects, map[string]any{"chain": map[string]any{"family": "inet", "table": table, "name": chain, "type": "filter", "hook": chain, "prio": -10, "policy": "accept"}})
	}
	for _, chain := range []string{"forward_in", "forward_out"} {
		objects = append(objects, map[string]any{"chain": map[string]any{"family": "inet", "table": table, "name": chain}})
	}
	accessAddress, accessPort := "", 0
	for _, peer := range owned.peerLinks() {
		if peer.AccessAddress != "" {
			accessAddress = strings.TrimSuffix(peer.AccessAddress, "/128")
			accessPort = peer.AccessPort
			break
		}
	}
	for _, chain := range []string{"input", "forward", "output", "forward_in", "forward_out"} {
		addRule := func(expr []any) {
			objects = append(objects, map[string]any{"rule": map[string]any{"family": "inet", "table": table, "chain": chain, "expr": expr}})
		}
		// Only explicit Link peers bypass the access-only boundary. Ordinary
		// peer identities are enforced by WG AllowedIPs, so adding or removing
		// one does not rewrite the shared filter or disturb other WG sessions.
		for _, peer := range owned.peerLinks() {
			if peer.AccessAddress != "" {
				continue
			}
			address := strings.Split(peer.AllowedIP, "/")[0]
			protocol := "ip"
			if strings.Contains(address, ":") {
				protocol = "ip6"
			}
			if chain == "input" || chain == "forward_in" {
				addRule([]any{match(meta("iifname"), owned.link.Interface), match(payload(protocol, "saddr"), address), map[string]any{"return": nil}})
			}
			if chain == "output" || chain == "forward_out" {
				addRule([]any{match(meta("oifname"), owned.link.Interface), match(payload(protocol, "daddr"), address), map[string]any{"return": nil}})
			}
		}
		incoming := []any{match(meta("iifname"), owned.link.Interface)}
		outgoing := []any{match(meta("oifname"), owned.link.Interface)}
		switch chain {
		case "input":
			addRule(append(append([]any{}, incoming...), match(payload("ip6", "daddr"), accessAddress), match(payload("udp", "dport"), accessPort), map[string]any{"return": nil}))
			addRule(append(incoming, map[string]any{"drop": nil}))
		case "forward":
			// Return from one direction continues through the other direction;
			// a relay target cannot bypass the ordinary source's rejection.
			addRule(append(incoming, map[string]any{"jump": map[string]any{"target": "forward_in"}}))
			addRule(append(outgoing, map[string]any{"jump": map[string]any{"target": "forward_out"}}))
		case "forward_in", "forward_out":
			addRule([]any{map[string]any{"drop": nil}})
		case "output":
			addRule(append(append([]any{}, outgoing...), match(payload("ip6", "saddr"), accessAddress), match(payload("udp", "sport"), accessPort), map[string]any{"return": nil}))
			addRule(append(outgoing, map[string]any{"drop": nil}))
		}
	}

	return objects
}

func readWireGuardFilter(options Options, owned wireGuardOwnedLink) ([]map[string]any, uint64, error) {
	body, err := runHostCommand(wireGuardNFT(options), "-j", "list", "tables")
	if err != nil || len(body) > 8<<20 {
		return nil, 0, errors.New("WireGuard filter inventory cannot be read")
	}
	var inventory struct {
		Objects []map[string]json.RawMessage `json:"nftables"`
	}
	if json.Unmarshal(body, &inventory) != nil || inventory.Objects == nil {
		return nil, 0, ErrWireGuardOwnership
	}
	found := false
	for _, object := range inventory.Objects {
		if raw, ok := object["table"]; ok {
			var table struct {
				Family string `json:"family"`
				Name   string `json:"name"`
			}
			if json.Unmarshal(raw, &table) != nil {
				return nil, 0, ErrWireGuardOwnership
			}
			if table.Family == "inet" && table.Name == wireGuardFilterName(owned) {
				if found {
					return nil, 0, ErrWireGuardOwnership
				}
				found = true
			}
		}
	}
	if !found {
		return nil, 0, nil
	}
	body, err = runHostCommand(wireGuardNFT(options), "-j", "list", "table", "inet", wireGuardFilterName(owned))
	if err != nil || len(body) > 8<<20 {
		return nil, 0, errors.New("WireGuard filter cannot be read")
	}
	var document struct {
		Objects []map[string]map[string]any `json:"nftables"`
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.UseNumber()
	if decoder.Decode(&document) != nil || document.Objects == nil {
		return nil, 0, ErrWireGuardOwnership
	}
	var result []map[string]any
	var handle uint64
	for _, object := range document.Objects {
		if len(object) != 1 {
			return nil, 0, ErrWireGuardOwnership
		}
		for kind, value := range object {
			if kind == "metainfo" {
				continue
			}
			if kind == "table" {
				number, ok := value["handle"].(json.Number)
				parsed, err := strconv.ParseUint(string(number), 10, 64)
				if !ok || err != nil || parsed == 0 || handle != 0 {
					return nil, 0, ErrWireGuardOwnership
				}
				handle = parsed
			}
			delete(value, "handle")
			result = append(result, map[string]any{kind: value})
		}
	}
	return result, handle, nil
}

func verifyWireGuardFilter(options Options, owned wireGuardOwnedLink) (uint64, error) {
	if !owned.hasAccessPeers() {
		return 0, nil
	}
	actual, handle, err := readWireGuardFilter(options, owned)
	if err != nil {
		return 0, err
	}
	if handle == 0 {
		return 0, errors.New("WireGuard access filter is absent")
	}
	want, _ := json.Marshal(wireGuardFilterObjects(owned))
	got, _ := json.Marshal(actual)
	if !bytes.Equal(want, got) {
		return 0, fmt.Errorf("%w: access filter differs", ErrWireGuardOwnership)
	}
	return handle, nil
}

func cleanupWireGuardFilter(options Options, owned wireGuardOwnedLink) error {
	if !owned.hasAccessPeers() {
		return nil
	}
	_, handle, err := readWireGuardFilter(options, owned)
	if err != nil || handle == 0 {
		return err
	}
	verified, err := verifyWireGuardFilter(options, owned)
	if err != nil || verified != handle {
		return errors.Join(ErrWireGuardOwnership, err)
	}
	// Delete the checked kernel handle, never a newly reused name or a shared
	// table. All interface peers must already be gone before this final step.
	if _, err := runHostCommand(wireGuardNFT(options), "delete", "table", "inet", "handle", strconv.FormatUint(handle, 10)); err != nil {
		return err
	}
	objects, remaining, err := readWireGuardFilter(options, owned)
	if err != nil || remaining != 0 || len(objects) != 0 {
		return errors.Join(ErrWireGuardOwnership, err)
	}
	return nil
}

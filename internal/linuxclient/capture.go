package linuxclient

import (
	"encoding/json"
	"errors"
)

func validateCapture(capture string) error {
	if capture != "tun" && capture != "mixed" {
		return errors.New("Linux capture must be tun or mixed")
	}
	return nil
}

// deriveLinuxMixedRuntime changes the local traffic source of an already
// authenticated access profile and reads missing domain metadata. Keeping its
// inbound tag preserves every route matcher; selectors and authorization are
// not rewritten. The sole listener is loopback and cannot capture host routes.
func deriveLinuxMixedRuntime(config string) (string, error) {
	var document map[string]json.RawMessage
	if err := json.Unmarshal([]byte(config), &document); err != nil {
		return "", errors.New("access runtime is invalid")
	}
	for field := range document {
		switch field {
		case "log", "dns", "inbounds", "outbounds", "route", "experimental":
		default:
			return "", errors.New("explicit Mixed source contains an unsupported runtime facility")
		}
	}
	var inbounds []map[string]json.RawMessage
	if err := json.Unmarshal(document["inbounds"], &inbounds); err != nil || len(inbounds) != 1 {
		return "", errors.New("explicit Mixed requires exactly one managed access inbound")
	}
	for field := range inbounds[0] {
		if field != "type" && field != "tag" && field != "auto_route" {
			return "", errors.New("explicit Mixed source contains an unsupported capture setting")
		}
	}
	var inboundType, inboundTag string
	var autoRoute bool
	if json.Unmarshal(inbounds[0]["type"], &inboundType) != nil || inboundType != "tun" ||
		json.Unmarshal(inbounds[0]["tag"], &inboundTag) != nil || inboundTag != "tun-in" ||
		json.Unmarshal(inbounds[0]["auto_route"], &autoRoute) != nil || !autoRoute {
		return "", errors.New("explicit Mixed requires exactly one managed access inbound")
	}
	var outbounds []struct {
		Type string `json:"type"`
		Tag  string `json:"tag"`
	}
	if err := json.Unmarshal(document["outbounds"], &outbounds); err != nil || len(outbounds) == 0 {
		return "", errors.New("explicit Mixed outbounds are invalid")
	}
	types := map[string]string{}
	for _, outbound := range outbounds {
		if outbound.Tag == "" || types[outbound.Tag] != "" {
			return "", errors.New("explicit Mixed outbound identity is invalid")
		}
		types[outbound.Tag] = outbound.Type
		switch outbound.Type {
		case "direct", "block", "dns", "selector", "hysteria2", "trojan":
		default:
			return "", errors.New("explicit Mixed source contains an unsupported outbound")
		}
	}
	var route map[string]json.RawMessage
	if err := json.Unmarshal(document["route"], &route); err != nil || route == nil {
		return "", errors.New("explicit Mixed requires certified traffic routing")
	}
	for field := range route {
		if field != "rules" && field != "final" {
			return "", errors.New("explicit Mixed route contains an unsupported network facility")
		}
	}
	var final string
	if json.Unmarshal(route["final"], &final) != nil || types[final] != "selector" && types[final] != "block" {
		return "", errors.New("explicit Mixed requires a certified selector or reject final route")
	}
	used := map[string]bool{final: true}
	if rules, found := route["rules"]; found {
		if err := validateMixedRules(rules, types, used); err != nil {
			return "", err
		}
	}
	for tag, kind := range types {
		if kind == "selector" && !used[tag] {
			return "", errors.New("explicit Mixed selector has no certified traffic rule")
		}
	}
	var experimental map[string]json.RawMessage
	if json.Unmarshal(document["experimental"], &experimental) != nil || len(experimental) != 1 || experimental["clash_api"] == nil {
		return "", errors.New("explicit Mixed permits only the managed local selector API")
	}
	var api map[string]json.RawMessage
	if json.Unmarshal(experimental["clash_api"], &api) != nil || len(api) != 2 {
		return "", errors.New("explicit Mixed selector API contains an unsupported facility")
	}
	var address, secret string
	if json.Unmarshal(api["external_controller"], &address) != nil || address != "127.0.0.1:61800" ||
		json.Unmarshal(api["secret"], &secret) != nil || secret == "" {
		return "", errors.New("explicit Mixed selector API is not the authenticated loopback API")
	}
	var rules []json.RawMessage
	if raw, found := route["rules"]; found {
		if err := json.Unmarshal(raw, &rules); err != nil {
			return "", errors.New("explicit Mixed traffic rules are invalid")
		}
	}
	// DNS dispatch retains precedence. The additional action only reads a
	// missing TLS/HTTP name, preserving the certified connection IP and all
	// original allow/reject rules. It neither captures DNS nor clears an
	// existing SOCKS domain when TLS has no SNI (sing-box 1.11.4 behavior).
	insert := 0
	for index, raw := range rules {
		var rule struct {
			Action   string `json:"action"`
			Outbound string `json:"outbound"`
		}
		if json.Unmarshal(raw, &rule) == nil && (rule.Action == "hijack-dns" || types[rule.Outbound] == "dns") {
			insert = index + 1
		}
	}
	sniff := json.RawMessage(`{"type":"logical","mode":"and","rules":[{"inbound":["tun-in"]},{"domain_regex":[".+"],"invert":true},{"port":[53],"invert":true}],"action":"sniff"}`)
	rules = append(rules, nil)
	copy(rules[insert+1:], rules[insert:])
	rules[insert] = sniff
	route["rules"], _ = json.Marshal(rules)
	document["route"], _ = json.Marshal(route)
	document["inbounds"] = json.RawMessage(`[{"type":"mixed","tag":"tun-in","listen":"127.0.0.1","listen_port":1080}]`)
	body, err := json.Marshal(document)
	return string(body), err
}

func validateMixedRules(body json.RawMessage, outbounds map[string]string, used map[string]bool) error {
	var rules []map[string]json.RawMessage
	if json.Unmarshal(body, &rules) != nil {
		return errors.New("explicit Mixed traffic rules are invalid")
	}
	for _, rule := range rules {
		for field := range rule {
			switch field {
			case "type", "mode", "rules", "domain", "domain_suffix", "domain_keyword", "domain_regex",
				"ip_cidr", "source_ip_cidr", "ip_is_private", "source_ip_is_private", "port", "port_range",
				"source_port", "source_port_range", "network", "protocol", "inbound", "auth_user", "invert", "outbound", "action":
			default:
				return errors.New("explicit Mixed traffic rule contains an unsupported network facility")
			}
		}
		if nested, found := rule["rules"]; found {
			if err := validateMixedRules(nested, outbounds, used); err != nil {
				return err
			}
		}
		if raw, found := rule["outbound"]; found {
			var tag string
			if json.Unmarshal(raw, &tag) != nil || outbounds[tag] == "" {
				return errors.New("explicit Mixed traffic rule references an unknown outbound")
			}
			used[tag] = true
		}
		if raw, found := rule["action"]; found {
			var action string
			if json.Unmarshal(raw, &action) != nil {
				return errors.New("explicit Mixed traffic rule action is invalid")
			}
			switch action {
			case "route", "reject", "sniff", "hijack-dns":
			default:
				return errors.New("explicit Mixed traffic rule action is unsupported")
			}
		}
	}
	return nil
}

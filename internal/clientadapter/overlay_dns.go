package clientadapter

import (
	"encoding/json"
	"errors"
	"loom/internal/control"
	"strings"
)

// WithOverlayDNS adds a process-local static transport. No host resolver,
// listener, filesystem or network is consulted by this execution projection.
func WithOverlayDNS(config string, records []control.DNSRecord, access bool, websiteAddresses ...string) (string, error) {
	values := map[string][]string{}
	for _, record := range records {
		if record.Validate() != nil || values[record.Name] != nil {
			return "", errors.New("invalid overlay DNS execution input")
		}
		values[record.Name] = append([]string{}, record.Addresses...)
	}
	if err := validateWebsiteAddresses(websiteAddresses); err != nil {
		return "", err
	}
	if len(websiteAddresses) > 0 {
		values["control.loom"] = append([]string{}, websiteAddresses...)
	}
	var document map[string]json.RawMessage
	if err := json.Unmarshal([]byte(config), &document); err != nil {
		return "", err
	}
	var dns map[string]json.RawMessage
	if document["dns"] != nil {
		if err := json.Unmarshal(document["dns"], &dns); err != nil {
			return "", err
		}
	}
	if len(values) == 0 && dns == nil {
		return config, nil
	}
	created := dns == nil
	if created {
		dns = map[string]json.RawMessage{"final": json.RawMessage(`"loom-overlay-dns"`)}
	}
	var existing []json.RawMessage
	if dns["rules"] != nil {
		if err := json.Unmarshal(dns["rules"], &existing); err != nil {
			return "", err
		}
	}
	var servers []json.RawMessage
	if dns["servers"] != nil {
		if err := json.Unmarshal(dns["servers"], &servers); err != nil {
			return "", err
		}
	}
	server := map[string]any{"tag": "loom-overlay-dns", "address": "rcode://name_error"}
	if len(values) > 0 {
		server["address"] = "loom-static"
		server["static_records"] = values
	}
	encoded, _ := json.Marshal(server)
	for _, raw := range servers {
		var prior struct {
			Tag string `json:"tag"`
		}
		if json.Unmarshal(raw, &prior) != nil || prior.Tag == "loom-overlay-dns" {
			return "", errors.New("overlay DNS already exists")
		}
	}
	servers = append(servers, encoded)
	dns["servers"], _ = json.Marshal(servers)
	// Remote WG resolution stays first. Local outbound lookups of .loom use
	// the certified static records; inbound WG DNS keeps its synthetic names.
	rules := []json.RawMessage{}
	for _, raw := range existing {
		var rule struct {
			Server   string   `json:"server"`
			Outbound []string `json:"outbound"`
		}
		if err := json.Unmarshal(raw, &rule); err != nil {
			return "", err
		}
		if len(rule.Outbound) > 0 && !strings.HasPrefix(rule.Server, "wg-dns.") {
			overlay, _ := json.Marshal(map[string]any{"outbound": rule.Outbound, "domain_suffix": []string{"loom"}, "server": "loom-overlay-dns"})
			rules = append(rules, overlay)
		}
		rules = append(rules, raw)
	}
	rules = append(rules, json.RawMessage(`{"domain_suffix":["loom"],"server":"loom-overlay-dns"}`))
	dns["rules"], _ = json.Marshal(rules)
	document["dns"], _ = json.Marshal(dns)
	if created && access {
		var route map[string]json.RawMessage
		if err := json.Unmarshal(document["route"], &route); err != nil {
			return "", err
		}
		var rules []json.RawMessage
		if err := json.Unmarshal(route["rules"], &rules); err != nil {
			return "", err
		}
		rules = append([]json.RawMessage{json.RawMessage(`{"inbound":["tun-in"],"port":[53],"action":"hijack-dns"}`)}, rules...)
		route["rules"], _ = json.Marshal(rules)
		document["route"], _ = json.Marshal(route)
	}
	body, err := json.Marshal(document)
	return string(body), err
}

// OverlayNames reads only the disposable DNS config, never a second authority.
func overlayNames(servers []json.RawMessage) (map[string]bool, error) {
	result := map[string]bool{}
	for _, raw := range servers {
		var server struct {
			Tag     string              `json:"tag"`
			Records map[string][]string `json:"static_records"`
		}
		if err := json.Unmarshal(raw, &server); err != nil {
			return nil, err
		}
		if server.Tag == "loom-overlay-dns" {
			for name := range server.Records {
				result[name] = true
			}
		}
	}
	return result, nil
}

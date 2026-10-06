package clientadapter

import (
	"encoding/json"
	"errors"
	"loom/internal/control"
)

// WithOverlayDNS adds a process-local static transport. No host resolver,
// listener, filesystem or network is consulted by this execution projection.
func WithOverlayDNS(config string, records []control.DNSRecord, access bool) (string, error) {
	values := map[string][]string{}
	for _, record := range records {
		if record.Validate() != nil || values[record.Name] != nil {
			return "", errors.New("invalid overlay DNS execution input")
		}
		values[record.Name] = append([]string{}, record.Addresses...)
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
	if dns["rules"] != nil {
		return "", errors.New("overlay DNS must precede capture DNS projection")
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
	servers = append(servers, encoded)
	dns["servers"], _ = json.Marshal(servers)
	dns["rules"] = json.RawMessage(`[{"domain_suffix":["loom"],"server":"loom-overlay-dns"}]`)
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

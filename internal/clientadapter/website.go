package clientadapter

import (
	"encoding/json"
	"errors"
	"loom/internal/control"
	"net/netip"
)

// WebsiteAccess is disposable execution input for one accepted View and
// network generation. It never grants a root, endpoint or Service permission.
type WebsiteAccess struct {
	Port      int
	Addresses []string
}

func (value WebsiteAccess) Validate() error {
	if value.Port == 0 && len(value.Addresses) == 0 {
		return nil
	}
	if value.Port < 1 || value.Port > 65535 || len(value.Addresses) == 0 {
		return errors.New("website execution requires one port and resolved addresses")
	}
	return validateWebsiteAddresses(value.Addresses)
}

func validateWebsiteAddresses(addresses []string) error {
	for index, value := range addresses {
		address, err := netip.ParseAddr(value)
		if err != nil || address.String() != value || address.Zone() != "" || address.Is4In6() || address.IsUnspecified() || address.IsMulticast() || index > 0 && addresses[index-1] >= value {
			return errors.New("website addresses must be canonical, unicast and uniquely sorted")
		}
	}
	return nil
}

func WebsiteAccessFor(view control.DeviceView, addresses []string) (WebsiteAccess, error) {
	if err := view.Validate(); err != nil {
		return WebsiteAccess{}, err
	}
	if len(view.WebEndpoints) == 0 {
		if len(addresses) != 0 {
			return WebsiteAccess{}, errors.New("website addresses have no certified entry")
		}
		return WebsiteAccess{}, nil
	}
	value := WebsiteAccess{Port: view.WebEndpoints[0].Port, Addresses: append([]string{}, addresses...)}
	return value, value.Validate()
}

func (value WebsiteAccess) Exclusions() ([]string, error) {
	if err := value.Validate(); err != nil {
		return nil, err
	}
	var result []string
	for _, raw := range value.Addresses {
		address := netip.MustParseAddr(raw)
		result = append(result, netip.PrefixFrom(address, address.BitLen()).String())
	}
	return result, nil
}

// WithWebsiteRoute adds only the authenticated website's exact proxy target.
// TUN adapters separately exclude these same addresses before capture starts.
func WithWebsiteRoute(config string, website WebsiteAccess) (string, error) {
	if err := website.Validate(); err != nil {
		return "", err
	}
	if website.Port == 0 {
		return config, nil
	}
	var document map[string]json.RawMessage
	if err := json.Unmarshal([]byte(config), &document); err != nil {
		return "", err
	}
	var outbounds []json.RawMessage
	if err := json.Unmarshal(document["outbounds"], &outbounds); err != nil {
		return "", err
	}
	for _, raw := range outbounds {
		var outbound struct {
			Tag string `json:"tag"`
		}
		if json.Unmarshal(raw, &outbound) != nil || outbound.Tag == "website-underlay" {
			return "", errors.New("website underlay is already present or invalid")
		}
	}
	outbounds = append(outbounds, json.RawMessage(`{"type":"direct","tag":"website-underlay"}`))
	document["outbounds"], _ = json.Marshal(outbounds)
	var route map[string]json.RawMessage
	if err := json.Unmarshal(document["route"], &route); err != nil || route == nil {
		return "", errors.New("website access requires the original authorization route")
	}
	var rules []json.RawMessage
	if err := json.Unmarshal(route["rules"], &rules); err != nil {
		return "", err
	}
	rule, _ := json.Marshal(map[string]any{"domain": []string{"control.loom"}, "network": "tcp", "port": []int{website.Port}, "outbound": "website-underlay"})
	route["rules"], _ = json.Marshal(append([]json.RawMessage{rule}, rules...))
	document["route"], _ = json.Marshal(route)
	body, err := json.Marshal(document)
	return string(body), err
}

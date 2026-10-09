package control

import (
	"errors"
	"net/netip"
	"strings"
)

// DNSRecord is a signed exact overlay value, not a resolver or an access grant.
type DNSRecord struct {
	ServiceID string   `json:"service_id,omitempty"`
	ID        string   `json:"id"`
	Name      string   `json:"name"`
	Addresses []string `json:"addresses"`
}

func (DNSRecord) materialPayload() {}

func (record DNSRecord) Validate() error {
	if record.ServiceID != "" && ValidateID(record.ServiceID) != nil || ValidateID(record.ID) != nil || !contractDNSName(record.Name) || !strings.HasSuffix(record.Name, ".loom") || record.Name == "control.loom" || len(record.Addresses) == 0 {
		return errors.New("DNS record requires an identity, an exact non-reserved .loom name and addresses")
	}
	for i, value := range record.Addresses {
		address, err := netip.ParseAddr(value)
		if err != nil || address.Zone() != "" || address.String() != value || address.Is4In6() || address.IsUnspecified() || address.IsMulticast() || i > 0 && record.Addresses[i-1] >= value {
			return errors.New("DNS record addresses must be canonical, unicast and uniquely sorted")
		}
	}
	return nil
}

func validateDNSRecords(records []DNSRecord) error {
	names := map[string]bool{}
	for i, record := range records {
		if err := record.Validate(); err != nil {
			return err
		}
		if i > 0 && records[i-1].ID >= record.ID || names[record.Name] {
			return errors.New("DNS records must have unique names and sorted unique identities")
		}
		names[record.Name] = true
	}
	return nil
}

// A concurrent namespace collision has no winner. Keep both ordinary values
// in the management projection so an operator can rename or delete one.
func projectDNSRecords(records []DNSRecord) []DNSRecord {
	counts := map[string]int{}
	for _, record := range records {
		counts[record.Name]++
	}
	var result []DNSRecord
	for _, record := range records {
		if counts[record.Name] == 1 {
			record.Addresses = append([]string{}, record.Addresses...)
			result = append(result, record)
		}
	}
	return result
}

// Keep old candidate digests when no relevant overlay fact exists. Only name
// matchers consume a DNS name; an IP-only permission does not authorize it.
func dnsCandidateSpec(value map[string]any, service Service, records []DNSRecord) map[string]any {
	var relevant []DNSRecord
	for _, record := range records {
		if record.ServiceID == service.ID && dnsRecordForLocalNetwork(record, service) {
			relevant = append(relevant, record)
			continue
		}
		for _, matcher := range service.Matchers {
			if matcher.Matches(record.Name) {
				relevant = append(relevant, record)
				break
			}
		}
	}
	if len(relevant) > 0 {
		value["dns_records"] = relevant
	}
	return value
}

func dnsRecordForLocalNetwork(record DNSRecord, service Service) bool {
	if service.LocalNetwork == nil || !service.LocalNetwork.Enabled || record.ServiceID != service.ID {
		return false
	}
	prefix, err := netip.ParsePrefix(service.LocalNetwork.VirtualPrefix)
	if err != nil || len(record.Addresses) == 0 {
		return false
	}
	for _, text := range record.Addresses {
		address, err := netip.ParseAddr(text)
		if err != nil || !prefix.Contains(address) {
			return false
		}
	}
	return true
}
func validateLocalNetworkDNS(material Material, projection Projection, record DNSRecord) error {
	if record.ServiceID == "" {
		return nil
	}
	for _, service := range projection.NetworkIntent.Services {
		if service.ID == record.ServiceID && dnsRecordForLocalNetwork(record, service) {
			return requireTargetDependency(material, projection, "service", service.ID, true)
		}
	}
	return errors.New("LAN DNS record requires its current enabled Service and virtual addresses")
}
func projectViewDNS(view DeviceView) []DNSRecord {
	var result []DNSRecord
	for _, record := range view.DNSRecords {
		if record.ServiceID == "" {
			result = append(result, record)
			continue
		}
		allowed := false
		for _, policy := range view.Policies {
			if policy.ServiceID == record.ServiceID && policy.Action == "allow" {
				allowed = true
			}
		}
		for _, service := range view.Services {
			if allowed && dnsRecordForLocalNetwork(record, service) {
				result = append(result, record)
				break
			}
		}
	}
	return result
}

package certmanager

import (
	"context"
	"errors"
	"strings"

	"loom/internal/dnsprovider"
)

type DNS01 struct {
	Provider dnsprovider.Provider
	Zone     string
	TTL      int64
}

// Present 只追加当前 ACME order 的 value，并保留并行 order 的 TXT。
func (d DNS01) Present(ctx context.Context, fqdn, value string) error {
	name, err := d.challengeName(fqdn)
	if err != nil || strings.TrimSpace(value) == "" || strings.ContainsAny(value, "\r\n") {
		return errors.New("[D103 ACME] DNS-01 challenge 输入无效")
	}
	values := []string{value}
	readback, err := d.Provider.Read(ctx, d.Zone, name, "TXT")
	if err == nil {
		values = append(values, readback.RRSet.Values...)
	} else if !errors.Is(err, dnsprovider.ErrNotFound) {
		return err
	}
	desired, err := dnsprovider.Normalize(dnsprovider.RRSet{Zone: d.Zone, Name: name, Type: "TXT", TTL: d.TTL, Values: unique(values)})
	if err != nil {
		return err
	}
	_, err = d.Provider.Replace(ctx, desired)
	return err
}

// Cleanup 逐值删除自己拥有的 TXT；不会删除其他并行 order 的值。
func (d DNS01) Cleanup(ctx context.Context, fqdn, value string) error {
	name, err := d.challengeName(fqdn)
	if err != nil {
		return err
	}
	readback, err := d.Provider.Read(ctx, d.Zone, name, "TXT")
	if err != nil {
		return err
	}
	remaining := make([]string, 0, len(readback.RRSet.Values))
	found := false
	for _, candidate := range readback.RRSet.Values {
		if candidate == value {
			found = true
			continue
		}
		remaining = append(remaining, candidate)
	}
	if !found {
		return nil
	}
	if len(remaining) == 0 {
		return d.Provider.Delete(ctx, d.Zone, name, "TXT")
	}
	_, err = d.Provider.Replace(ctx, dnsprovider.RRSet{Zone: d.Zone, Name: name, Type: "TXT", TTL: readback.RRSet.TTL, Values: remaining})
	return err
}

func (d DNS01) challengeName(fqdn string) (string, error) {
	zone := strings.ToLower(strings.TrimSuffix(d.Zone, "."))
	host := strings.ToLower(strings.TrimSuffix(fqdn, "."))
	if host != zone && !strings.HasSuffix(host, "."+zone) {
		return "", errors.New("[D103 ACME] FQDN 不属于 managed zone")
	}
	relative := strings.TrimSuffix(host, "."+zone)
	if host == zone {
		relative = ""
	}
	if relative == "" {
		return "_acme-challenge", nil
	}
	return "_acme-challenge." + relative, nil
}

func unique(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	out := make([]string, 0, len(values))
	for _, value := range values {
		if _, exists := seen[value]; exists {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	return out
}

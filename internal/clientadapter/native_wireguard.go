package clientadapter

import (
	"encoding/json"
	"errors"
	"sort"
	"strings"

	"loom/internal/control"
)

// ValidateNativeSenders is the capture boundary: certified senders are purely
// userspace. System receiver interfaces are added only by the Linux host adapter.
func ValidateNativeSenders(raw json.RawMessage) error {
	if raw == nil {
		return nil
	}
	var endpoints []map[string]any
	if err := json.Unmarshal(raw, &endpoints); err != nil {
		return err
	}
	if len(endpoints) > 1 {
		return errors.New("WG must share one native instance")
	}
	for _, endpoint := range endpoints {
		tag, _ := endpoint["tag"].(string)
		if endpoint["type"] != "wireguard" || endpoint["system"] != false || (tag != "wg-shared" && (!strings.HasPrefix(tag, "resource:") || control.ValidateID(strings.TrimPrefix(tag, "resource:")) != nil)) || endpoint["name"] != nil || endpoint["host_sources"] != nil || endpoint["stack_address"] != nil || endpoint["netns"] != nil {
			return errors.New("capture requires an explicit native userspace WG sender")
		}
	}
	return nil
}

const NativeProbeAddress = "127.0.0.1:61801"

// WithNativeProbe adds one authenticated process-local DNS diagnostic entry.
// Certified rules already restrict every user to its receiver's DNS address.
func WithNativeProbe(config, secret string) (string, error) {
	var document map[string]any
	if err := json.Unmarshal([]byte(config), &document); err != nil {
		return "", err
	}
	outbounds, _ := document["outbounds"].([]any)
	ids := []string{}
	for _, raw := range outbounds {
		outbound, ok := raw.(map[string]any)
		if !ok {
			return "", errors.New("invalid native outbound")
		}
		tag, _ := outbound["tag"].(string)
		if strings.HasPrefix(tag, "wg-base.") && outbound["type"] == "direct" {
			ids = append(ids, strings.TrimPrefix(tag, "wg-base."))
		}
	}
	sort.Strings(ids)
	users := []any{}
	for i, id := range ids {
		if control.ValidateID(id) != nil || i > 0 && id == ids[i-1] {
			return "", errors.New("invalid native diagnostic resource")
		}
		users = append(users, map[string]any{"username": id, "password": secret})
	}
	if len(users) == 0 {
		return config, nil
	}
	if secret == "" {
		return "", errors.New("native diagnostic requires local authentication")
	}
	inbounds, _ := document["inbounds"].([]any)
	for _, raw := range inbounds {
		if raw.(map[string]any)["tag"] == control.LinkProbeInbound {
			return "", errors.New("native diagnostic inbound duplicated")
		}
	}
	document["inbounds"] = append(inbounds, map[string]any{"type": "socks", "tag": control.LinkProbeInbound, "listen": "127.0.0.1", "listen_port": 61801, "users": users})
	body, err := json.Marshal(document)
	return string(body), err
}

// WithRuntimeDNSCache binds disposable synthetic-name state to the existing
// protected runtime root. Both native receivers and TUN use the same DNS pool.
func WithRuntimeDNSCache(config string) (string, error) {
	var document map[string]any
	if err := json.Unmarshal([]byte(config), &document); err != nil {
		return "", err
	}
	dns, _ := document["dns"].(map[string]any)
	if dns["fakeip"] == nil {
		return config, nil
	}
	experimental, _ := document["experimental"].(map[string]any)
	if experimental == nil {
		experimental = map[string]any{}
		document["experimental"] = experimental
	}
	want := map[string]any{"enabled": true, "path": TUNDNSCache, "store_fakeip": true}
	if actual := experimental["cache_file"]; actual != nil {
		a, _ := json.Marshal(actual)
		b, _ := json.Marshal(want)
		if string(a) != string(b) {
			return "", errors.New("runtime DNS cache ownership differs")
		}
	}
	experimental["cache_file"] = want
	body, err := json.Marshal(document)
	return string(body), err
}

package clientruntime

import (
	"bytes"
	"encoding/json"
	"errors"
	"reflect"

	"loom/internal/clientadapter"
	"loom/internal/control"
)

const maxSingBoxBytes = 16 << 20

// WindowsRuntimeProfile selects capture facilities, never business permission.
type WindowsRuntimeProfile string

const (
	WindowsInstalledProfile     WindowsRuntimeProfile = "installed"
	WindowsPortableMixedProfile WindowsRuntimeProfile = "portable-mixed"
	WindowsPortableTUNProfile   WindowsRuntimeProfile = "portable-tun"
)

// WindowsRuntimeConfig is a disposable projection of one certified View. Its
// private bytes prevent arbitrary JSON becoming another source of permission
// at the Windows process boundary.
type WindowsRuntimeConfig struct {
	body    []byte
	profile WindowsRuntimeProfile
}

func (c WindowsRuntimeConfig) Bytes() []byte { return bytes.Clone(c.body) }
func (c WindowsRuntimeConfig) Clear()        { clear(c.body) }

// NativeResourceBase derives the process input from this already certified
// projection. Its full sender descriptions remain available to the caller for
// permission/resource application; arbitrary JSON is never accepted here.
func (c WindowsRuntimeConfig) NativeResourceBase() (WindowsRuntimeConfig, error) {
	if err := c.validate(); err != nil {
		return WindowsRuntimeConfig{}, err
	}
	base, err := clientadapter.NativeResourceBase(string(c.body))
	if err != nil {
		return WindowsRuntimeConfig{}, err
	}
	return WindowsRuntimeConfig{body: []byte(base), profile: c.profile}, nil
}

func (c WindowsRuntimeConfig) validate() error {
	if err := validateRuntimeTarget(c.profile); err != nil {
		return err
	}
	if len(c.body) == 0 || len(c.body) > maxSingBoxBytes || !json.Valid(c.body) {
		return errors.New("Windows runtime projection is absent or cleared")
	}
	return nil
}

// DeriveWindowsRuntimeConfig uses the common authorization renderer; it does
// not decode a platform-specific copy of Service, Policy or native transport.
// External execution inputs are supplied by the caller, keeping this pure.
func DeriveWindowsRuntimeConfig(view control.DeviceView, profile WindowsRuntimeProfile, secret string,
	website clientadapter.WebsiteAccess, connected *[]string) (WindowsRuntimeConfig, error) {
	if view.Platform != "windows" {
		return WindowsRuntimeConfig{}, errors.New("Windows capture requires a Windows device View")
	}
	if err := validateRuntimeTarget(profile); err != nil {
		return WindowsRuntimeConfig{}, err
	}
	wantWebsite, err := clientadapter.WebsiteAccessFor(view, website.Addresses)
	if err != nil || !reflect.DeepEqual(wantWebsite, website) {
		return WindowsRuntimeConfig{}, errors.New("Windows website input differs from the certified entry")
	}
	source, err := clientadapter.AccessRuntimeSource(view, secret)
	if err != nil {
		return WindowsRuntimeConfig{}, err
	}
	source, err = clientadapter.WithBlockedSelectors(source)
	if err != nil {
		return WindowsRuntimeConfig{}, err
	}
	body, err := deriveWindowsCapture(source, profile, view.DNSServers, view.DNSRecords, website, connected, secret)
	if err != nil {
		return WindowsRuntimeConfig{}, err
	}
	return WindowsRuntimeConfig{body: body, profile: profile}, nil
}

// Only the constructor supplies business input. Capture transformations
// preserve native fields rather than maintaining another business decoder.
func deriveWindowsCapture(source string, profile WindowsRuntimeProfile, dnsServers []string, records []control.DNSRecord,
	website clientadapter.WebsiteAccess, connected *[]string, secret string) ([]byte, error) {
	exclusions, err := website.Exclusions()
	if err != nil {
		return nil, err
	}
	var document map[string]json.RawMessage
	if err := json.Unmarshal([]byte(source), &document); err != nil {
		return nil, err
	}
	if err := clientadapter.ValidateNativeSenders(document["endpoints"]); err != nil {
		return nil, err
	}
	document["log"] = json.RawMessage(`{"level":"warn"}`)
	inbounds := []map[string]any{{"type": "mixed", "tag": "in-1080", "listen": "127.0.0.1", "listen_port": 1080}}
	tun := profile != WindowsPortableMixedProfile
	if tun {
		inbounds = append(inbounds, map[string]any{"type": "tun", "tag": "tun-in", "address": []string{"172.19.0.1/30", "2001:db8::1/126"},
			"auto_route": true, "stack": "system", "route_exclude_address": exclusions})
	}
	document["inbounds"], _ = json.Marshal(inbounds)
	var route map[string]json.RawMessage
	if err := json.Unmarshal(document["route"], &route); err != nil {
		return nil, err
	}
	var rules []json.RawMessage
	if err := json.Unmarshal(route["rules"], &rules); err != nil {
		return nil, err
	}
	dnsInbounds := []string{"in-1080"}
	if tun {
		dnsInbounds = append(dnsInbounds, "tun-in")
		route["auto_detect_interface"] = json.RawMessage(`true`)
	}
	dnsRule, _ := json.Marshal(map[string]any{"inbound": dnsInbounds, "port": []int{53}, "action": "hijack-dns"})
	prefix := []json.RawMessage{dnsRule}
	if tun {
		prefix = append(prefix, windowsSniffRule("tun-in"))
	}
	prefix = append(prefix, windowsSniffRule("in-1080"))
	route["rules"], _ = json.Marshal(append(prefix, rules...))
	document["route"], _ = json.Marshal(route)
	body, err := json.Marshal(document)
	if err != nil {
		return nil, err
	}
	config, err := clientadapter.WithManagedDNS(string(body), dnsServers, false)
	if err != nil {
		return nil, err
	}
	config, err = clientadapter.WithOverlayDNS(config, records, false, website.Addresses...)
	if err != nil {
		return nil, err
	}
	config, err = clientadapter.WithWebsiteRoute(config, website)
	if err != nil {
		return nil, err
	}
	if tun {
		config, err = clientadapter.WithTUNDomainDNS(config)
		if err != nil {
			return nil, err
		}
	}
	config, err = clientadapter.WithLocalNetworkBoundary(config, connected)
	return []byte(config), err
}

func validateRuntimeTarget(profile WindowsRuntimeProfile) error {
	switch profile {
	case WindowsInstalledProfile, WindowsPortableMixedProfile, WindowsPortableTUNProfile:
		return nil
	}
	return errors.New("unsupported Windows runtime profile")
}

func windowsSniffRule(inbound string) json.RawMessage {
	body, _ := json.Marshal(map[string]any{"type": "logical", "mode": "and", "rules": []any{
		map[string]any{"inbound": []string{inbound}},
		map[string]any{"port": []int{53}, "invert": true},
		map[string]any{"domain_regex": []string{".+"}, "invert": true},
	}, "action": "sniff"})
	return body
}

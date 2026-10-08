package clientruntime

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
	"strings"

	"loom/internal/clientadapter"
	"loom/internal/control"
)

const (
	maxSingBoxBytes = 16 << 20
)

// WindowsRuntimeProfile 按 §7.2.1 从同一签名策略派生本地接管面。
// TUN 的 DNS 接管与底层网卡绑定不能改变出口授权。
type WindowsRuntimeProfile string

const (
	WindowsInstalledProfile     WindowsRuntimeProfile = "installed"
	WindowsPortableMixedProfile WindowsRuntimeProfile = "portable-mixed"
	WindowsPortableTUNProfile   WindowsRuntimeProfile = "portable-tun"
)

type singBoxConfig struct {
	Endpoints    []singBoxEndpoint    `json:"endpoints,omitempty"`
	Log          singBoxLog           `json:"log,omitempty"`
	DNS          *singBoxDNS          `json:"dns,omitempty"`
	Inbounds     []singBoxInbound     `json:"inbounds"`
	Outbounds    []singBoxOutbound    `json:"outbounds"`
	Route        singBoxRoute         `json:"route"`
	Experimental *singBoxExperimental `json:"experimental,omitempty"`
}

type singBoxLog struct {
	Level string `json:"level"`
}

type singBoxDNS struct {
	Final            string             `json:"final,omitempty"`
	Servers          []singBoxDNSServer `json:"servers"`
	Strategy         string             `json:"strategy,omitempty"`
	ReverseMapping   bool               `json:"reverse_mapping,omitempty"`
	IndependentCache bool               `json:"independent_cache,omitempty"`
	Rules            []singBoxDNSRule   `json:"rules,omitempty"`
	FakeIP           *singBoxFakeIP     `json:"fakeip,omitempty"`
}

type singBoxDNSRule struct {
	Outbound     []string `json:"outbound,omitempty"`
	Inbound      []string `json:"inbound,omitempty"`
	QueryType    []string `json:"query_type,omitempty"`
	Domain       []string `json:"domain,omitempty"`
	DomainSuffix []string `json:"domain_suffix,omitempty"`
	Server       string   `json:"server"`
}

type singBoxFakeIP struct {
	Enabled    bool   `json:"enabled"`
	Inet4Range string `json:"inet4_range"`
	Inet6Range string `json:"inet6_range"`
}

type singBoxDNSServer struct {
	Strategy      string              `json:"strategy,omitempty"`
	StaticRecords map[string][]string `json:"static_records,omitempty"`
	Tag           string              `json:"tag"`
	Address       string              `json:"address"`
	Detour        string              `json:"detour,omitempty"`
}

type singBoxInbound struct {
	RouteExcludeAddress []string      `json:"route_exclude_address,omitempty"`
	Type                string        `json:"type"`
	Tag                 string        `json:"tag"`
	Listen              string        `json:"listen,omitempty"`
	ListenPort          int           `json:"listen_port,omitempty"`
	Address             []string      `json:"address,omitempty"`
	AutoRoute           bool          `json:"auto_route,omitempty"`
	Stack               string        `json:"stack,omitempty"`
	Users               []singBoxUser `json:"users,omitempty"`
	TLS                 *singBoxTLS   `json:"tls,omitempty"`
}

type singBoxUser struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type singBoxTLS struct {
	Enabled         bool     `json:"enabled"`
	ServerName      string   `json:"server_name,omitempty"`
	CertificatePath string   `json:"certificate_path,omitempty"`
	KeyPath         string   `json:"key_path,omitempty"`
	ALPN            []string `json:"alpn,omitempty"`
	Certificate     []string `json:"certificate,omitempty"`
	Insecure        bool     `json:"insecure,omitempty"`
	DisableSNI      bool     `json:"disable_sni,omitempty"`
}

type singBoxOutbound struct {
	Inet6BindAddress string      `json:"inet6_bind_address,omitempty"`
	Type             string      `json:"type"`
	Tag              string      `json:"tag"`
	Server           string      `json:"server,omitempty"`
	ServerPort       int         `json:"server_port,omitempty"`
	Password         string      `json:"password,omitempty"`
	Version          string      `json:"version,omitempty"`
	TLS              *singBoxTLS `json:"tls,omitempty"`
	Detour           string      `json:"detour,omitempty"`
	Outbounds        []string    `json:"outbounds,omitempty"`
	Default          string      `json:"default,omitempty"`
	BindInterface    string      `json:"bind_interface,omitempty"`
	OverrideAddress  string      `json:"override_address,omitempty"`
	OverridePort     int         `json:"override_port,omitempty"`
}

type singBoxRoute struct {
	Rules               []singBoxRule `json:"rules,omitempty"`
	Final               string        `json:"final"`
	AutoDetectInterface bool          `json:"auto_detect_interface,omitempty"`
}

type singBoxRule struct {
	Network      string        `json:"network,omitempty"`
	Type         string        `json:"type,omitempty"`
	Mode         string        `json:"mode,omitempty"`
	Rules        []singBoxRule `json:"rules,omitempty"`
	DomainRegex  []string      `json:"domain_regex,omitempty"`
	Invert       bool          `json:"invert,omitempty"`
	Inbound      []string      `json:"inbound,omitempty"`
	AuthUser     []string      `json:"auth_user,omitempty"`
	IPCIDR       []string      `json:"ip_cidr,omitempty"`
	Domain       []string      `json:"domain,omitempty"`
	DomainSuffix []string      `json:"domain_suffix,omitempty"`
	Port         []int         `json:"port,omitempty"`
	Outbound     string        `json:"outbound,omitempty"`
	Action       string        `json:"action,omitempty"`
}

type singBoxExperimental struct {
	ClashAPI  *singBoxAPI       `json:"clash_api,omitempty"`
	CacheFile *singBoxCacheFile `json:"cache_file,omitempty"`
}

type singBoxCacheFile struct {
	Enabled     bool   `json:"enabled"`
	Path        string `json:"path"`
	StoreFakeIP bool   `json:"store_fakeip"`
}

type singBoxAPI struct {
	ExternalController string `json:"external_controller"`
	Secret             string `json:"secret"`
}

// ValidateWindowsSingBox accepts only the current hydrated authorization source.
// Platform capture is derived separately; no CA or DNS defaults are supplied.
func ValidateWindowsSingBox(body []byte) error {
	c, err := decodeWindowsConfig(body)
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(c.Inbounds, []singBoxInbound{{Type: "tun", Tag: "tun-in", AutoRoute: true}}) || c.DNS != nil && len(c.Endpoints) == 0 || c.Log.Level != "" || c.Route.AutoDetectInterface {
		return errors.New("Windows source contains platform capture facilities")
	}
	return validateWindowsAuthorization(c)
}

// DeriveWindowsRuntimeConfig preserves the authenticated routes and adds only
// local capture and explicitly supplied authenticated DNS infrastructure.
func DeriveWindowsRuntimeConfig(body []byte, profile WindowsRuntimeProfile, dnsServers []string, records []control.DNSRecord, websites ...clientadapter.WebsiteAccess) ([]byte, error) {
	if len(websites) > 1 {
		return nil, errors.New("Windows runtime requires one website execution input")
	}
	var website clientadapter.WebsiteAccess
	if len(websites) == 1 {
		website = websites[0]
	}
	exclusions, err := website.Exclusions()
	if err != nil {
		return nil, err
	}
	if err := ValidateWindowsSingBox(body); err != nil {
		return nil, err
	}
	if err := validateRuntimeTarget(profile); err != nil {
		return nil, err
	}
	c, _ := decodeWindowsConfig(body)
	c.Log.Level = "warn"
	c.Inbounds = []singBoxInbound{{Type: "mixed", Tag: "in-1080", Listen: "127.0.0.1", ListenPort: 1080}}
	tun := profile != WindowsPortableMixedProfile
	if tun {
		c.Inbounds = append(c.Inbounds, singBoxInbound{Type: "tun", Tag: "tun-in", Address: []string{"172.19.0.1/30", "2001:db8::1/126"}, AutoRoute: true, Stack: "system", RouteExcludeAddress: exclusions})
		c.Route.AutoDetectInterface = true
	}
	prefix := []singBoxRule{}
	if c.DNS != nil || len(dnsServers) > 0 || len(records) > 0 || website.Port != 0 {
		prefix = append(prefix, windowsDNSRule(tun))
	}

	if tun {
		prefix = append(prefix, windowsSniffRule("tun-in"))
	}
	prefix = append(prefix, windowsMixedSniffRule())
	c.Route.Rules = append(prefix, c.Route.Rules...)
	result, err := json.Marshal(c)
	if err != nil {
		return nil, err
	}
	managed, err := clientadapter.WithManagedDNS(string(result), dnsServers, false)
	if err != nil {
		return nil, err
	}
	derivedDNS, err := clientadapter.WithOverlayDNS(managed, records, false, website.Addresses...)
	if err != nil {
		return nil, err
	}
	result = []byte(derivedDNS)
	websiteConfig, err := clientadapter.WithWebsiteRoute(string(result), website)
	if err != nil {
		return nil, err
	}
	result = []byte(websiteConfig)
	if tun {
		derived, err := clientadapter.WithTUNDomainDNS(string(result))
		if err != nil {
			return nil, err
		}
		result = []byte(derived)
	}
	diagnostic, err := clientadapter.WithNativeProbe(string(result), c.Experimental.ClashAPI.Secret)
	if err != nil {
		return nil, err
	}
	result = []byte(diagnostic)
	if err = ValidateWindowsRuntimeConfig(result, profile); err != nil {
		return nil, err
	}
	return result, nil
}

func ValidateWindowsRuntimeConfig(body []byte, profile WindowsRuntimeProfile) error {
	if err := validateRuntimeTarget(profile); err != nil {
		return err
	}
	c, err := decodeWindowsConfig(body)
	if err != nil {
		return err
	}
	website, err := windowsWebsiteInput(c)
	if err != nil {
		return err
	}
	exclusions, _ := website.Exclusions()
	tun := profile != WindowsPortableMixedProfile
	expected := []singBoxInbound{{Type: "mixed", Tag: "in-1080", Listen: "127.0.0.1", ListenPort: 1080}}
	if tun {
		expected = append(expected, singBoxInbound{Type: "tun", Tag: "tun-in", Address: []string{"172.19.0.1/30", "2001:db8::1/126"}, AutoRoute: true, Stack: "system", RouteExcludeAddress: exclusions})
	}
	if len(c.Endpoints) > 0 {
		if c.Experimental == nil || c.Experimental.ClashAPI == nil {
			return errors.New("native runtime has no authenticated local API")
		}
		users := []singBoxUser{}
		for _, endpoint := range c.Endpoints {
			users = append(users, singBoxUser{Username: strings.TrimPrefix(endpoint.Tag, "wg-send."), Password: c.Experimental.ClashAPI.Secret})
		}
		expected = append(expected, singBoxInbound{Type: "socks", Tag: control.LinkProbeInbound, Listen: "127.0.0.1", ListenPort: 61801, Users: users})
	}
	if !reflect.DeepEqual(c.Inbounds, expected) || c.Log.Level != "warn" || c.Route.AutoDetectInterface != tun {
		return errors.New("Windows runtime capture does not match its profile")
	}
	if website.Port != 0 {
		c.Route.Rules = c.Route.Rules[1:]
		c.Outbounds = c.Outbounds[:len(c.Outbounds)-1]
	}
	if c.DNS != nil && c.DNS.FakeIP != nil {
		if !tun || c.Experimental == nil || c.Experimental.CacheFile == nil {
			return errors.New("domain capture has no managed TUN cache")
		}
		original, _ := json.Marshal(c)
		servers := []singBoxDNSServer{}
		for _, server := range c.DNS.Servers {
			if server.Tag != "loom-tun-domain" {
				servers = append(servers, server)
			}
		}
		c.DNS.Servers = servers
		rules := []singBoxDNSRule{}
		for _, rule := range c.DNS.Rules {
			if rule.Server != "loom-tun-domain" {
				rules = append(rules, rule)
			}
		}
		c.DNS.Rules = rules
		c.DNS.FakeIP = nil
		c.Experimental.CacheFile = nil
		base, _ := json.Marshal(c)
		derived, err := clientadapter.WithTUNDomainDNS(string(base))
		if err != nil {
			return err
		}
		var got, want any
		json.Unmarshal(original, &got)
		json.Unmarshal([]byte(derived), &want)
		if !reflect.DeepEqual(got, want) {
			return errors.New("TUN domain DNS differs from Service projection")
		}
	}
	prefix := []singBoxRule{}
	if c.DNS != nil {
		prefix = append(prefix, windowsDNSRule(tun))
	}
	if tun {
		prefix = append(prefix, windowsSniffRule("tun-in"))
	}
	prefix = append(prefix, windowsMixedSniffRule())
	if len(c.Route.Rules) < len(prefix) || !reflect.DeepEqual(c.Route.Rules[:len(prefix)], prefix) {
		return errors.New("managed DNS/sniff rules are missing, reordered or broadened")
	}
	c.Route.Rules = c.Route.Rules[len(prefix):]
	return validateWindowsAuthorization(c)
}

func decodeWindowsConfig(body []byte) (singBoxConfig, error) {
	var c singBoxConfig
	if len(body) == 0 || len(body) > maxSingBoxBytes {
		return c, errors.New("invalid config size")
	}
	if bytes.Contains(body, []byte("${secret:")) {
		return c, errors.New("unresolved runtime secret")
	}
	if err := rejectDuplicateJSONKeys(body); err != nil {
		return c, err
	}
	d := json.NewDecoder(bytes.NewReader(body))
	d.DisallowUnknownFields()
	if err := d.Decode(&c); err != nil {
		return c, err
	}
	return c, nil
}
func validateRuntimeTarget(profile WindowsRuntimeProfile) error {
	switch profile {
	case WindowsInstalledProfile, WindowsPortableMixedProfile, WindowsPortableTUNProfile:
		return nil
	}
	return errors.New("unsupported Windows runtime profile")
}
func windowsDNSRule(tun bool) singBoxRule {
	inbound := []string{"in-1080"}
	if tun {
		inbound = append(inbound, "tun-in")
	}
	return singBoxRule{Inbound: inbound, Port: []int{53}, Action: "hijack-dns"}
}
func windowsSniffRule(inbound string) singBoxRule {
	return singBoxRule{Type: "logical", Mode: "and", Rules: []singBoxRule{{Inbound: []string{inbound}}, {Port: []int{53}, Invert: true}, {DomainRegex: []string{".+"}, Invert: true}}, Action: "sniff"}
}
func windowsMixedSniffRule() singBoxRule { return windowsSniffRule("in-1080") }
func validateWindowsAuthorization(c singBoxConfig) error {
	if c.Route.Final != "reject" || len(c.Outbounds) == 0 {
		return errors.New("runtime must retain reject final")
	}
	if c.Experimental == nil || c.Experimental.CacheFile != nil || c.Experimental.ClashAPI == nil || c.Experimental.ClashAPI.ExternalController != "127.0.0.1:61800" || strings.TrimSpace(c.Experimental.ClashAPI.Secret) == "" {
		return errors.New("runtime must have its local authenticated API")
	}
	tags := map[string]string{}
	for _, o := range c.Outbounds {
		if o.Tag == "" || tags[o.Tag] != "" {
			return errors.New("duplicate or missing outbound tag")
		}
		tags[o.Tag] = o.Type
		shape := singBoxOutbound{Type: o.Type, Tag: o.Tag}
		switch o.Type {
		case "block":
			if o.Tag != "reject" {
				return errors.New("invalid block")
			}
		case "direct":
			shape.Detour, shape.Inet6BindAddress = o.Detour, o.Inet6BindAddress
			if (o.Detour == "") != (o.Inet6BindAddress == "") {
				return errors.New("WG direct wrapper requires its exact source binding")
			}

			if o.Tag == "dns-underlay" || o.Tag == "website-underlay" {
				return errors.New("DNS underlay cannot enter authorization")
			}
		case "selector":
			shape.Outbounds = o.Outbounds
			shape.Default = o.Default
			if len(o.Outbounds) == 0 {
				return errors.New("empty selector")
			}
		case "hysteria2":
			if o.Server == "" || o.ServerPort < 1 || o.ServerPort > 65535 || control.ValidatePublicKey(o.Password) != nil ||
				o.TLS == nil || !o.TLS.Enabled || o.TLS.ServerName == "" || len(o.TLS.Certificate) == 0 {
				return errors.New("incomplete authenticated Hy2 transport")
			}
			if o.Detour != "" {
				return errors.New("Hy2 must terminate at its first receiving node")
			}
			shape.Server, shape.ServerPort, shape.Password = o.Server, o.ServerPort, o.Password
			shape.TLS = &singBoxTLS{Enabled: true, ServerName: o.TLS.ServerName, Certificate: o.TLS.Certificate}

		default:
			return errors.New("unsupported authorization transport")
		}
		if !reflect.DeepEqual(o, shape) {
			return errors.New("unsupported authorization outbound fields")
		}
	}
	if tags["reject"] != "block" {
		return errors.New("missing reject outbound")
	}
	if err := validateWindowsNativeEndpoints(c, tags); err != nil {
		return err
	}
	for _, o := range c.Outbounds {
		if o.Detour != "" {
			if o.Type != "direct" || tags[o.Detour] != "wireguard" {
				return errors.New("invalid native WG source wrapper")
			}
			found := false
			for _, endpoint := range c.Endpoints {
				if endpoint.Tag == o.Detour {
					for _, address := range endpoint.Address {
						if address == o.Inet6BindAddress+"/128" {
							found = true
						}
					}
				}
			}
			if !found {
				return errors.New("WG source binding is outside its sender")
			}
		}

		if o.Type == "selector" {
			seen := map[string]bool{}
			for _, member := range o.Outbounds {
				if seen[member] || (tags[member] != "direct" && tags[member] != "hysteria2") {
					return errors.New("invalid selector member")
				}
				seen[member] = true
			}
			if !seen[o.Default] {
				return errors.New("invalid selector default")
			}
		}
	}
	if err := validateWindowsDNS(c, tags); err != nil {
		return err
	}
	for _, r := range c.Route.Rules {
		if len(r.Inbound) == 1 && r.Inbound[0] == control.LinkProbeInbound {
			if err := validateNativeProbeRule(r, tags); err != nil {
				return err
			}
			continue
		}
		if err := validateServiceRule(r, tags, true); err != nil {
			return err
		}
	}
	return nil
}
func validateServiceRule(r singBoxRule, tags map[string]string, top bool) error {
	if r.Network != "" || r.Action != "" || r.Invert || len(r.Inbound) > 0 || len(r.AuthUser) > 0 || len(r.DomainRegex) > 0 || len(r.Port) > 0 {
		return errors.New("authorization contains capture rule")
	}
	if top {
		if r.Outbound != "reject" && tags[r.Outbound] != "selector" {
			return errors.New("unknown service selector")
		}
	} else if r.Outbound != "" {
		return errors.New("nested authorization outbound")
	}
	if r.Type == "logical" {
		if (r.Mode != "and" && r.Mode != "or") || len(r.Rules) == 0 || len(r.Domain) > 0 || len(r.DomainSuffix) > 0 || len(r.IPCIDR) > 0 {
			return errors.New("invalid logical Service match")
		}
		for _, child := range r.Rules {
			if err := validateServiceRule(child, tags, false); err != nil {
				return err
			}
		}
		return nil
	}
	if r.Type != "" || r.Mode != "" || len(r.Rules) > 0 || len(r.Domain)+len(r.DomainSuffix)+len(r.IPCIDR) == 0 {
		return errors.New("invalid Service match")
	}
	return nil
}

// HasServerInbound reports whether an already-installed sing-box configuration
// owns a server-facing listener.  Linux client installation uses this before it
// retires the old units: a client-only RuntimeProfile is not a replacement for
// a server data-plane listener on the same host.
//
// The inspection is deliberately narrow. TUN and mixed are the two local
// capture shapes used by clients. Hysteria2 and Trojan are server listeners.
// An unknown inbound fails closed instead of being guessed to be disposable.
func HasServerInbound(body []byte) (bool, error) {
	if len(body) == 0 || len(body) > maxSingBoxBytes {
		return false, errors.New("sing-box config has invalid size")
	}
	if err := rejectDuplicateJSONKeys(body); err != nil {
		return false, err
	}
	var config struct {
		Endpoints []struct {
			Type       string `json:"type"`
			System     bool   `json:"system"`
			ListenPort int    `json:"listen_port"`
		} `json:"endpoints"`
		Inbounds []struct {
			Type string `json:"type"`
		} `json:"inbounds"`
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	if err := decoder.Decode(&config); err != nil {
		return false, fmt.Errorf("decode sing-box config: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return false, errors.New("sing-box config has trailing content")
	}
	for _, endpoint := range config.Endpoints {
		if endpoint.System || endpoint.ListenPort != 0 {
			return true, nil
		}
	}
	for _, inbound := range config.Inbounds {
		switch inbound.Type {
		case "tun", "mixed", "socks":
		case "hysteria2", "trojan":
			return true, nil
		default:
			return false, fmt.Errorf("cannot prove ownership of inbound type %q", inbound.Type)
		}
	}
	return false, nil
}

func rejectDuplicateJSONKeys(body []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.UseNumber()
	if err := walkJSONValue(decoder); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return errors.New("JSON contains trailing content")
	}
	return nil
}

func walkJSONValue(decoder *json.Decoder) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delimiter {
	case '{':
		seen := map[string]bool{}
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return err
			}
			key, ok := keyToken.(string)
			if !ok {
				return errors.New("JSON object key is not a string")
			}
			if seen[key] {
				return fmt.Errorf("duplicate JSON field %q", key)
			}
			seen[key] = true
			if err := walkJSONValue(decoder); err != nil {
				return err
			}
		}
		_, err = decoder.Token()
		return err
	case '[':
		for decoder.More() {
			if err := walkJSONValue(decoder); err != nil {
				return err
			}
		}
		_, err = decoder.Token()
		return err
	default:
		return errors.New("unexpected JSON delimiter")
	}
}

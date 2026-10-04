package clientruntime

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"reflect"
	"strings"
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
	Servers        []singBoxDNSServer `json:"servers"`
	Strategy       string             `json:"strategy,omitempty"`
	ReverseMapping bool               `json:"reverse_mapping,omitempty"`
}

type singBoxDNSServer struct {
	Tag     string `json:"tag"`
	Address string `json:"address"`
	Detour  string `json:"detour"`
}

type singBoxInbound struct {
	Type       string        `json:"type"`
	Tag        string        `json:"tag"`
	Listen     string        `json:"listen,omitempty"`
	ListenPort int           `json:"listen_port,omitempty"`
	Address    []string      `json:"address,omitempty"`
	AutoRoute  bool          `json:"auto_route,omitempty"`
	Stack      string        `json:"stack,omitempty"`
	Users      []singBoxUser `json:"users,omitempty"`
	TLS        *singBoxTLS   `json:"tls,omitempty"`
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
}

type singBoxOutbound struct {
	Type            string      `json:"type"`
	Tag             string      `json:"tag"`
	Server          string      `json:"server,omitempty"`
	ServerPort      int         `json:"server_port,omitempty"`
	Password        string      `json:"password,omitempty"`
	Version         string      `json:"version,omitempty"`
	TLS             *singBoxTLS `json:"tls,omitempty"`
	Detour          string      `json:"detour,omitempty"`
	Outbounds       []string    `json:"outbounds,omitempty"`
	Default         string      `json:"default,omitempty"`
	BindInterface   string      `json:"bind_interface,omitempty"`
	OverrideAddress string      `json:"override_address,omitempty"`
	OverridePort    int         `json:"override_port,omitempty"`
}

type singBoxRoute struct {
	Rules               []singBoxRule `json:"rules,omitempty"`
	Final               string        `json:"final"`
	AutoDetectInterface bool          `json:"auto_detect_interface,omitempty"`
}

type singBoxRule struct {
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
	ClashAPI *singBoxAPI `json:"clash_api,omitempty"`
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
	if !reflect.DeepEqual(c.Inbounds, []singBoxInbound{{Type: "tun", Tag: "tun-in", AutoRoute: true}}) || c.DNS != nil || c.Log.Level != "" || c.Route.AutoDetectInterface {
		return errors.New("Windows source contains platform capture facilities")
	}
	return validateWindowsAuthorization(c)
}

// DeriveWindowsRuntimeConfig preserves the authenticated routes and adds only
// local capture and explicitly supplied authenticated DNS infrastructure.
func DeriveWindowsRuntimeConfig(body []byte, profile WindowsRuntimeProfile, dnsServers []string) ([]byte, error) {
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
		c.Inbounds = append(c.Inbounds, singBoxInbound{Type: "tun", Tag: "tun-in", Address: []string{"172.19.0.1/30"}, AutoRoute: true, Stack: "system"})
		c.Route.AutoDetectInterface = true
	}
	prefix := []singBoxRule{}
	if len(dnsServers) > 0 {
		c.DNS = &singBoxDNS{ReverseMapping: tun, Servers: []singBoxDNSServer{}}
		for i, address := range dnsServers {
			ip, err := netip.ParseAddr(address)
			if err != nil || ip.String() != address {
				return nil, errors.New("authenticated DNS must be a canonical IP")
			}
			c.DNS.Servers = append(c.DNS.Servers, singBoxDNSServer{Tag: fmt.Sprintf("dns-%d", i), Address: address, Detour: "dns-underlay"})
		}
		c.Outbounds = append(c.Outbounds, singBoxOutbound{Type: "direct", Tag: "dns-underlay"})
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
	tun := profile != WindowsPortableMixedProfile
	expected := []singBoxInbound{{Type: "mixed", Tag: "in-1080", Listen: "127.0.0.1", ListenPort: 1080}}
	if tun {
		expected = append(expected, singBoxInbound{Type: "tun", Tag: "tun-in", Address: []string{"172.19.0.1/30"}, AutoRoute: true, Stack: "system"})
	}
	if !reflect.DeepEqual(c.Inbounds, expected) || c.Log.Level != "warn" || c.Route.AutoDetectInterface != tun {
		return errors.New("Windows runtime capture does not match its profile")
	}
	prefix := []singBoxRule{}
	if c.DNS != nil {
		if len(c.DNS.Servers) == 0 || c.DNS.ReverseMapping != tun || c.DNS.Strategy != "" {
			return errors.New("invalid managed DNS")
		}
		for i, server := range c.DNS.Servers {
			ip, err := netip.ParseAddr(server.Address)
			if err != nil || ip.String() != server.Address || server.Tag != fmt.Sprintf("dns-%d", i) || server.Detour != "dns-underlay" {
				return errors.New("invalid managed DNS server")
			}
		}
		last := len(c.Outbounds) - 1
		if last < 0 || !reflect.DeepEqual(c.Outbounds[last], singBoxOutbound{Type: "direct", Tag: "dns-underlay"}) {
			return errors.New("missing managed DNS underlay")
		}
		c.Outbounds = c.Outbounds[:last]
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
	if c.Experimental == nil || c.Experimental.ClashAPI == nil || c.Experimental.ClashAPI.ExternalController != "127.0.0.1:61800" || strings.TrimSpace(c.Experimental.ClashAPI.Secret) == "" {
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
			if o.Tag == "dns-underlay" {
				return errors.New("DNS underlay cannot enter authorization")
			}
		case "selector":
			shape.Outbounds = o.Outbounds
			shape.Default = o.Default
			if len(o.Outbounds) == 0 {
				return errors.New("empty selector")
			}
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
	for _, o := range c.Outbounds {
		if o.Type == "selector" {
			seen := map[string]bool{}
			for _, member := range o.Outbounds {
				if seen[member] || tags[member] != "direct" {
					return errors.New("invalid selector member")
				}
				seen[member] = true
			}
			if !seen[o.Default] {
				return errors.New("invalid selector default")
			}
		}
	}
	for _, r := range c.Route.Rules {
		if err := validateServiceRule(r, tags, true); err != nil {
			return err
		}
	}
	return nil
}
func validateServiceRule(r singBoxRule, tags map[string]string, top bool) error {
	if r.Action != "" || r.Invert || len(r.Inbound) > 0 || len(r.AuthUser) > 0 || len(r.DomainRegex) > 0 || len(r.Port) > 0 {
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
	for _, inbound := range config.Inbounds {
		switch inbound.Type {
		case "tun", "mixed":
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

package clientruntime

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
	"slices"
	"strings"
)

const (
	WindowsInstalledCAPath = `C:\ProgramData\Loom\tls\ca.crt`
	maxSingBoxBytes        = 16 << 20
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
	Log          singBoxLog           `json:"log"`
	DNS          *singBoxDNS          `json:"dns"`
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

func ValidateWindowsSingBox(body []byte) error {
	return validateWindowsSingBox(body, WindowsInstalledProfile, WindowsInstalledCAPath, false)
}

// DeriveWindowsRuntimeConfig 按 §7.2.1 先验证完整签名策略，再派生本机接管面。
// Mixed 删除 TUN 及仅匹配 TUN 的规则，避免移除匹配条件后扩大规则范围。
// TUN 将 DNS 交给签名配置中的解析器，并绑定默认网卡以防底层连接重新进入 TUN。
func DeriveWindowsRuntimeConfig(body []byte, profile WindowsRuntimeProfile, caPath string) ([]byte, error) {
	if err := ValidateWindowsSingBox(body); err != nil {
		return nil, fmt.Errorf("validate signed Windows source config: %w", err)
	}
	if err := validateRuntimeTarget(profile, caPath); err != nil {
		return nil, err
	}
	var config singBoxConfig
	if err := json.Unmarshal(body, &config); err != nil {
		return nil, err
	}
	for index := range config.Outbounds {
		if config.Outbounds[index].TLS != nil {
			config.Outbounds[index].TLS.CertificatePath = caPath
		}
	}
	if profile == WindowsPortableMixedProfile {
		inbounds := config.Inbounds[:0]
		for _, inbound := range config.Inbounds {
			if inbound.Tag != "tun-in" {
				inbounds = append(inbounds, inbound)
			}
		}
		config.Inbounds = inbounds
		rules := config.Route.Rules[:0]
		for _, rule := range config.Route.Rules {
			hadInbound := len(rule.Inbound) > 0
			selected := rule.Inbound[:0]
			for _, inbound := range rule.Inbound {
				if inbound != "tun-in" {
					selected = append(selected, inbound)
				}
			}
			rule.Inbound = selected
			if hadInbound && len(rule.Inbound) == 0 {
				continue
			}
			rules = append(rules, rule)
		}
		config.Route.Rules = rules
	} else {
		config.Route.AutoDetectInterface = true
		// §7.2.1：TUN 只收到目标 IP；复用受管 DNS 的域名映射，并从可见的
		// HTTP/TLS/QUIC 元数据补充域名，才能执行原签名 Service 规则。
		config.DNS.ReverseMapping = true
		config.Route.Rules = append([]singBoxRule{windowsTUNDNSRule(), windowsTUNSniffRule()}, config.Route.Rules...)
	}
	derived, err := json.MarshalIndent(&config, "", "  ")
	if err != nil {
		return nil, err
	}
	derived = append(derived, '\n')
	if err := ValidateWindowsRuntimeConfig(derived, profile, caPath); err != nil {
		clear(derived)
		return nil, fmt.Errorf("validate derived Windows runtime config: %w", err)
	}
	return derived, nil
}

// ValidateWindowsRuntimeConfig validates a derived local runtime shape. Callers
// must still use DeriveWindowsRuntimeConfig rather than accepting this as a
// second unsigned policy input.
func ValidateWindowsRuntimeConfig(body []byte, profile WindowsRuntimeProfile, caPath string) error {
	if err := validateRuntimeTarget(profile, caPath); err != nil {
		return err
	}
	return validateWindowsSingBox(body, profile, caPath, true)
}

func windowsTUNDNSRule() singBoxRule {
	return singBoxRule{Inbound: []string{"tun-in"}, Port: []int{53}, Action: "hijack-dns"}
}

func isWindowsTUNDNSRule(rule singBoxRule) bool {
	return reflect.DeepEqual(rule, windowsTUNDNSRule())
}

func windowsTUNSniffRule() singBoxRule {
	// §7.2.1：1.11.4 的无 SNI TLS 嗅探会清空已恢复的 DNS 域名；只补充未知域名。
	return singBoxRule{Type: "logical", Mode: "and", Rules: []singBoxRule{
		{Inbound: []string{"tun-in"}},
		{DomainRegex: []string{".+"}, Invert: true},
	}, Action: "sniff"}
}

func isWindowsTUNSniffRule(rule singBoxRule) bool {
	return reflect.DeepEqual(rule, windowsTUNSniffRule())
}

func validateRuntimeTarget(profile WindowsRuntimeProfile, caPath string) error {
	switch profile {
	case WindowsInstalledProfile:
		if !validInstalledWindowsCAPath(caPath) {
			return errors.New("[§7.2.1 / §13.5] Installed CA 路径必须属于受保护的本地连接配置")
		}
	case WindowsPortableMixedProfile, WindowsPortableTUNProfile:
		if !validAbsoluteWindowsPath(caPath) || !strings.HasSuffix(strings.ToLower(caPath), `\tls\ca.crt`) {
			return fmt.Errorf("portable Windows CA path is not an absolute managed path: %q", caPath)
		}
	default:
		return fmt.Errorf("unsupported Windows runtime profile %q", profile)
	}
	return nil
}

// §13.5：签名源仍使用统一的 CA 占位路径；只有本机派生配置可定位到独立身份根。
// 用固定目录与精确标识校验，不将 GUI 名称、相对路径或规范化别名当作可信路径。
func validInstalledWindowsCAPath(path string) bool {
	if path == WindowsInstalledCAPath {
		return true
	}
	id, ok := strings.CutPrefix(path, `C:\ProgramData\Loom\profiles\`)
	if !ok {
		return false
	}
	id, ok = strings.CutSuffix(id, `\tls\ca.crt`)
	if !ok || len(id) != 32 {
		return false
	}
	for _, character := range id {
		if !(character >= '0' && character <= '9' || character >= 'a' && character <= 'f') {
			return false
		}
	}
	return true
}

func validAbsoluteWindowsPath(value string) bool {
	if len(value) < 4 || len(value) > 1024 || ((value[0] < 'A' || value[0] > 'Z') && (value[0] < 'a' || value[0] > 'z')) ||
		value[1] != ':' || value[2] != '\\' || strings.Contains(value, "/") || strings.ContainsAny(value, "\x00\r\n") {
		return false
	}
	for _, part := range strings.Split(value[3:], `\`) {
		if part == "" || part == "." || part == ".." {
			return false
		}
	}
	return true
}

func validateWindowsSingBox(body []byte, profile WindowsRuntimeProfile, caPath string, derived bool) error {
	if len(body) == 0 || len(body) > maxSingBoxBytes {
		return errors.New("sing-box config has invalid size")
	}
	if bytes.Contains(body, []byte("${secret:")) {
		return errors.New("sing-box config contains an unresolved secret")
	}
	if bytes.Contains(bytes.ToLower(body), []byte("/etc/loom")) {
		return errors.New("sing-box config contains a Linux Loom path")
	}
	if err := rejectDuplicateJSONKeys(body); err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	var config singBoxConfig
	if err := decoder.Decode(&config); err != nil {
		return fmt.Errorf("decode sing-box config: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return errors.New("sing-box config has trailing content")
	}
	if strings.TrimSpace(config.Log.Level) == "" || config.DNS == nil || len(config.DNS.Servers) == 0 ||
		len(config.Inbounds) == 0 || len(config.Outbounds) == 0 {
		return errors.New("sing-box config is missing log, dns, inbounds, or outbounds")
	}
	if config.Route.Final != "block" {
		return fmt.Errorf("route.final must remain block, got %q", config.Route.Final)
	}
	localTUNCapture := derived && profile != WindowsPortableMixedProfile
	if config.Route.AutoDetectInterface != localTUNCapture {
		return errors.New("[§7.2.1] Windows 网卡绑定与本地接管形态不一致")
	}
	if config.DNS.ReverseMapping != localTUNCapture {
		return errors.New("[§7.2.1] DNS 域名映射只属于本机 TUN 接管，不属于远端签名策略")
	}
	if localTUNCapture && (len(config.Route.Rules) < 2 || !isWindowsTUNDNSRule(config.Route.Rules[0]) || !isWindowsTUNSniffRule(config.Route.Rules[1])) {
		return errors.New("[§7.2.1] Windows TUN 必须在出口规则之前接管 DNS 并识别域名")
	}

	inboundTags := map[string]bool{}
	tunCount, managedMixedCount := 0, 0
	for _, inbound := range config.Inbounds {
		if inbound.Tag == "" || inboundTags[inbound.Tag] {
			return fmt.Errorf("empty or duplicate inbound tag %q", inbound.Tag)
		}
		inboundTags[inbound.Tag] = true
		switch inbound.Type {
		case "tun":
			tunCount++
			if inbound.Tag != "tun-in" || !inbound.AutoRoute || inbound.Stack != "system" ||
				!slices.Equal(inbound.Address, []string{"172.19.0.1/30"}) || inbound.Listen != "" || inbound.ListenPort != 0 ||
				len(inbound.Users) != 0 || inbound.TLS != nil {
				return errors.New("Windows TUN inbound does not match the managed platform shape")
			}
		case "mixed":
			if inbound.Listen != "127.0.0.1" || inbound.ListenPort < 1 || inbound.ListenPort > 65535 ||
				len(inbound.Address) != 0 || inbound.AutoRoute || inbound.Stack != "" || inbound.TLS != nil {
				return fmt.Errorf("mixed inbound %q must listen on IPv4 loopback", inbound.Tag)
			}
			for _, user := range inbound.Users {
				if user.Username == "" || user.Password == "" {
					return fmt.Errorf("mixed inbound %q has an incomplete local user", inbound.Tag)
				}
			}
			if inbound.Tag == "in-1080" && inbound.ListenPort == 1080 {
				managedMixedCount++
			}
		default:
			return fmt.Errorf("unsupported Windows inbound type %q", inbound.Type)
		}
	}
	wantTun := 1
	if profile == WindowsPortableMixedProfile {
		wantTun = 0
	}
	if tunCount != wantTun || managedMixedCount != 1 {
		return fmt.Errorf("Windows %s config requires %d managed TUN and one 1080 mixed inbound, got %d/%d",
			profile, wantTun, tunCount, managedMixedCount)
	}

	outboundTags := map[string]bool{}
	block := false
	for _, outbound := range config.Outbounds {
		if outbound.Tag == "" || outboundTags[outbound.Tag] {
			return fmt.Errorf("empty or duplicate outbound tag %q", outbound.Tag)
		}
		outboundTags[outbound.Tag] = true
		switch outbound.Type {
		case "direct":
			if outbound.Server != "" || outbound.ServerPort != 0 || outbound.Password != "" ||
				outbound.Version != "" || outbound.TLS != nil || len(outbound.Outbounds) != 0 || outbound.Default != "" {
				return fmt.Errorf("direct outbound %q contains proxy or selector fields", outbound.Tag)
			}
		case "hysteria2", "trojan":
			if strings.TrimSpace(outbound.Server) == "" || outbound.ServerPort < 1 || outbound.ServerPort > 65535 ||
				outbound.Password == "" || outbound.TLS == nil || len(outbound.Outbounds) != 0 || outbound.Default != "" ||
				outbound.BindInterface != "" || outbound.OverrideAddress != "" || outbound.OverridePort != 0 {
				return fmt.Errorf("proxy outbound %q is missing its server, password, or TLS", outbound.Tag)
			}
		case "selector":
			if len(outbound.Outbounds) == 0 || outbound.Default == "" || outbound.Server != "" ||
				outbound.ServerPort != 0 || outbound.Password != "" || outbound.Version != "" || outbound.TLS != nil ||
				outbound.Detour != "" || outbound.BindInterface != "" || outbound.OverrideAddress != "" || outbound.OverridePort != 0 {
				return fmt.Errorf("selector outbound %q has an invalid shape", outbound.Tag)
			}
		case "block":
			if outbound.Tag != "block" || outbound.Server != "" || outbound.ServerPort != 0 ||
				outbound.Password != "" || outbound.Version != "" || outbound.TLS != nil || outbound.Detour != "" ||
				len(outbound.Outbounds) != 0 || outbound.Default != "" || outbound.BindInterface != "" ||
				outbound.OverrideAddress != "" || outbound.OverridePort != 0 {
				return fmt.Errorf("block outbound %q has an invalid fail-closed shape", outbound.Tag)
			}
		default:
			return fmt.Errorf("unsupported Windows outbound type %q", outbound.Type)
		}
		if outbound.Type == "block" && outbound.Tag == "block" {
			block = true
		}
		if outbound.TLS != nil {
			if !outbound.TLS.Enabled || outbound.TLS.ServerName == "" ||
				outbound.TLS.CertificatePath != caPath || outbound.TLS.KeyPath != "" || len(outbound.TLS.ALPN) == 0 {
				return fmt.Errorf("outbound %q does not use the managed Windows CA path", outbound.Tag)
			}
		}
	}
	if !block {
		return errors.New("Windows config is missing the fail-closed block outbound")
	}
	for _, outbound := range config.Outbounds {
		if outbound.Detour != "" && (outbound.Detour == outbound.Tag || !outboundTags[outbound.Detour]) {
			return fmt.Errorf("outbound %q has an unknown or recursive detour %q", outbound.Tag, outbound.Detour)
		}
		if outbound.Type == "selector" {
			members := map[string]bool{}
			for _, member := range outbound.Outbounds {
				if member == outbound.Tag || !outboundTags[member] || members[member] {
					return fmt.Errorf("selector %q contains an invalid member %q", outbound.Tag, member)
				}
				members[member] = true
			}
			if !members[outbound.Default] {
				return fmt.Errorf("selector %q default is not one of its members", outbound.Tag)
			}
		}
	}
	dnsTags := map[string]bool{}
	for index, server := range config.DNS.Servers {
		if server.Tag == "" || dnsTags[server.Tag] || strings.TrimSpace(server.Address) == "" ||
			server.Detour == "" || !outboundTags[server.Detour] || server.Detour == "block" {
			return fmt.Errorf("DNS server %d has an invalid tag, address, or detour", index)
		}
		dnsTags[server.Tag] = true
	}
	managedRule := false
	for index, rule := range config.Route.Rules {
		if rule.Action != "" {
			if localTUNCapture && (index == 0 && isWindowsTUNDNSRule(rule) || index == 1 && isWindowsTUNSniffRule(rule)) {
				continue
			}
			return fmt.Errorf("[§7.2.1] 路由规则 %d 包含非托管 action", index)
		}
		if rule.Type != "" || rule.Mode != "" || len(rule.Rules) != 0 || len(rule.DomainRegex) != 0 || rule.Invert {
			return fmt.Errorf("[§7.2.1] 路由规则 %d 包含本地接管专用匹配字段", index)
		}
		if rule.Outbound == "" || !outboundTags[rule.Outbound] {
			return fmt.Errorf("route rule %d references unknown outbound %q", index, rule.Outbound)
		}
		seenManagedTun, seenManagedMixed := false, false
		for _, inbound := range rule.Inbound {
			if !inboundTags[inbound] {
				return fmt.Errorf("route rule %d references unknown inbound %q", index, inbound)
			}
			seenManagedTun = seenManagedTun || inbound == "tun-in"
			seenManagedMixed = seenManagedMixed || inbound == "in-1080"
		}
		if seenManagedMixed && (wantTun == 0 || seenManagedTun) {
			managedRule = true
		}
	}
	if !managedRule {
		if wantTun == 0 {
			return errors.New("Windows Portable Mixed config does not route the managed mixed inbound")
		}
		return errors.New("Windows TUN and managed mixed inbound do not share a routing rule")
	}
	if config.Experimental == nil || config.Experimental.ClashAPI == nil ||
		config.Experimental.ClashAPI.ExternalController != "127.0.0.1:61800" ||
		strings.TrimSpace(config.Experimental.ClashAPI.Secret) == "" {
		return errors.New("Windows config is missing the authenticated loopback selector API")
	}
	return nil
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

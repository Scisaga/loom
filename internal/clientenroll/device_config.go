package clientenroll

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"unicode"

	"gopkg.in/yaml.v3"

	"loom/internal/model"
	"loom/internal/netx"
)

const defaultServerInboundPort = 61698

// DeviceConfig contains only operator-declared facts that cannot be inferred
// safely from the local platform. It is optional for a use_loom-only Device.
// ProfileVersion remains the authority for responsibilities; this file cannot
// grant forward or internet_egress by itself.
type DeviceConfig struct {
	Server *ServerConfig `yaml:"server,omitempty"`
}

type ServerConfig struct {
	PublicEndpoint string `yaml:"public_endpoint"`
	InboundPort    int    `yaml:"inbound_port,omitempty"`
	Direction      string `yaml:"direction"`
	Country        string `yaml:"country,omitempty"`
	City           string `yaml:"city,omitempty"`
	Provider       string `yaml:"provider,omitempty"`
}

// ServerEnrollment is sent with the CSR. The private WireGuard key is created
// and retained locally; only its canonical public key crosses the enrollment
// boundary.
type ServerEnrollment struct {
	PublicEndpoint string `json:"public_endpoint"`
	InboundPort    int    `json:"inbound_port"`
	Direction      string `json:"direction"`
	WGPublicKey    string `json:"wg_public_key"`
	Country        string `json:"country,omitempty"`
	City           string `json:"city,omitempty"`
	Provider       string `json:"provider,omitempty"`
}

// PrepareServerEnrollment reads an optional strict config and creates/reuses
// the local WireGuard identity only when a server block is present.
func PrepareServerEnrollment(configPath, privateKeyPath string, random io.Reader) (*ServerEnrollment, error) {
	config, err := readDeviceConfig(configPath)
	if err != nil || config.Server == nil {
		return nil, err
	}
	server := *config.Server
	server.PublicEndpoint = strings.TrimSpace(server.PublicEndpoint)
	if endpoint, ok := netx.NormalizePublicEndpoint(server.PublicEndpoint); ok {
		server.PublicEndpoint = endpoint
	}
	server.Direction = strings.TrimSpace(server.Direction)
	server.Country = strings.ToUpper(strings.TrimSpace(server.Country))
	server.City = strings.TrimSpace(server.City)
	server.Provider = strings.TrimSpace(server.Provider)
	if server.InboundPort == 0 {
		server.InboundPort = defaultServerInboundPort
	}
	if err := validateServerConfig(server); err != nil {
		return nil, err
	}
	publicKey, err := loadOrCreateWireGuardKey(privateKeyPath, random)
	if err != nil {
		return nil, err
	}
	return &ServerEnrollment{
		PublicEndpoint: server.PublicEndpoint, InboundPort: server.InboundPort,
		Direction: server.Direction, WGPublicKey: publicKey,
		Country: server.Country, City: server.City, Provider: server.Provider,
	}, nil
}

func readDeviceConfig(path string) (DeviceConfig, error) {
	var config DeviceConfig
	if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return config, fmt.Errorf("[§9.2 加入流程] device-config 必须是绝对且已清理的路径:%q", path)
	}
	body, err := readRegularFile(path, 64<<10, false)
	if errors.Is(err, os.ErrNotExist) {
		return config, nil
	}
	if err != nil {
		return config, fmt.Errorf("读取 Device 配置:%w", err)
	}
	decoder := yaml.NewDecoder(bytes.NewReader(body))
	decoder.KnownFields(true)
	if err := decoder.Decode(&config); err != nil {
		return DeviceConfig{}, fmt.Errorf("解析 Device 配置:%w", err)
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return DeviceConfig{}, errors.New("Device 配置必须只包含一个 YAML 文档")
	}
	return config, nil
}

func validateServerConfig(server ServerConfig) error {
	if !validConfiguredPublicEndpoint(server.PublicEndpoint) {
		return errors.New("[§8.1 inbound] server.public_endpoint 必须是不带 scheme/端口的公网 IP 或 DNS 名")
	}
	if server.InboundPort < 1 || server.InboundPort > 65535 {
		return errors.New("[§8.1 inbound] server.inbound_port 必须在 1-65535")
	}
	if !model.Direction(server.Direction).Valid() {
		return errors.New("[§2.1 direction] server.direction 必须是 bidirectional、reverse_only 或 direct_only")
	}
	if server.Country != "" && !model.ValidCountryCode(server.Country) {
		return errors.New("server.country 必须是两个大写字母")
	}
	for _, item := range []struct{ name, value string }{
		{"city", server.City}, {"provider", server.Provider},
	} {
		if len(item.value) > 128 || strings.IndexFunc(item.value, unicode.IsControl) >= 0 {
			return fmt.Errorf("server.%s 不能超过 128 字节或包含控制字符", item.name)
		}
	}
	return nil
}

func validConfiguredPublicEndpoint(value string) bool {
	_, ok := netx.NormalizePublicEndpoint(value)
	return ok
}

func loadOrCreateWireGuardKey(path string, random io.Reader) (string, error) {
	if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return "", fmt.Errorf("[§13.1 私钥边界] wg-key 必须是绝对且已清理的路径:%q", path)
	}
	if random == nil {
		random = rand.Reader
	}
	var raw []byte
	body, err := readPrivateFile(path, 256)
	switch {
	case err == nil:
		encoded := strings.TrimSpace(string(body))
		raw, err = base64.StdEncoding.Strict().DecodeString(encoded)
		if err != nil || len(raw) != 32 || base64.StdEncoding.EncodeToString(raw) != encoded {
			return "", errors.New("[§13.1 私钥边界] 已有 WireGuard 私钥格式无效")
		}
	case errors.Is(err, os.ErrNotExist):
		raw = make([]byte, 32)
		if _, err := io.ReadFull(random, raw); err != nil {
			return "", fmt.Errorf("生成 WireGuard 私钥:%w", err)
		}
		// WireGuard uses an X25519 scalar in canonical clamped form.
		raw[0] &= 248
		raw[31] &= 127
		raw[31] |= 64
		encoded := base64.StdEncoding.EncodeToString(raw) + "\n"
		if err := writePrivateAtomic(path, []byte(encoded), 0o600); err != nil {
			return "", fmt.Errorf("保存 WireGuard 私钥:%w", err)
		}
	default:
		return "", fmt.Errorf("读取 WireGuard 私钥:%w", err)
	}
	privateKey, err := ecdh.X25519().NewPrivateKey(raw)
	if err != nil {
		return "", errors.New("[§13.1 私钥边界] WireGuard 私钥无法派生公钥")
	}
	return base64.StdEncoding.EncodeToString(privateKey.PublicKey().Bytes()), nil
}

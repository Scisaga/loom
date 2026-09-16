//go:build linux

package clientv2

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"time"

	"loom/internal/netx"
	"loom/internal/wire"
)

// 只改变镜像名称的本地解析路径，TLS/WebPKI、SNI、pin 和内容摘要仍由
// MirrorFetcher 核对；不修改宿主解析器或任何 DNS 记录。
func LinuxMirrorFetcher(dnsServer string, timeout time.Duration) (MirrorFetcher, error) {
	fetcher := MirrorFetcher{Timeout: timeout}
	if dnsServer == "" {
		return fetcher, nil
	}
	if address, err := netip.ParseAddr(dnsServer); err == nil {
		dnsServer = net.JoinHostPort(address.String(), "53")
	} else {
		if address, err := netip.ParseAddrPort(dnsServer); err != nil || address.Port() == 0 {
			return fetcher, errors.New("[Linux config] 解析器必须是 IP 或 IP:port")
		}
	}
	client := netx.Client(dnsServer, timeout)
	fetcher.DialContext = client.Transport.(*http.Transport).DialContext
	return fetcher, nil
}

func installedLinuxMirrorFetcher(installation *DeviceInstallationV1, fetcher MirrorFetcher) (MirrorFetcher, error) {
	if fetcher.DialContext != nil {
		return fetcher, nil
	}
	if installation == nil {
		return fetcher, errors.New("[Linux config] 缺已安装配置")
	}
	for _, config := range installation.Configs {
		if config.ArtifactID != wire.LinuxRuntimeArtifactID {
			continue
		}
		var artifact wire.LinuxRuntimeArtifactV1
		if _, err := wire.DecodeStrict(config.Config, maximumLinuxConfigArtifact, &artifact); err != nil {
			return fetcher, err
		}
		for _, file := range artifact.Files {
			if file.Path != "report/v2/config.json" {
				continue
			}
			var cfg struct {
				DNS []string `json:"dns"`
			}
			if err := json.Unmarshal([]byte(file.Content), &cfg); err != nil {
				return fetcher, err
			}
			if len(cfg.DNS) == 0 {
				return fetcher, nil
			}
			configured, err := LinuxMirrorFetcher(cfg.DNS[0], fetcher.Timeout)
			fetcher.DialContext = configured.DialContext
			return fetcher, err
		}
	}
	return fetcher, nil
}

// FetchLinuxDeviceConfigArtifacts 只按 certified refs 向 Enrollment 时钉住的
// public mirrors 取 content-addressed bytes；不会携带 Device credential/token。
func FetchLinuxDeviceConfigArtifacts(ctx context.Context,
	mirrors []wire.DistributionMirrorRefV1, refs []wire.DeviceConfigArtifactRefV1,
	fetcher MirrorFetcher,
) ([]InstalledConfigV1, error) {
	if ctx == nil || refs == nil || len(refs) > maximumLinuxConfigArtifacts {
		return nil, errors.New("[Linux config] config fetch 输入无效")
	}
	configs := make([]InstalledConfigV1, len(refs))
	totalBytes := 0
	for index := range refs {
		ref := &refs[index]
		if err := wire.ValidateDeviceConfigArtifactRef(ref); err != nil {
			return nil, err
		}
		if ref.Platform != "linux-server" || ref.SizeBytes > maximumLinuxConfigArtifact {
			return nil, errors.New("[Linux config] config ref 平台或大小无效")
		}
		totalBytes += int(ref.SizeBytes)
		if totalBytes > maximumLinuxConfigTotalBytes {
			return nil, errors.New("[Linux config] configs 超过总预算")
		}
		body, err := fetcher.FetchCanonicalObject(ctx, mirrors, ref.ContentHash,
			wire.DomainDeviceConfigArtifact, ref.SizeBytes)
		if err != nil {
			return nil, err
		}
		if len(body) != int(ref.SizeBytes) {
			return nil, errors.New("[Linux config] mirror config size 与 exact ref 不匹配")
		}
		configs[index] = InstalledConfigV1{
			ArtifactID: ref.ArtifactID, Generation: ref.Generation, Platform: ref.Platform,
			MediaType: ref.MediaType, RenderContractID: ref.RenderContractID,
			SizeBytes: ref.SizeBytes, ContentHash: ref.ContentHash,
			Config: append(json.RawMessage(nil), body...),
		}
	}
	if err := validateLinuxInstalledConfigs(configs, refs); err != nil {
		return nil, err
	}
	return configs, nil
}

// LinuxInstalledConfigArtifact 让 runtime 从与 Device view 同步原子保存的
// config 取 bytes；旧 installation 仍可由 CLI 显式传入文件迁移。
func LinuxInstalledConfigArtifact(installation *DeviceInstallationV1,
	artifactID string,
) ([]byte, error) {
	if installation == nil || artifactID == "" {
		return nil, errors.New("[Linux runtime] installed config 上下文缺失")
	}
	var selected *InstalledConfigV1
	for index := range installation.Configs {
		candidate := &installation.Configs[index]
		if candidate.ArtifactID != artifactID {
			continue
		}
		if selected != nil {
			return nil, errors.New("[Linux runtime] installed config artifact ID 不唯一")
		}
		selected = candidate
	}
	if selected == nil {
		return nil, errors.New("[Linux runtime] durable state 缺目标 config artifact")
	}
	body := append([]byte(nil), selected.Config...)
	canonical, err := wire.CanonicalizeStrict(body)
	if err != nil || !bytes.Equal(canonical, body) {
		return nil, errors.New("[Linux runtime] installed config 不是 exact canonical wire")
	}
	return body, nil
}

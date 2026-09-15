package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"loom/internal/agent"
	"loom/internal/controlplane"
	"loom/internal/webui"
	"loom/internal/wire"
)

// 复用已运行 reporter 的内存表，仅读取当前 Device 配置允许的服务器。
// 不调用 Collect、probe 或任何服务器/业务地址。
func (runtime *controlRuntime) readDeviceReportObservations(ctx context.Context, report controlplane.VerifiedDeviceReportV2) ([]json.RawMessage, error) {
	runtime.mu.Lock()
	identity, err := runtime.readDeviceIdentityLocked(report.CertificateHash())
	var refs []wire.DeviceConfigArtifactRefV1
	if err == nil && identity.Record.IdentityStatus == "active" && identity.CurrentDeviceView.Payload.Active != nil {
		refs = append(refs, identity.CurrentDeviceView.Payload.Active.ConfigArtifactRefs...)
	}
	runtime.mu.Unlock()
	if err != nil {
		return nil, err
	}
	query, err := runtime.deviceObservationQuery(report.DeviceID(), refs)
	if err != nil {
		return nil, err
	}
	if len(query.Servers) == 0 {
		return []json.RawMessage{}, nil
	}
	body, err := wire.MarshalCanonical(query)
	if err != nil {
		return nil, err
	}
	transport := &http.Transport{Proxy: nil, DisableCompression: true, DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{Timeout: time.Second}).DialContext(ctx, "unix", webui.ReadOnlySocketPath)
	}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 2 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("[服务器观测] 禁止重定向") }}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://loom-control-ui.local"+wire.LocalDeviceObservationsPath, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := client.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK || response.Header.Get("Content-Encoding") != "" || response.Header.Get("Content-Type") != "application/json" {
		return nil, errors.New("[服务器观测] 本机只读快照不可用")
	}
	raw, err := io.ReadAll(io.LimitReader(response.Body, (1<<20)+8192))
	if err != nil || len(raw) > 1<<20 {
		return nil, errors.New("[服务器观测] 本机响应超限")
	}
	var observations []json.RawMessage
	canonical, err := wire.DecodeStrict(raw, 1<<20, &observations)
	if err != nil || !bytes.Equal(canonical, raw) || len(observations) > 256 {
		return nil, errors.New("[服务器观测] 本机响应格式无效")
	}
	return observations, nil
}

func (runtime *controlRuntime) deviceObservationQuery(deviceID string, refs []wire.DeviceConfigArtifactRefV1) (wire.DeviceObservationQueryV1, error) {
	query := wire.DeviceObservationQueryV1{Schema: 1, Servers: []string{}}
	servers := map[string]bool{}
	for _, ref := range refs {
		if ref.ArtifactID != wire.WindowsRuntimeArtifactID && ref.ArtifactID != "android-runtime" && ref.ArtifactID != wire.LinuxRuntimeArtifactID {
			continue
		}
		if _, err := wire.ParseHash(ref.ContentHash); err != nil {
			return query, err
		}
		file := filepath.Join(runtime.dir, "public", "distribution", "sha256", strings.TrimPrefix(ref.ContentHash, "sha256:"))
		raw, err := os.ReadFile(file)
		if err != nil {
			return query, err
		}
		hash, err := wire.DeviceConfigArtifactContentHash(raw)
		if err != nil || hash != ref.ContentHash || int64(len(raw)) != ref.SizeBytes {
			return query, errors.New("[服务器观测] 当前 runtime 制品摘要不匹配")
		}
		var config string
		switch ref.Platform {
		case "android":
			var bundle struct {
				Owner string            `json:"owner"`
				Files map[string]string `json:"files"`
			}
			if _, err := wire.DecodeStrict(raw, 4<<20, &bundle); err != nil || bundle.Owner != deviceID {
				return query, errors.New("[服务器观测] Android runtime 身份无效")
			}
			config = bundle.Files["agent/config.json"]
		case "windows-desktop":
			var artifact wire.WindowsRuntimeArtifactV1
			if _, err := wire.DecodeStrict(raw, 4<<20, &artifact); err != nil || artifact.DeviceID != deviceID {
				return query, errors.New("[服务器观测] Windows runtime 身份无效")
			}
			for _, file := range artifact.Files {
				if file.Path == "agent/config.json" {
					config = file.Content
				}
			}
		case "linux-server":
			var artifact wire.LinuxRuntimeArtifactV1
			if _, err := wire.DecodeStrict(raw, 4<<20, &artifact); err != nil || artifact.DeviceID != deviceID {
				return query, errors.New("[服务器观测] Linux runtime 身份无效")
			}
			for _, file := range artifact.Files {
				if file.Path == "agent/v2/config.json" {
					config = file.Content
				}
			}
		}
		if config == "" {
			continue
		}
		var routing agent.Config
		if err := json.Unmarshal([]byte(config), &routing); err != nil || routing.Node != deviceID {
			return query, errors.New("[服务器观测] 当前选路配置身份无效")
		}
		for _, declaration := range routing.Declarations {
			for _, candidate := range declaration.Candidates {
				for _, id := range candidate.Chain {
					if id != deviceID {
						servers[id] = true
					}
				}
			}
		}
	}
	for id := range servers {
		query.Servers = append(query.Servers, id)
	}
	sort.Strings(query.Servers)
	return query, wire.ValidateDeviceObservationQuery(&query)
}

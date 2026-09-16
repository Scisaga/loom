package main

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"loom/internal/agent"
	"loom/internal/controlplane"
	"loom/internal/wire"
)

// 回执只读取已提交的 v2 报告；不请求旧 report HTTP/Unix 入口，也不触发采样。
func (runtime *controlRuntime) deviceReportObservations(store *controlplane.DeviceReportStore) controlplane.DeviceReportObservationReader {
	return func(ctx context.Context, report controlplane.VerifiedDeviceReportV2) ([]json.RawMessage, error) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		runtime.mu.Lock()
		defer runtime.mu.Unlock()
		application, err := runtime.certifiedApplicationLocked()
		if err != nil {
			return nil, err
		}
		identity, err := runtime.readDeviceIdentityAtApplicationLocked(application, report.CertificateHash(), false)
		if err != nil {
			return nil, err
		}
		if identity.Record.IdentityStatus != "active" || identity.CurrentDeviceView.Payload.Active == nil {
			return nil, errors.New("[服务器观测] 请求设备不再活动")
		}
		sources, err := runtime.deviceObservationSources(report.DeviceID(), identity.CurrentDeviceView.Payload.Active.ConfigArtifactRefs)
		if err != nil {
			return nil, err
		}
		allowed := map[string]bool{}
		for _, id := range sources {
			allowed[id] = true
		}
		latest := map[string]json.RawMessage{}
		times := map[string]string{}
		for _, record := range store.Snapshot().Reports {
			if !allowed[record.DeviceID] || record.Body.Kind != "node-health" {
				continue
			}
			owner, err := runtime.readDeviceIdentityAtApplicationLocked(application, record.CertificateHash, false)
			if err != nil {
				continue
			}
			own, err := verifyNodeReportObservationAt(application, record.Payload, owner, runtime.now().UTC())
			if err != nil {
				continue
			}
			body, err := wire.MarshalCanonical(own)
			if err != nil || own.TS <= times[own.Node] {
				continue
			}
			latest[own.Node], times[own.Node] = body, own.TS
		}
		out := []json.RawMessage{}
		total := 2
		for _, id := range sources {
			body, found := latest[id]
			if !found || total+len(body)+1 > 1<<20 || len(out) >= 256 {
				continue
			}
			total += len(body) + 1
			out = append(out, body)
		}
		return out, nil
	}
}

func (runtime *controlRuntime) deviceObservationSources(deviceID string, refs []wire.DeviceConfigArtifactRefV1) ([]string, error) {
	sources := []string{}
	servers := map[string]bool{}
	for _, ref := range refs {
		if ref.ArtifactID != wire.WindowsRuntimeArtifactID && ref.ArtifactID != "android-runtime" && ref.ArtifactID != wire.LinuxRuntimeArtifactID {
			continue
		}
		if _, err := wire.ParseHash(ref.ContentHash); err != nil {
			return nil, err
		}
		file := filepath.Join(runtime.dir, "public", "distribution", "sha256", strings.TrimPrefix(ref.ContentHash, "sha256:"))
		raw, err := os.ReadFile(file)
		if err != nil {
			return nil, err
		}
		hash, err := wire.DeviceConfigArtifactContentHash(raw)
		if err != nil || hash != ref.ContentHash || int64(len(raw)) != ref.SizeBytes {
			return nil, errors.New("[服务器观测] 当前 runtime 制品摘要不匹配")
		}
		var config string
		switch ref.Platform {
		case "android":
			var bundle struct {
				Owner string            `json:"owner"`
				Files map[string]string `json:"files"`
			}
			if _, err := wire.DecodeStrict(raw, 4<<20, &bundle); err != nil || bundle.Owner != deviceID {
				return nil, errors.New("[服务器观测] Android runtime 身份无效")
			}
			config = bundle.Files["agent/config.json"]
		case "windows-desktop":
			var artifact wire.WindowsRuntimeArtifactV1
			if _, err := wire.DecodeStrict(raw, 4<<20, &artifact); err != nil || artifact.DeviceID != deviceID {
				return nil, errors.New("[服务器观测] Windows runtime 身份无效")
			}
			for _, file := range artifact.Files {
				if file.Path == "agent/config.json" {
					config = file.Content
				}
			}
		case "linux-server":
			var artifact wire.LinuxRuntimeArtifactV1
			if _, err := wire.DecodeStrict(raw, 4<<20, &artifact); err != nil || artifact.DeviceID != deviceID {
				return nil, errors.New("[服务器观测] Linux runtime 身份无效")
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
			return nil, errors.New("[服务器观测] 当前选路配置身份无效")
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
		sources = append(sources, id)
	}
	sort.Strings(sources)
	if len(sources) > 256 {
		return nil, errors.New("[服务器观测] 来源集合超过读取上限")
	}
	return sources, nil
}

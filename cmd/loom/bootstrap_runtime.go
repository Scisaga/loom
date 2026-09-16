package main

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"loom/internal/bootstrapaccess"
	"loom/internal/certmanager"
	"loom/internal/publish"
	"loom/internal/rotation"
	"loom/internal/wire"
)

type bootstrapPreparedReadinessV1 struct {
	Schema            int                                               `json:"schema"`
	DeviceID          string                                            `json:"device_id"`
	BundleHash        string                                            `json:"bundle_hash"`
	LocalEvidence     bootstrapaccess.BootstrapLocalReadinessEvidenceV1 `json:"local_evidence"`
	LocalEvidenceHash string                                            `json:"local_evidence_hash"`
	OuterPlan         bootstrapaccess.BootstrapOuterProbePlanV1         `json:"outer_plan"`
}

type preparedBootstrapRuntime struct {
	generations []*bootstrapaccess.PreparedBootstrapGeneration
	access      bootstrapRuntimeDeviceAccess
	unlocked    func()
	done        chan error
}

type bootstrapRuntimeDeviceAccess interface {
	Resolve(context.Context, wire.BootstrapCapabilityLookupRequestV1) (wire.VerifiedBootstrapCapabilityV1, error)
	DialContext(context.Context, string, string) (net.Conn, error)
	Close()
}

func (runtime *preparedBootstrapRuntime) Close() {
	for _, generation := range runtime.generations {
		_ = generation.Close()
	}
	if runtime.unlocked != nil {
		runtime.unlocked()
		runtime.unlocked = nil
	}
	if runtime.access != nil {
		runtime.access.Close()
		runtime.access = nil
	}
}

func cmdBootstrapServe(args []string) error {
	flags := flag.NewFlagSet("bootstrap serve", flag.ContinueOnError)
	bundlePath := flags.String("bundle", "", "管理员导出的认证安装交付")
	device := flags.String("device", "", "原 Device ID")
	platform := flags.String("platform-pubkey", "/etc/loom/trust/platform.pub", "原平台公钥，仅验证迁移证明")
	state := flags.String("state-dir", "/var/lib/loom-bootstrap-v2", "持久 listener 与 capability 使用状态")
	deviceState := flags.String("device-state-dir", "/var/lib/loom/client-v2", "已迁移 Device 身份与 LKG 目录")
	certificates := flags.String("certificate-dir", "/var/lib/loom-public-v2/certificates", "原节点已有证书材料目录")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 || *bundlePath == "" || *device == "" {
		return errors.New("bootstrap serve 需要 bundle 和 device")
	}
	var bundle bootstrapInstallationBundleV1
	if err := readCanonicalFile(*bundlePath, 32<<20, &bundle); err != nil {
		return err
	}
	key, err := readKey(*platform, ed25519.PublicKeySize)
	if err != nil {
		return err
	}
	installation, err := verifyBootstrapInstallationBundle(bundle, key, *device)
	if err != nil {
		return err
	}
	access, err := openBootstrapRuntimeDeviceAccess(filepath.Join(*deviceState, "state.json"),
		filepath.Join(*deviceState, "identity.json"), *device,
		installation.Catalog.BootstrapIngressSetHash, time.Now, 15*time.Second)
	if err != nil {
		return err
	}
	transferred := false
	defer func() {
		if !transferred {
			access.Close()
		}
	}()
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	runtime, err := startPreparedBootstrapRuntime(ctx, bundle, key, *device, *state, *certificates, nil, time.Now, access)
	if err != nil {
		return err
	}
	transferred = true
	defer runtime.Close()
	fmt.Println("✓ 认证的 Bootstrap listeners 已启动并完成本机 TLS/QUIC 验证；新连接按当前 certified capability 判定")
	select {
	case <-ctx.Done():
		return nil
	case err := <-runtime.done:
		if err == nil {
			return errors.New("Bootstrap listener 意外停止")
		}
		return err
	}
}

func startPreparedBootstrapRuntime(ctx context.Context, bundle bootstrapInstallationBundleV1, public ed25519.PublicKey,
	deviceID, stateDir, certificateDir string, roots *x509.CertPool, now func() time.Time,
	deviceAccess ...bootstrapRuntimeDeviceAccess) (*preparedBootstrapRuntime, error) {
	if ctx == nil || now == nil {
		return nil, errors.New("[bootstrap] 缺运行 context 或可信时间")
	}
	installation, err := verifyBootstrapInstallationBundle(bundle, public, deviceID)
	if err != nil {
		return nil, err
	}
	if !filepath.IsAbs(stateDir) || filepath.Clean(stateDir) != stateDir {
		return nil, errors.New("[bootstrap] 状态目录必须是规范绝对路径")
	}
	if err := os.MkdirAll(stateDir, 0700); err != nil {
		return nil, err
	}
	info, err := os.Lstat(stateDir)
	if err != nil || !info.IsDir() || info.Mode().Perm() != 0700 || info.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("[bootstrap] 状态目录必须是 0700 实体目录")
	}
	unlock, err := publish.AcquireLock(filepath.Join(stateDir, "runtime.lock"))
	if err != nil {
		return nil, err
	}
	var access bootstrapRuntimeDeviceAccess
	if len(deviceAccess) > 1 {
		unlock()
		return nil, errors.New("[bootstrap] Device access 重复")
	}
	if len(deviceAccess) == 1 {
		access = deviceAccess[0]
	}
	runtime := &preparedBootstrapRuntime{access: access, unlocked: unlock, done: make(chan error, len(installation.Plans))}
	success := false
	defer func() {
		if !success {
			runtime.Close()
		}
	}()
	bundleHash, err := wire.HashObject("loom-bootstrap-installation-bundle-v1", bundle)
	if err != nil {
		return nil, err
	}
	binding := struct {
		Schema     int    `json:"schema"`
		DeviceID   string `json:"device_id"`
		BundleHash string `json:"bundle_hash"`
	}{1, deviceID, bundleHash}
	var prior struct {
		Schema     int    `json:"schema"`
		DeviceID   string `json:"device_id"`
		BundleHash string `json:"bundle_hash"`
	}
	bindingPath := filepath.Join(stateDir, "installation.json")
	if err := readCanonicalFile(bindingPath, 1<<20, &prior); err == nil {
		if !wire.EqualCanonical(prior, binding) {
			return nil, errors.New("[bootstrap] 持久状态已绑定另一安装，不能替换或回退")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	} else if err := writeCanonicalAtomic(bindingPath, binding, 0600); err != nil {
		return nil, err
	}
	manager, err := bootstrapaccess.Open(filepath.Join(stateDir, "capability-usage.json"), now)
	if err != nil {
		return nil, err
	}
	// 初始 prepared 阶段不接受任何 bearer；只有后续认证发布及实际邀请
	// capability 的验证输入才能开放加入，不能用固定 credential 代替。
	var resolver bootstrapaccess.CapabilityResolver
	dial := bootstrapaccess.DialContext((&net.Dialer{}).DialContext)
	if access != nil {
		resolver = access.Resolve
		dial = access.DialContext
	}
	registry, err := bootstrapaccess.NewCredentialRegistryWithResolver(installation.Catalog.BootstrapIngressSetHash,
		[]wire.VerifiedBootstrapCapabilityV1{}, resolver)
	if err != nil {
		return nil, err
	}
	for i, plan := range installation.Plans {
		listener := installation.Input.Listeners[i]
		if listener.Profile.ServerID != deviceID {
			continue
		}
		certificate, err := certmanager.LoadExistingRuntimeCertificate(certificateDir, listener.Certificate, listener.Certificate.Identity, roots, now().UTC())
		if err != nil {
			return nil, err
		}
		transition := rotation.Transition{NextPhase: "prepared", CertifiedHeadHash: bundle.Activation.Head.HeadHash, CertifiedAt: bundle.Activation.Head.Body.Payload.CommittedLogicalTime}
		verify := func(intent *rotation.IntentV1, current *rotation.StateV1, event *rotation.Transition) error {
			if current != nil || !wire.EqualCanonical(*intent, plan.Intent) || !wire.EqualCanonical(*event, transition) {
				return errors.New("[bootstrap] rotation 事件不属于已验证的认证安装")
			}
			return nil
		}
		slot := bootstrapStateSlot(plan.EndpointID)
		store, err := rotation.OpenStore(filepath.Join(stateDir, slot+"-rotation.json"), verify)
		if err != nil {
			return nil, err
		}
		if _, err := store.BeginPrepared(plan.Intent, transition); err != nil {
			return nil, err
		}
		plans, err := rotation.OpenExecutionPlanStore(filepath.Join(stateDir, slot+"-plan.json"))
		if err != nil {
			return nil, err
		}
		frozen, err := plans.Freeze(plan.Intent, plan.Execution)
		if err != nil {
			return nil, err
		}
		authorized, err := rotation.AuthorizeRuntimePlan(store.Snapshot(), frozen, verify)
		if err != nil {
			return nil, err
		}
		runtimePlan, err := bootstrapaccess.BuildBootstrapIngressRuntimePlan(&installation.Catalog, &installation.Input.Parent, &installation.Input.ControlSet, nil,
			authorized, &listener.Profile, &listener.Resources, plan.EndpointID, 1, now().UTC(), 2)
		if err != nil {
			return nil, err
		}
		transport, err := bootstrapaccess.NewBootstrapIngressRuntime(bootstrapaccess.BootstrapIngressRuntimeOptions{Plan: runtimePlan, Manager: manager, Registry: registry,
			TLSConfig: &tls.Config{Certificates: []tls.Certificate{certificate.TLSCertificate}, MinVersion: tls.VersionTLS13}, Dial: dial,
			HandshakeTimeout: 10 * time.Second, IdleTimeout: time.Minute, MaximumConcurrentConnections: 128, MaximumStreamsPerConnection: 8})
		if err != nil {
			return nil, err
		}
		generation, err := bootstrapaccess.StartPreparedBootstrapGeneration(ctx, transport, authorized, bootstrapaccess.BootstrapLocalReadinessOptions{
			TLSConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS13}, Now: now, Timeout: 10 * time.Second})
		if err != nil {
			return nil, err
		}
		runtime.generations = append(runtime.generations, generation)
		evidence, evidenceHash, err := generation.LocalEvidence()
		if err != nil {
			return nil, err
		}
		outer, err := generation.ProbePlan()
		if err != nil {
			return nil, err
		}
		readiness := bootstrapPreparedReadinessV1{Schema: 1, DeviceID: deviceID, BundleHash: bundleHash, LocalEvidence: evidence, LocalEvidenceHash: evidenceHash, OuterPlan: outer}
		if err := writeCanonicalAtomic(filepath.Join(stateDir, slot+"-readiness.json"), readiness, 0600); err != nil {
			return nil, err
		}
		if err := writeCanonicalAtomic(filepath.Join(stateDir, slot+"-outer-plan.json"), outer, 0600); err != nil {
			return nil, err
		}
		go func() { runtime.done <- generation.Wait() }()
	}
	if len(runtime.generations) == 0 {
		return nil, errors.New("[bootstrap] 没有本机 listener")
	}
	// 运行中任一批次失败由命令返回并关闭其他批次，systemd 不会保留半套入口。
	success = true
	return runtime, nil
}

func bootstrapStateSlot(endpointID string) string {
	return strings.TrimPrefix(wire.HashRaw("loom-bootstrap-endpoint-slot-v1", []byte(endpointID)), "sha256:")
}

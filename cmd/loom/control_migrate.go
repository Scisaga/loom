package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"time"

	"loom/internal/clientregistry"
	"loom/internal/model"
	"loom/internal/wire"
)

// 迁移输入包含全部目标 preimage；旧网络从独立文件再次读取并核对，不能把一份
// 自称已迁移的空 application 提交到原日志。输入不含可由操作者填写的 Head/QC。
type controlMigrationInputV1 struct {
	Schema         int                                 `json:"schema"`
	Source         string                              `json:"source"`
	Registry       string                              `json:"registry"`
	Application    controlApplicationV1                `json:"application"`
	RecoveryProofs []wire.RecoveryKeyPossessionProofV1 `json:"recovery_key_possession_proofs"`
	DeviceInputs   *controlMigrationDeviceInputsV1     `json:"device_inputs,omitempty"`
}

type controlMigrationRequestV1 struct {
	Schema     int                        `json:"schema"`
	InputHash  string                     `json:"input_hash"`
	Activation controlRuntimeActivationV1 `json:"activation"`
	Operation  wire.ControlOperationV1    `json:"operation"`
}

func cmdControlMigrate(args []string) error {
	fs := flag.NewFlagSet("control migrate", flag.ContinueOnError)
	dir := fs.String("state-dir", "/var/lib/loom-control", "已停止 daemon 的原控制状态目录")
	admin := fs.String("admin-dir", "", "当前管理员完整身份目录")
	inputPath := fs.String("input", "", "受保护的完整迁移输入")
	platformPath := fs.String("platform-key", "", "既有平台签名私钥")
	output := fs.String("out", "", "保存 exact 请求与回执的受保护目录")
	reason := fs.String("reason", "", "迁移理由")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 || *admin == "" || *inputPath == "" || *platformPath == "" || *output == "" || *reason == "" {
		return errors.New("control migrate 必须指定 -admin-dir、-input、-platform-key、-out、-reason")
	}
	unlock, err := lockControlState(*dir)
	if err != nil {
		return err
	}
	defer unlock()
	var config controlDiskConfigV1
	if err := readCanonicalFile(filepath.Join(*dir, controlConfigName), 8<<20, &config); err != nil {
		return err
	}
	// 早期 daemon 不持有维护锁，同时占住它的 listener 才能排除并发旧进程。
	var listeners []net.Listener
	defer func() {
		for _, listener := range listeners {
			_ = listener.Close()
		}
	}()
	for _, address := range []string{
		net.JoinHostPort(config.OverlayIP, fmt.Sprint(config.ControlPort)),
		net.JoinHostPort(controlLoopbackIP, fmt.Sprint(config.ControlPort)),
		net.JoinHostPort(config.OverlayIP, fmt.Sprint(config.RaftPort)),
	} {
		listener, err := net.Listen("tcp", address)
		if err != nil {
			return errors.New("控制 listener 尚未释放；迁移前须停止原 control daemon")
		}
		listeners = append(listeners, listener)
	}
	runtime, err := openControlRuntime(*dir, time.Now)
	if err != nil {
		return err
	}
	if err := runtime.migrateControlApplication(*inputPath, *admin, *platformPath, *output, *reason); err != nil {
		return err
	}
	fmt.Println("✓ 原控制日志已认证迁移；exact 请求与回执已保存")
	return nil
}

func (runtime *controlRuntime) migrateControlApplication(inputPath, adminDir, platformPath, output, reason string) error {
	raw, err := readOwnerOnlyFile(inputPath, 64<<20)
	if err != nil {
		return err
	}
	var input controlMigrationInputV1
	if _, err := wire.DecodeStrict(raw, 64<<20, &input); err != nil {
		return err
	}
	if input.Application.ClusterID != runtime.config.ClusterID {
		return errors.New("迁移输入不属于原网络")
	}
	inputHash, err := wire.HashObject("loom-control-migration-input-v1", input)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(output, 0o700); err != nil {
		return err
	}
	unlock, err := lockControlState(output)
	if err != nil {
		return err
	}
	defer unlock()
	requestPath := filepath.Join(output, "migration-request.json")
	var request controlMigrationRequestV1
	retained, err := readOwnerOnlyFile(requestPath, 64<<20)
	if errors.Is(err, os.ErrNotExist) {
		if input.DeviceInputs != nil {
			key, err := readKey(platformPath, ed25519.PrivateKeySize)
			if err != nil {
				return err
			}
			public := ed25519.PrivateKey(key).Public().(ed25519.PublicKey)
			clear(key)
			if err := runtime.prepareMigrationDevices(&input, public); err != nil {
				return err
			}
		} else if err := validateControlMigrationSource(&input); err != nil {
			return err
		}
		request, err = runtime.prepareControlMigration(input, inputHash, adminDir, platformPath, reason)
		if err != nil {
			return err
		}
		// 签名请求先耐久保存；崩溃后只恢复同一迁移，不能因重试更换 parent 或秘密。
		if err := writeCanonicalAtomic(requestPath, request, 0o600); err != nil {
			return err
		}
	} else if err != nil {
		return err
	} else {
		canonical, err := wire.DecodeStrict(retained, 64<<20, &request)
		if err != nil || !bytes.Equal(canonical, retained) || request.Schema != 1 || request.InputHash != inputHash ||
			request.Activation.Bundle.Proof.Statement.Reason != reason {
			return errors.New("迁移目录已绑定不同输入；不能覆盖原请求")
		}
		expected := controlClone(request.Activation.Application)
		if input.DeviceInputs != nil {
			if len(input.Application.Devices) != 0 || len(input.Application.DeviceMigrations) != 0 {
				return errors.New("逐设备请求不能混用手填迁移结果")
			}
			expected.Devices, expected.DeviceMigrations = input.Application.Devices, input.Application.DeviceMigrations
		}
		if !wire.EqualCanonical(expected, input.Application) {
			return errors.New("迁移请求不再对应原 application 输入")
		}
		input.Application = request.Activation.Application
		if err := validateControlMigrationSource(&input); err != nil {
			return err
		}
	}
	result, err := runtime.activateRuntime(request.Activation, request.Operation)
	if err != nil {
		return err
	}
	return writeCanonicalAtomic(filepath.Join(output, "migration-receipt.json"), result, 0o600)
}

func validateControlMigrationSource(input *controlMigrationInputV1) error {
	if input == nil || input.Schema != 1 || input.Source == "" || input.Registry == "" {
		return errors.New("迁移缺完整 source/registry 输入")
	}
	if _, err := input.Application.roots(); err != nil {
		return err
	}
	source, err := os.ReadFile(input.Source)
	if err != nil {
		return err
	}
	if !bytes.Equal(source, []byte(input.Application.LegacySSOT)) {
		return errors.New("迁移不能改写原 SSOT")
	}
	ssot, err := model.Load(source)
	if err != nil {
		return err
	}
	registry, err := readOwnerOnlyFile(input.Registry, 4<<20)
	if err != nil {
		return err
	}
	if wire.HashRaw("loom-legacy-registry-migration-v1", registry) != input.Application.LegacyRegistryHash {
		return errors.New("迁移 registry 承诺不匹配原始数据")
	}
	if _, err := wire.CanonicalizeStrict(registry); err != nil {
		return err
	}
	var previous struct {
		Schema  int                     `json:"schema"`
		Clients []clientregistry.Client `json:"clients"`
		Invites []json.RawMessage       `json:"invites"`
	}
	if _, err := wire.DecodeStrict(registry, 4<<20, &previous); err != nil || previous.Schema != clientregistry.Schema {
		return errors.New("迁移 registry 不是可验证的当前存储格式")
	}
	devices := make(map[string]controlDeviceStateV1, len(input.Application.Devices))
	for _, device := range input.Application.Devices {
		devices[device.View.DeviceID] = device
	}
	deferred := make(map[string]controlDeferredDeviceMigrationV1, len(input.Application.DeferredMigrations))
	for _, record := range input.Application.DeferredMigrations {
		deferred[record.DeviceID] = record
	}
	for _, node := range ssot.Nodes {
		if _, found := devices[node.ID]; !found {
			if _, retained := deferred[node.ID]; !retained {
				return errors.New("迁移缺少原 SSOT 中的 Device，不能用空网络替代")
			}
		}
	}
	migrations := make(map[string]wire.RuntimeDeviceMigrationLeafV1, len(input.Application.DeviceMigrations))
	for _, migration := range input.Application.DeviceMigrations {
		migrations[migration.DeviceID] = migration
	}
	for _, node := range ssot.Nodes {
		if devices[node.ID].View.State == "active" {
			if _, found := migrations[node.ID]; !found {
				return errors.New("迁移缺少原 Device 的身份、证书与 floor 承诺")
			}
		}
	}
	for _, client := range previous.Clients {
		if client.PublicKey == "" {
			continue
		}
		device, found := devices[client.ID]
		if !found {
			pending, retained := deferred[client.ID]
			spki, err := base64.RawStdEncoding.Strict().DecodeString(client.PublicKey)
			hash, hashErr := wire.HashBytes(wire.DomainEnrollmentIdentitySPKI, spki)
			if !retained || client.Status == "revoked" || err != nil || hashErr != nil || pending.IdentitySPKIHash != hash || pending.Platform != client.Platform {
				return errors.New("迁移丢失或替换原 registry 中的已加入身份")
			}
			delete(deferred, client.ID)
			continue
		}
		if client.Status == "revoked" {
			if device.View.State == "active" {
				return errors.New("迁移不得恢复已撤权身份")
			}
			continue
		}
		spki, err := base64.RawStdEncoding.Strict().DecodeString(client.PublicKey)
		if err != nil {
			return errors.New("原身份 SPKI 编码无效")
		}
		hash, err := wire.HashBytes(wire.DomainEnrollmentIdentitySPKI, spki)
		if err != nil || device.View.Active == nil || device.View.Active.IdentitySPKIHash != hash {
			return errors.New("迁移改变了已加入 Device 的身份 key")
		}
		migration, found := migrations[client.ID]
		if !found || migration.IdentitySPKIHash != hash || client.Platform != "" && migration.Platform != client.Platform {
			return errors.New("迁移未保留已加入 Device 的逐设备身份或平台")
		}
	}
	if len(deferred) != 0 {
		return errors.New("暂存身份没有对应的原 registry 记录")
	}
	return nil
}

func (runtime *controlRuntime) prepareControlMigration(input controlMigrationInputV1, inputHash, adminDir, platformPath, reason string) (controlMigrationRequestV1, error) {
	var request controlMigrationRequestV1
	state := runtime.store.Snapshot()
	if state.CertifiedHead == nil || state.CertifiedQC == nil || state.Active != nil {
		return request, errors.New("迁移要求稳定的原 certified Head")
	}
	adminPEM, err := readOwnerOnlyFile(filepath.Join(adminDir, controlAdminCertName), 1<<20)
	if err != nil {
		return request, err
	}
	admin, err := parseSingleCertificatePEM(adminPEM)
	if err != nil || !runtime.adminCertificateAuthorizedLocked(admin.Raw) {
		return request, errors.New("迁移管理员不属于当前 certified ACL")
	}
	var authorization wire.AdminAuthorizationV1
	for _, candidate := range runtime.config.Authorizations {
		if candidate.AdminCertificateDER == base64.RawURLEncoding.EncodeToString(admin.Raw) {
			authorization = candidate
		}
	}
	var secrets controlDiskSecretsV1
	if err := readCanonicalFile(filepath.Join(runtime.dir, controlSecretsName), 8<<20, &secrets); err != nil {
		return request, err
	}
	ownerKey, err := parsePrivateKeyPKCS8PEM([]byte(secrets.AdminCAPrivateKeyPKCS8PEM))
	if err != nil {
		return request, err
	}
	platformBytes, err := readKey(platformPath, ed25519.PrivateKeySize)
	if err != nil {
		return request, err
	}
	defer clear(platformBytes)
	platform := ed25519.PrivateKey(platformBytes)
	public := platform.Public().(ed25519.PublicKey)
	keyID, _ := wire.ControlKeyID(public)
	digest := sha256.Sum256(public)
	roots, err := input.Application.roots()
	if err != nil {
		return request, err
	}
	policyHash, _ := wire.RecoveryPolicyHash(&input.Application.RecoveryPolicy)
	popRoot, err := wire.RecoveryKeyPossessionRoot(&input.Application.RecoveryPolicy, input.RecoveryProofs)
	if err != nil {
		return request, err
	}
	qc, _ := wire.MarshalCanonical(state.CertifiedQC)
	qcHash, _ := wire.ConfigQCHash(qc)
	issued := runtime.now().UTC().Truncate(time.Second)
	migrationRoot, err := wire.RuntimeDeviceMigrationRoot(input.Application.DeviceMigrations)
	if err != nil {
		return request, err
	}
	operationID := "migration-" + inputHash[len("sha256:"):]
	statement := wire.RuntimeActivationStatementV1{Schema: 1, ClusterID: runtime.config.ClusterID, OperationID: operationID,
		ParentHeadHash: state.CertifiedHead.HeadHash, ParentQCHash: qcHash, LegacyRecoveryPolicyHash: state.CertifiedHead.Body.Payload.RecoveryPolicyHash,
		V1PlatformKeyID: keyID, V1PlatformPublicKey: base64.RawURLEncoding.EncodeToString(public), V1PlatformKeyDigest: fmt.Sprintf("sha256:%x", digest),
		NewRecoveryEpoch: 2, NewRecoveryPolicyHash: policyHash, NewRecoveryKeyPoPRoot: popRoot, DeviceMigrationRoot: migrationRoot,
		Roots: roots, IssuedAt: issued.Format(time.RFC3339), Reason: reason}
	// 原 owner preimage 由磁盘中的初始 profile 恢复，不能用轮换后的浏览器 issuer 代替。
	policy, err := runtime.legacyRuntimePolicy()
	if err != nil {
		return request, err
	}
	proof, err := wire.SignRuntimeActivationProof(statement, policy, ownerKey, platform)
	if err != nil {
		return request, err
	}
	activation := controlRuntimeActivationV1{Application: input.Application, PreviousAuthorization: authorization,
		PreviousProfile: runtime.config.AdminProfiles[authorization.CertificateProfileRef.ProfileID],
		Bundle: wire.RuntimeActivationBundleV1{Schema: 1, Proof: proof, Parent: *state.CertifiedHead, ParentQC: *state.CertifiedQC,
			ControlSet: state.ControlSet, RecoveryPolicy: input.Application.RecoveryPolicy, RecoveryKeyPossessionProofs: input.RecoveryProofs,
			PreviousOperationLeaves: runtime.operationLeaves(len(runtime.journal.Records))}}
	var endpoint controlAdminEndpointV1
	if err := readCanonicalFile(filepath.Join(adminDir, controlEndpointName), 4<<20, &endpoint); err != nil {
		return request, err
	}
	status := controlStatusResponseV1{Schema: 1, ClusterID: runtime.config.ClusterID, MemberID: runtime.config.MemberID,
		Quorum: 1, Head: *state.CertifiedHead, ConfigQC: qc, ControlSet: state.ControlSet, Service: runtime.config.ControlService}
	signed, err := newControlPingRequest(adminDir, endpoint, status, operationID, issued)
	if err != nil {
		return request, err
	}
	adminKeyPEM, err := readOwnerOnlyFile(filepath.Join(adminDir, controlAdminKeyName), 1<<20)
	if err != nil {
		return request, err
	}
	defer clear(adminKeyPEM)
	adminKey, err := parseAdminPrivateKey(adminKeyPEM)
	if err != nil {
		return request, err
	}
	body := signed.Operation.Body
	body.Kind, body.OperationID = controlActivationKind, operationID
	body.PayloadHash, _ = wire.RuntimeActivationStatementHash(&statement)
	operation, err := wire.NewControlOperation(body, adminKey, controlActivationSchemas)
	if err != nil {
		return request, err
	}
	return controlMigrationRequestV1{Schema: 1, InputHash: inputHash, Activation: activation, Operation: operation}, nil
}

func (runtime *controlRuntime) legacyRuntimePolicy() (wire.LegacyRuntimePolicyV1, error) {
	var initial controlDiskConfigV1
	if err := readCanonicalFile(filepath.Join(runtime.dir, controlConfigName), 8<<20, &initial); err != nil {
		return wire.LegacyRuntimePolicyV1{}, err
	}
	for _, authorization := range initial.Authorizations {
		profile := initial.AdminProfiles[authorization.CertificateProfileRef.ProfileID]
		for _, issuer := range profile.IssuerChainDER {
			policy := wire.LegacyRuntimePolicyV1{Schema: 1, AdminRoot: issuer}
			hash, err := wire.HashObject(wire.DomainLegacyRuntimePolicy, policy)
			if err == nil && hash == initial.GenesisEvidence.RecoveryPolicyHash {
				return policy, nil
			}
		}
	}
	return wire.LegacyRuntimePolicyV1{}, errors.New("初始 profile 中缺少与原 genesis 承诺相符的 owner root")
}

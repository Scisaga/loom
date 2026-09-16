package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"loom/internal/bootstrapaccess"
	"loom/internal/certmanager"
	"loom/internal/model"
	"loom/internal/publish"
	"loom/internal/wire"
)

type controlExistingMirrorInputV1 struct {
	EndpointID      string                                   `json:"endpoint_id"`
	ServerID        string                                   `json:"server_id"`
	ServerName      string                                   `json:"server_name"`
	Port            int64                                    `json:"port"`
	AddressFamilies []string                                 `json:"address_families"`
	Certificate     certmanager.ExistingCertificateBindingV1 `json:"certificate"`
}

// 输入只定位原始材料与现有 mirror。Head、QC、issuer public key、set digest
// 和逐设备 view 都由正式生产器生成，操作者不填写认证结果。
type controlPrepareMigrationInputV1 struct {
	Schema             int                                `json:"schema"`
	RequestID          string                             `json:"request_id"`
	Source             string                             `json:"source"`
	Registry           string                             `json:"registry"`
	MaterialsPath      string                             `json:"materials_path"`
	RecoveryPath       string                             `json:"recovery_path"`
	BootstrapPath      string                             `json:"bootstrap_path"`
	DeviceInputsPath   string                             `json:"device_inputs_path"`
	InvitePolicy       wire.InviteIssuancePolicyV2        `json:"invite_policy"`
	Mirrors            []controlExistingMirrorInputV1     `json:"mirrors"`
	DeferredMigrations []controlDeferredDeviceMigrationV1 `json:"deferred_migrations,omitempty"`
}

func cmdControlPrepareMigrationInput(args []string) error {
	flags := flag.NewFlagSet("control prepare-migration-input", flag.ContinueOnError)
	dir := flags.String("state-dir", "/var/lib/loom-control", "原控制状态目录")
	admin := flags.String("admin-dir", "", "原管理员材料目录")
	input := flags.String("input", "", "原材料与现有静态镜像输入")
	out := flags.String("out", "", "完整受保护迁移输入")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 || *admin == "" || *input == "" || !filepath.IsAbs(*out) {
		return errors.New("prepare-migration-input 需要 admin-dir、input 和 out 绝对路径")
	}
	parent, err := os.Lstat(filepath.Dir(*out))
	if err != nil || !parent.IsDir() || parent.Mode().Perm() != 0700 || parent.Mode()&os.ModeSymlink != 0 {
		return errors.New("迁移输入输出须位于已有的 0700 实体目录")
	}
	var request controlPrepareMigrationInputV1
	if err := readCanonicalFile(*input, 32<<20, &request); err != nil {
		return err
	}
	endpoint, client, err := loadControlAdminClient(*admin)
	if err != nil {
		return err
	}
	defer client.CloseIdleConnections()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	status, err := fetchControlStatus(ctx, endpoint, client)
	if err != nil {
		return err
	}
	prepared, err := prepareMigrationInput(*dir, request, status, nil, time.Now().UTC().Truncate(time.Second))
	if err != nil {
		return err
	}
	var prior controlMigrationInputV1
	if err := readCanonicalFile(*out, 64<<20, &prior); err == nil {
		if !wire.EqualCanonical(prior, prepared) {
			return errors.New("迁移输出已绑定另一份输入；不能覆盖")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	} else if err := writeCanonicalAtomic(*out, prepared, 0600); err != nil {
		return err
	}
	fmt.Println("✓ 已生成完整迁移输入，保留原网络与设备请求；尚未认证激活")
	return nil
}

func prepareMigrationInput(dir string, request controlPrepareMigrationInputV1, status controlStatusResponseV1,
	roots *x509.CertPool, now time.Time) (controlMigrationInputV1, error) {
	var result controlMigrationInputV1
	if request.Schema != 1 || request.RequestID == "" || len(request.RequestID) > 128 || status.Schema != 1 {
		return result, errors.New("迁移组装输入格式或请求 ID 无效")
	}
	var config controlDiskConfigV1
	if err := readCanonicalFile(filepath.Join(dir, controlConfigName), 8<<20, &config); err != nil {
		return result, err
	}
	if config.ClusterID != status.ClusterID || config.ControlService.ServiceID != status.Service.ServiceID {
		return result, errors.New("迁移输入未绑定本机原控制服务")
	}
	if err := wire.VerifyConfigQCAuthority(status.Head.HeadHash, status.ConfigQC, &status.Head, &status.ControlSet, nil); err != nil {
		return result, err
	}
	var materials controlPreparedMigrationMaterialsV1
	var recovery controlRecoveryMaterialV1
	var bootstrap bootstrapaccess.InitialBootstrapInstallationV1
	var devices controlMigrationDeviceInputsV1
	for _, input := range []struct {
		path string
		into any
	}{{request.MaterialsPath, &materials}, {request.RecoveryPath, &recovery}, {request.BootstrapPath, &bootstrap}, {request.DeviceInputsPath, &devices}} {
		if err := readCanonicalFile(input.path, 32<<20, input.into); err != nil {
			return result, err
		}
	}
	if materials.Schema != 1 || materials.ClusterID != config.ClusterID || materials.DeviceID != config.DeviceID ||
		recovery.Schema != 1 || recovery.Policy.ClusterID != config.ClusterID || devices.Schema != 1 || len(devices.Entries) == 0 ||
		request.InvitePolicy.ClusterID != config.ClusterID || !wire.EqualCanonical(bootstrap.Input.Parent, status.Head) ||
		!wire.EqualCanonical(bootstrap.Input.ControlSet, status.ControlSet) {
		return result, errors.New("迁移材料不属于原网络、设备或当前认证 parent")
	}
	if err := bootstrapaccess.ValidateInitialBootstrapInstallation(&bootstrap); err != nil {
		return result, err
	}
	policyHash, err := wire.InviteIssuancePolicyHash(&request.InvitePolicy)
	if err != nil {
		return result, err
	}
	if int64(len(request.Mirrors)) < request.InvitePolicy.MinimumDistributionMirrors || int64(len(request.Mirrors)) > request.InvitePolicy.MaximumDistributionMirrors {
		return result, errors.New("现有静态镜像数量不满足邀请策略")
	}
	source, err := os.ReadFile(request.Source)
	if err != nil {
		return result, err
	}
	ssot, err := model.Load(source)
	if err != nil {
		return result, err
	}
	registry, err := readOwnerOnlyFile(request.Registry, 4<<20)
	if err != nil {
		return result, err
	}
	if _, err := readControlLegacyRegistry(request.Registry, wire.HashRaw("loom-legacy-registry-migration-v1", registry)); err != nil {
		return result, err
	}
	sets, mirrors, err := prepareExistingDistribution(request.Mirrors, status, bootstrap.Catalog.ValidFrom, bootstrap.Catalog.ValidUntil, roots, now)
	if err != nil {
		return result, err
	}
	nodes := ssot.NodeByID()
	for _, mirror := range request.Mirrors {
		node := nodes[mirror.ServerID]
		if node == nil || node.Server == nil || node.Decommission || node.Paused {
			return result, errors.New("静态 mirror 不属于原网络中的活动服务器")
		}
	}
	enroll := ""
	for _, material := range materials.PrivateServices.Services {
		if material.Service.Role == "enroll" {
			if enroll != "" {
				return result, errors.New("迁移材料重复提供 Enrollment 服务")
			}
			enroll = material.Service.ServiceID
		}
	}
	if enroll == "" {
		return result, errors.New("迁移材料缺独立 Enrollment 服务")
	}
	// 原 authority 不变；这是受限 capability 的独立 issuer，不能签 Device 或 Head。
	issuer, err := prepareBootstrapIssuer(dir, request.RequestID, config.ClusterID, policyHash, request.InvitePolicy,
		bootstrap.Catalog, enroll)
	if err != nil {
		return result, err
	}
	result = controlMigrationInputV1{Schema: 1, Source: request.Source, Registry: request.Registry, DeviceInputs: &devices,
		Prepared: &controlMigrationPreparedV1{Schema: 1, ClusterID: config.ClusterID, Materials: materials, Recovery: recovery,
			InvitePolicy: request.InvitePolicy, BootstrapCatalog: bootstrap.Catalog, BootstrapInstallation: &bootstrap,
			BootstrapIssuers: []wire.BootstrapIssuerAuthorizationV1{issuer}, DistributionSets: sets, Mirrors: mirrors,
			DeferredMigrations: request.DeferredMigrations}}
	return result, nil
}

func prepareExistingDistribution(inputs []controlExistingMirrorInputV1, status controlStatusResponseV1, from, until string,
	roots *x509.CertPool, now time.Time) ([]wire.DistributionEndpointSetV1, []wire.DistributionMirrorRefV1, error) {
	sets := make([]wire.DistributionEndpointSetV1, 0, len(inputs))
	mirrors := make([]wire.DistributionMirrorRefV1, 0, len(inputs))
	for i, input := range inputs {
		if i > 0 && inputs[i-1].EndpointID >= input.EndpointID || input.Port < 1 || input.Port > 65535 || !wire.ValidFQDN(input.ServerName) ||
			input.Certificate.Identity.ClusterID != status.ClusterID || input.Certificate.Identity.KeyOwnerDeviceID != input.ServerID ||
			!containsControlValue(input.Certificate.Identity.DNSNames, input.ServerName) || !containsControlValue(input.Certificate.Identity.EndpointIDs, input.EndpointID) ||
			input.Certificate.NotBefore > from || input.Certificate.NotAfter < until {
			return nil, nil, errors.New("distribution 身份、名称、端口、顺序或证书有效期不匹配")
		}
		if err := certmanager.VerifyExistingPublicCertificate(input.Certificate, roots, now); err != nil {
			return nil, nil, err
		}
		bindingHash, err := certmanager.ExistingCertificateBindingHash(&input.Certificate)
		if err != nil {
			return nil, nil, err
		}
		profile := input.Certificate.Identity.IssuerProfileRef
		identities := []string{profile, input.Certificate.Identity.SPKIHash}
		sort.Strings(identities)
		listener := wire.ListenerGenerationV2{Schema: 2, ListenerGeneration: 1, PublishedState: "preferred", DialTargetFQDN: input.ServerName,
			PublicPort: input.Port, AddressFamilies: input.AddressFamilies, TransportIdentityRefs: identities, CredentialGeneration: 1,
			CertificateIdentityProjectionHash: input.Certificate.IdentityProjectionHash, PublicProfileGeneration: 1,
			IntroducedRevision: status.Head.Body.Payload.ControlRevision + 1, ValidFrom: from, ValidUntil: until, RotationOperationHash: bindingHash}
		set := wire.DistributionEndpointSetV1{Schema: 1, ClusterID: status.ClusterID, EndpointSetID: input.EndpointID, Generation: 1,
			ValidFrom: from, ValidUntil: until, ParentHeadHash: status.Head.HeadHash, ConfigQC: status.ConfigQC,
			Endpoints: []wire.DistributionEndpointV1{{EndpointID: input.EndpointID, LogicalServerID: input.ServerID, Transport: "https",
				DistributionPathPrefix: "/distribution/sha256/", ListenerGenerations: []wire.ListenerGenerationV2{listener}, ListenerTombstones: []wire.ListenerGenerationTombstoneV1{}}}}
		hash, err := wire.DistributionEndpointSetHash(&set)
		if err != nil {
			return nil, nil, err
		}
		sets = append(sets, set)
		mirrors = append(mirrors, wire.DistributionMirrorRefV1{Schema: 1, EndpointID: input.EndpointID, DistributionEndpointSetHash: hash,
			ListenerGeneration: 1, BaseURL: "https://" + net.JoinHostPort(input.ServerName, strconv.FormatInt(input.Port, 10)) + "/distribution/sha256/",
			ServerName: input.ServerName, WebPKIProfileRef: profile, SPKIPins: []string{input.Certificate.Identity.SPKIHash}, HintRank: int64(i)})
	}
	byHash := make(map[string]wire.DistributionEndpointSetV1, len(sets))
	for _, set := range sets {
		hash, _ := wire.DistributionEndpointSetHash(&set)
		byHash[hash] = set
	}
	return sets, mirrors, wire.ValidateDistributionMirrorBindings(status.ClusterID, mirrors, byHash)
}

func prepareBootstrapIssuer(dir, requestID, cluster, policyHash string, policy wire.InviteIssuancePolicyV2,
	catalog wire.BootstrapEndpointCatalogV1, serviceID string) (wire.BootstrapIssuerAuthorizationV1, error) {
	var empty wire.BootstrapIssuerAuthorizationV1
	root := filepath.Join(dir, "bootstrap-issuers")
	if err := os.MkdirAll(root, 0700); err != nil {
		return empty, err
	}
	info, err := os.Lstat(root)
	if err != nil || !info.IsDir() || info.Mode().Perm() != 0700 || info.Mode()&os.ModeSymlink != 0 {
		return empty, errors.New("bootstrap issuer 存储必须是 0700 实体目录")
	}
	unlock, err := publish.AcquireLock(filepath.Join(root, "prepare.lock"))
	if err != nil {
		return empty, err
	}
	defer unlock()
	input := struct {
		RequestID string `json:"request_id"`
		ClusterID string `json:"cluster_id"`
	}{requestID, cluster}
	id, _ := wire.HashObject("loom-bootstrap-issuer-preparation-v1", input)
	path := filepath.Join(root, "request-"+strings.TrimPrefix(id, "sha256:")+".json")
	var material controlBootstrapIssuerKeyV1
	if err := readCanonicalFile(path, 8192, &material); errors.Is(err, os.ErrNotExist) {
		entries, err := os.ReadDir(root)
		if err != nil {
			return empty, err
		}
		for _, entry := range entries {
			if entry.Name() != "prepare.lock" {
				return empty, errors.New("bootstrap issuer 已有材料但缺此请求；不能重新生成身份")
			}
		}
		public, private, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return empty, err
		}
		defer clear(private)
		keyID, _ := wire.ControlKeyID(public)
		material = controlBootstrapIssuerKeyV1{Schema: 1, KeyID: keyID, PrivateKey: base64.RawURLEncoding.EncodeToString(private)}
		if err := writeCanonicalAtomic(path, material, 0600); err != nil {
			return empty, err
		}
	} else if err != nil {
		return empty, err
	}
	private, err := base64.RawURLEncoding.DecodeString(material.PrivateKey)
	if err != nil || material.Schema != 1 || len(private) != ed25519.PrivateKeySize {
		return empty, errors.New("bootstrap issuer 准备材料损坏；不能自动更换密钥")
	}
	defer clear(private)
	key := ed25519.PrivateKey(private)
	if !key.Equal(ed25519.NewKeyFromSeed(key.Seed())) {
		return empty, errors.New("bootstrap issuer 私钥自检失败")
	}
	public := key.Public().(ed25519.PublicKey)
	keyID, _ := wire.ControlKeyID(public)
	if keyID != material.KeyID {
		return empty, errors.New("bootstrap issuer key ID 与原材料不一致")
	}
	keyPath := filepath.Join(root, strings.TrimPrefix(keyID, "sha256:")+".json")
	// 同一份耐久记录以内容 ID 链接给正式 daemon；崩溃重试不再生成 key。
	if err := os.Link(path, keyPath); err != nil && !errors.Is(err, os.ErrExist) {
		return empty, err
	}
	var stored controlBootstrapIssuerKeyV1
	if err := readCanonicalFile(keyPath, 8192, &stored); err != nil || !wire.EqualCanonical(stored, material) {
		return empty, errors.New("bootstrap issuer 不可变 key 与请求材料冲突")
	}
	if err := syncDirectory(root); err != nil {
		return empty, err
	}
	issuer := wire.BootstrapIssuerAuthorizationV1{Schema: 1, ClusterID: cluster, AuthorizationID: "bootstrap-issuer", Generation: 1,
		Status: "active", ParentHeadHash: catalog.ParentHeadHash, Active: &wire.BootstrapIssuerAuthorizationActiveV1{IssuerEpoch: 1,
			IssuerKeyID: keyID, IssuerPublicKey: base64.RawURLEncoding.EncodeToString(public), InviteIssuancePolicyHash: policyHash,
			ValidFrom: catalog.ValidFrom, ValidUntil: catalog.ValidUntil,
			MaximumCapabilityTTLSeconds: max(policy.MaximumInitialCapabilityTTLSeconds, policy.MaximumResumeCapabilityTTLSeconds),
			MaximumConnectionAttempts:   policy.BootstrapConnectionAttempts, MaximumConcurrentSessions: policy.BootstrapMaxConcurrentSessions,
			MaximumSessionSeconds: policy.BootstrapSessionSeconds, MaximumTotalBytes: policy.BootstrapTotalBytes,
			PermittedIngressSetHashes: []string{catalog.BootstrapIngressSetHash}, PermittedServiceIDs: []string{serviceID},
			PermittedModes: []string{"initial_claim", "resume_committed_claim"}}}
	_, err = wire.BootstrapIssuerAuthorizationHash(&issuer)
	return issuer, err
}

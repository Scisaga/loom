package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"loom/internal/clientmigration"
	"loom/internal/clientregistry"
	"loom/internal/enrollmentv2"
	"loom/internal/model"
	"loom/internal/wire"
)

// 请求由原 Device key 签名，服务器的原证书/CA 是独立迁移输入；不能从请求
// 自报的 SPKI 推导“预期身份”。原 signed current 由平台旧签名和本机 floor 验证。
type controlMigrationDeviceInputsV1 struct {
	Schema      int                             `json:"schema"`
	ServerCAPEM string                          `json:"server_ca_pem"`
	Entries     []controlMigrationDeviceInputV1 `json:"entries"`
}

type controlMigrationDeviceInputV1 struct {
	Request              wire.RuntimeDeviceMigrationRequestV1 `json:"request"`
	ServerCertificatePEM string                               `json:"server_certificate_pem,omitempty"`
	LegacySignedCurrent  string                               `json:"legacy_signed_current"`
}

type controlLegacyRegistryV1 struct {
	Schema  int                     `json:"schema"`
	Clients []clientregistry.Client `json:"clients"`
	Invites []json.RawMessage       `json:"invites"`
}

func readControlLegacyRegistry(path string, expectedHash string) (controlLegacyRegistryV1, error) {
	var registry controlLegacyRegistryV1
	raw, err := readOwnerOnlyFile(path, 4<<20)
	if err != nil {
		return registry, err
	}
	if wire.HashRaw("loom-legacy-registry-migration-v1", raw) != expectedHash {
		return registry, errors.New("原 registry 与迁移承诺不同")
	}
	if _, err := wire.DecodeStrict(raw, 4<<20, &registry); err != nil || registry.Schema != clientregistry.Schema {
		return registry, errors.New("迁移 registry 不是受支持的原存储格式")
	}
	return registry, nil
}

// 只有 control migrate 在维护锁内、原 Raft 已加载后调用，签发坐标等于接下来
// 真正提交的迁移记录。Device view 由原权限生成，不接受手填证书 hash 或新身份。
func (runtime *controlRuntime) prepareMigrationDevices(input *controlMigrationInputV1, platform ed25519.PublicKey) error {
	if input == nil || input.Schema != 1 || input.Source == "" || input.Registry == "" || input.Application.ClusterID != runtime.config.ClusterID {
		return errors.New("逐设备迁移缺原网络、source 或 registry 输入")
	}
	spec := input.DeviceInputs
	if spec == nil || spec.Schema != 1 || len(spec.Entries) == 0 || len(platform) != ed25519.PublicKeySize ||
		len(input.Application.Devices) != 0 || len(input.Application.DeviceMigrations) != 0 {
		return errors.New("逐设备迁移要求原始请求，且不能同时提交手填 Device view/certificate")
	}
	ssot, err := model.Load([]byte(input.Application.LegacySSOT))
	if err != nil {
		return err
	}
	source, err := os.ReadFile(input.Source)
	if err != nil || !bytes.Equal(source, []byte(input.Application.LegacySSOT)) {
		return errors.New("逐设备迁移不允许替换原 SSOT")
	}
	registry, err := readControlLegacyRegistry(input.Registry, input.Application.LegacyRegistryHash)
	if err != nil {
		return err
	}
	clients := map[string]clientregistry.Client{}
	for _, client := range registry.Clients {
		if _, duplicate := clients[client.ID]; duplicate {
			return errors.New("原 registry 设备重复")
		}
		clients[client.ID] = client
	}
	roots := x509.NewCertPool()
	if spec.ServerCAPEM != "" && !roots.AppendCertsFromPEM([]byte(spec.ServerCAPEM)) {
		return errors.New("原服务器 CA 无效")
	}
	// 原节点观测与 v2 私有服务使用不同 CA；把已验证的原根一起认证迁移，
	// 不得用新控制 TLS 根代替原观测身份。
	if input.Application.ObservationCAPEM != "" && input.Application.ObservationCAPEM != spec.ServerCAPEM {
		return errors.New("迁移输入替换了原服务器观测 CA")
	}
	input.Application.ObservationCAPEM = spec.ServerCAPEM
	// 此文件由正式材料准备命令生成；profile 必须与其真实封装密钥相符。
	var profile wire.DeviceCertificateProfileStateV1
	if err := readCanonicalFile(filepath.Join(runtime.dir, "software-material", "device-ca-prepared.json"), 4<<20, &profile); err != nil {
		return err
	}
	profileFound := false
	for _, candidate := range input.Application.CARegistry.DeviceProfiles {
		profileFound = profileFound || wire.EqualCanonical(candidate, profile)
	}
	if !profileFound {
		return errors.New("迁移 CA registry 未包含本机准备的真实 Device profile")
	}
	issuer, err := runtime.loadDeviceIssuer(profile)
	if err != nil {
		return err
	}
	defer clearControlSigner(issuer)
	profileHash, err := wire.DeviceCertificateProfileStateHash(&profile)
	if err != nil {
		return err
	}
	coordinate := wire.IssuanceLogCoordinateV1{RecoveryEpoch: 2, RaftIndex: runtime.storage.SnapshotRaft().CommitIndex + 1}
	now := runtime.now().UTC().Truncate(time.Second)
	platformHash := fmt.Sprintf("sha256:%x", sha256.Sum256(platform))
	nodes := ssot.NodeByID()
	for i, entry := range spec.Entries {
		request := entry.Request
		id := request.Body.DeviceID
		if i > 0 && spec.Entries[i-1].Request.Body.DeviceID >= id {
			return errors.New("迁移请求必须按原 Device ID 唯一排序")
		}
		node := nodes[id]
		if node == nil || node.Decommission || node.Paused {
			return errors.New("迁移请求缺原活动 Device，或原设备暂停/退役状态尚不能投影")
		}
		platformName, roles, grants, err := migrationDeviceAuthorization(ssot, node)
		if err != nil {
			return err
		}
		if request.Body.Platform != platformName {
			return errors.New("迁移请求改变了原设备平台")
		}
		identity, err := originalMigrationDeviceIdentity(id, platformName, clients[id], entry.ServerCertificatePEM, roots)
		if err != nil {
			return err
		}
		if err := wire.VerifyRuntimeDeviceMigrationRequest(&request, identity, platformHash); err != nil {
			return err
		}
		floor, err := clientmigration.ParseFloor(request.Body.LegacyFloor)
		if err != nil {
			return err
		}
		current, err := base64.RawURLEncoding.Strict().DecodeString(entry.LegacySignedCurrent)
		if err != nil || base64.RawURLEncoding.EncodeToString(current) != entry.LegacySignedCurrent {
			return errors.New("原 signed current 编码无效")
		}
		floorLeaf, err := clientmigration.VerifyFloor(current, platform, id, floor)
		if err != nil {
			return err
		}
		certificate, err := enrollmentv2.PrepareMigratedDeviceCertificate(request, identity, platformHash, profile, roles.Values, coordinate, now, issuer, rand.Reader)
		if err != nil {
			return err
		}
		certificateHash, err := wire.DeviceCertificateHash(certificate)
		if err != nil {
			return err
		}
		wrappingDER, err := base64.RawURLEncoding.Strict().DecodeString(request.Body.WrappingSPKIDER)
		if err != nil {
			return err
		}
		wrappingHash, err := wire.HashBytes(wire.DomainEnrollmentWrappingSPKI, wrappingDER)
		if err != nil {
			return err
		}
		bundle := wire.DeviceEndpointBundleV1{Schema: 1, ClusterID: input.Application.ClusterID, DeviceID: id, DeviceGeneration: 1,
			DataIngressSets: []wire.DeviceDataIngressBindingV1{}}
		active := wire.DeviceActiveViewV1{IdentitySPKIHash: identity, Membership: wire.EnrollmentMembershipV1{Schema: 1, DesiredState: "active_on_completion"},
			Responsibilities: roles, Grants: grants, EndpointBundle: bundle, ConfigArtifactRefs: []wire.DeviceConfigArtifactRefV1{}}
		active.MembershipHash, err = wire.HashObject("loom-enrollment-membership-v1", active.Membership)
		if err != nil {
			return err
		}
		active.ResponsibilitiesHash, err = wire.HashObject("loom-enrollment-responsibilities-v1", roles)
		if err != nil {
			return err
		}
		active.GrantsHash, err = wire.HashObject("loom-enrollment-destination-grants-v1", grants)
		if err != nil {
			return err
		}
		active.EndpointBundleHash, err = wire.DeviceEndpointBundleHash(&bundle)
		if err != nil {
			return err
		}
		active.SecretArtifactRefsRoot, err = wire.SecretArtifactRefsRoot([]wire.SecretArtifactRefV2{})
		if err != nil {
			return err
		}
		device := controlDeviceStateV1{View: wire.DeviceViewPayloadV2{Schema: 2, ClusterID: input.Application.ClusterID, DeviceID: id, DeviceGeneration: 1, State: "active", Active: &active},
			PreviousViewHash: wire.EmptyHashV1, SecretArtifactRefs: []wire.SecretArtifactRefV2{}}
		if _, err := wire.DeviceViewHash(&device.View); err != nil {
			return err
		}
		input.Application.Devices = append(input.Application.Devices, device)
		input.Application.DeviceMigrations = append(input.Application.DeviceMigrations, wire.RuntimeDeviceMigrationLeafV1{Schema: 1,
			ClusterID: input.Application.ClusterID, DeviceID: id, Platform: platformName, IdentitySPKIHash: identity, WrappingKeyHash: wrappingHash,
			LegacyFloor: floorLeaf, DeviceCertificateHash: certificateHash, DeviceCertificateProfileHash: profileHash, Issuance: coordinate})
		if err := persistMigrationContent(runtime.dir, "migration-certificates", certificateHash, ".der", certificate); err != nil {
			return err
		}
		if err := persistMigrationContent(runtime.dir, "migration-currents", floorLeaf.V1SignedCurrentHash, ".json", current); err != nil {
			return err
		}
	}
	return validateControlMigrationSource(input)
}

func originalMigrationDeviceIdentity(id, platform string, client clientregistry.Client, certificatePEM string, roots *x509.CertPool) (string, error) {
	if client.ID != "" && (client.Status == "revoked" || client.Platform != "" && client.Platform != platform) {
		return "", errors.New("原 registry 已撤权或平台不一致")
	}
	var public []byte
	if client.PublicKey != "" {
		var err error
		public, err = base64.RawStdEncoding.Strict().DecodeString(client.PublicKey)
		if err != nil {
			return "", err
		}
	}
	if platform == "linux-server" {
		certificate, err := parseSingleCertificatePEM([]byte(certificatePEM))
		if err != nil || certificate.IsCA || len(certificate.DNSNames) != 1 || certificate.DNSNames[0] != id+".node.internal" ||
			certificate.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
			return "", errors.New("原服务器证书未绑定指定设备")
		}
		if _, err := certificate.Verify(x509.VerifyOptions{Roots: roots, DNSName: id + ".node.internal", CurrentTime: certificate.NotBefore.Add(time.Second),
			KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth}}); err != nil {
			return "", errors.New("原服务器证书不属于提供的原 CA")
		}
		if len(public) != 0 && !bytes.Equal(public, certificate.RawSubjectPublicKeyInfo) {
			return "", errors.New("原 registry 与原服务器证书的身份 key 不同")
		}
		public = certificate.RawSubjectPublicKeyInfo
	} else if certificatePEM != "" {
		return "", errors.New("移动/桌面设备须由原 registry 证明身份")
	}
	if len(public) == 0 {
		return "", errors.New("缺原 registry 身份或原服务器证书")
	}
	return wire.HashBytes(wire.DomainEnrollmentIdentitySPKI, public)
}

// 迁移只投影原能力和凭据授权。临时 drain 不撤销授权；不能把全网资源
// 自动授予一个只有少量凭据的客户端。control 仍由原 ControlSet 单独认证。
func migrationDeviceAuthorization(ssot *model.SSOT, node *model.Node) (string, wire.EnrollmentResponsibilitiesV1, wire.EnrollmentDestinationGrantsV1, error) {
	roles := wire.EnrollmentResponsibilitiesV1{Schema: 1, Values: []string{}}
	grants := wire.EnrollmentDestinationGrantsV1{Schema: 1, Values: []wire.EnrollmentDestinationGrantV1{}}
	platform := "linux-server"
	if node.Access != nil {
		roles.Values = append(roles.Values, "use_loom")
		platform = string(node.Access.Platform)
	}
	if node.Server != nil {
		roles.Values = append(roles.Values, "forward")
		if node.Server.EgressCapable {
			roles.Values = append(roles.Values, "internet_egress")
		}
	}
	if err := wire.ValidateEnrollmentResponsibilities(&roles); err != nil {
		return platform, roles, grants, err
	}
	granted := map[string]wire.EnrollmentDestinationGrantV1{}
	credentials, declarations, nodes := ssot.CredentialByID(), ssot.DeclarationByID(), ssot.NodeByID()
	if node.Access != nil {
		for _, credentialID := range node.Access.Credentials {
			credential := credentials[credentialID]
			if credential == nil || declarations[credential.Declaration] == nil {
				return platform, roles, grants, errors.New("原设备凭据未指向有效授权声明")
			}
			declaration := declarations[credential.Declaration]
			for _, service := range ssot.ServicesFor(declaration.ID) {
				granted["service:"+service.ID] = wire.EnrollmentDestinationGrantV1{Kind: "service", TargetID: service.ID}
			}
			if !declaration.AddressFromRequest() {
				continue
			}
			for _, allowed := range declaration.AllowedServers {
				server := nodes[allowed]
				if server == nil || server.Server == nil || !server.Server.EgressCapable || server.Decommission || declaration.PinnedEgress() != "" && declaration.PinnedEgress() != allowed {
					continue
				}
				granted["egress:"+allowed] = wire.EnrollmentDestinationGrantV1{Kind: "egress", TargetID: allowed}
			}
		}
	}
	keys := make([]string, 0, len(granted))
	for key := range granted {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		grants.Values = append(grants.Values, granted[key])
	}
	return platform, roles, grants, wire.ValidateEnrollmentDestinationGrants(&grants)
}

func persistMigrationContent(dir, subdir, hash, suffix string, body []byte) error {
	if _, err := wire.ParseHash(hash); err != nil {
		return err
	}
	root := filepath.Join(dir, subdir)
	if err := os.MkdirAll(root, 0o700); err != nil {
		return err
	}
	path := filepath.Join(root, strings.TrimPrefix(hash, "sha256:")+suffix)
	if original, err := readOwnerOnlyFile(path, 4<<20); err == nil {
		if !bytes.Equal(original, body) {
			return errors.New("同一迁移材料 hash 已保存不同字节")
		}
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return writeBytesAtomic(path, body, 0o600)
}

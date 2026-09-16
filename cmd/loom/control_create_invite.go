package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"loom/internal/model"
	"loom/internal/publish"
	"loom/internal/wire"
)

const privateControlInviteContextPath = "/private/v2/control/invite-context"

type controlInviteGrantOptionV1 struct {
	Grant wire.EnrollmentDestinationGrantV1 `json:"grant"`
	Name  string                            `json:"name"`
}

type controlInviteContextV1 struct {
	Schema   int                                    `json:"schema"`
	Status   controlStatusResponseV1                `json:"status"`
	Policy   wire.InviteIssuancePolicyV2            `json:"policy"`
	Profiles []wire.DeviceCertificateProfileStateV1 `json:"profiles"`
	Issuers  []wire.BootstrapIssuerAuthorizationV1  `json:"issuers"`
	Catalog  wire.BootstrapEndpointCatalogV1        `json:"catalog"`
	Service  wire.PrivateEnrollmentServiceRefV1     `json:"service"`
	Mirrors  []wire.DistributionMirrorRefV1         `json:"mirrors"`
	Grants   []controlInviteGrantOptionV1           `json:"grants"`
}

type controlCreateInviteInputV1 struct {
	Name             string   `json:"name"`
	Platform         string   `json:"platform"`
	Responsibilities []string `json:"responsibilities"`
	Grants           []string `json:"grants"`
	TTLSeconds       int64    `json:"ttl_seconds"`
}

// 管理员本地先保存 exact 已签请求，再发送。重复执行同一命令只重放这一请求，
// 不会因超时再生成另一个 Device、token 或 operation ID。
type controlInviteRequestFileV1 struct {
	Schema  int                        `json:"schema"`
	Input   controlCreateInviteInputV1 `json:"input"`
	Base    controlStatusResponseV1    `json:"base"`
	Request controlOperationRequestV1  `json:"request"`
}

type controlInviteDistributionOptionsV1 struct {
	Targets   []string
	SSHConfig string
}

type controlInviteStaticPublicationV1 struct {
	Schema      int      `json:"schema"`
	CatalogHash string   `json:"catalog_hash"`
	ProofHash   string   `json:"proof_hash"`
	Paths       []string `json:"paths"`
	MirrorCount int64    `json:"mirror_count"`
}

func cmdControlCreateInvite(args []string) error {
	fs := flag.NewFlagSet("control create-invite", flag.ContinueOnError)
	adminDir := fs.String("admin-dir", "", "管理员证书与 endpoint 目录")
	out := fs.String("out", "", "受保护的请求与邀请交付目录；重试使用相同目录")
	name := fs.String("name", "", "设备显示名称")
	platform := fs.String("platform", "linux-server", "linux-server、android 或 windows-desktop")
	responsibilities := fs.String("responsibilities", "use_loom", "逗号分隔的职责")
	grants := fs.String("grants", "", "逗号分隔的 service:<ID> 或 egress:<ID>")
	ttl := fs.Duration("ttl", 15*time.Minute, "邀请有效期")
	list := fs.Bool("list-grants", false, "列出当前可授权目标")
	sshConfig := fs.String("ssh-config", ".ssh_config", "SSH 分发目标使用的配置")
	var distributionTargets repeatedFlag
	fs.Var(&distributionTargets, "distribution-target", "静态镜像根目录或 ssh://<alias>/<绝对目录>；按 descriptor 镜像逐个提供")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 || *adminDir == "" || !*list && (*out == "" || strings.TrimSpace(*name) == "" || len(distributionTargets) < 2 || len(distributionTargets) > 3) {
		return errors.New("用法: loom control create-invite -admin-dir <dir> -name <name> -out <dir> -distribution-target <root|ssh://alias/root>（重复 2–3 次） [-platform linux-server|android|windows-desktop] [-grants service:<ID>,egress:<ID>]；可先加 -list-grants")
	}
	endpoint, client, err := loadControlAdminClient(*adminDir)
	if err != nil {
		return err
	}
	defer client.CloseIdleConnections()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	if *list {
		var options controlInviteContextV1
		if err := fetchControlInviteJSON(ctx, endpoint, client, privateControlInviteContextPath, &options); err != nil {
			return err
		}
		if err := validateControlInviteContext(endpoint, options); err != nil {
			return err
		}
		for _, option := range options.Grants {
			fmt.Printf("%s:%s\t%s\n", option.Grant.Kind, option.Grant.TargetID, option.Name)
		}
		return nil
	}
	input := controlCreateInviteInputV1{Name: strings.TrimSpace(*name), Platform: *platform,
		Responsibilities: controlResponsibilityValues(*responsibilities), Grants: controlCommaValues(*grants), TTLSeconds: int64(*ttl / time.Second)}
	if *ttl <= 0 || *ttl%time.Second != 0 {
		return errors.New("邀请有效期必须是正整秒")
	}
	if err := createControlInvite(ctx, *adminDir, endpoint, client, input, *out, time.Now,
		controlInviteDistributionOptionsV1{Targets: distributionTargets, SSHConfig: *sshConfig}); err != nil {
		return err
	}
	fmt.Printf("✓ 邀请已由控制日志认证；交付文件：%s\n", filepath.Join(*out, "invite.loom-invite"))
	return nil
}

func controlCommaValues(raw string) []string {
	values := []string{}
	for _, value := range strings.Split(raw, ",") {
		if value = strings.TrimSpace(value); value != "" {
			values = append(values, value)
		}
	}
	sort.Strings(values)
	return values
}

func controlResponsibilityValues(raw string) []string {
	values := controlCommaValues(raw)
	order := map[string]int{"use_loom": 1, "forward": 2, "internet_egress": 3}
	sort.SliceStable(values, func(i, j int) bool { return order[values[i]] < order[values[j]] })
	return values
}

func createControlInvite(ctx context.Context, adminDir string, endpoint controlAdminEndpointV1, client *http.Client,
	input controlCreateInviteInputV1, output string, now func() time.Time,
	distribution ...controlInviteDistributionOptionsV1) error {
	if now == nil {
		return errors.New("创建邀请缺可信时钟")
	}
	if len(distribution) > 1 {
		return errors.New("创建邀请的静态分发配置重复")
	}
	if len(distribution) == 1 {
		if len(distribution[0].Targets) < 2 || len(distribution[0].Targets) > 3 {
			return errors.New("创建邀请必须配置 2–3 个静态分发目标")
		}
		seen := make(map[string]bool, len(distribution[0].Targets))
		for _, spec := range distribution[0].Targets {
			if seen[spec] {
				return errors.New("创建邀请的静态分发目标重复")
			}
			seen[spec] = true
			if _, err := publish.ParseTarget(spec, distribution[0].SSHConfig); err != nil {
				return err
			}
		}
	}
	if err := os.MkdirAll(output, 0o700); err != nil {
		return err
	}
	info, err := os.Lstat(output)
	if err != nil || !info.IsDir() || info.Mode().Perm() != 0o700 || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("邀请交付目录必须是 0700 实体目录")
	}
	unlock, err := lockControlState(output)
	if err != nil {
		return fmt.Errorf("邀请交付目录正在使用或不能加锁: %w", err)
	}
	defer unlock()
	requestPath := filepath.Join(output, "request.json")
	var retained controlInviteRequestFileV1
	encoded, err := readOwnerOnlyFile(requestPath, 8<<20)
	if errors.Is(err, os.ErrNotExist) {
		var options controlInviteContextV1
		if err := fetchControlInviteJSON(ctx, endpoint, client, privateControlInviteContextPath, &options); err != nil {
			return err
		}
		if len(distribution) == 1 && len(distribution[0].Targets) != len(options.Mirrors) {
			return errors.New("静态分发目标数量必须逐一覆盖当前 certified mirrors")
		}
		request, err := buildControlInviteRequest(adminDir, endpoint, options, input, now().UTC().Truncate(time.Second))
		if err != nil {
			return err
		}
		retained = controlInviteRequestFileV1{Schema: 1, Input: input, Base: options.Status, Request: request}
		if err := writeCanonicalAtomic(requestPath, retained, 0o600); err != nil {
			return err
		}
	} else if err != nil {
		return err
	} else {
		canonical, err := wire.DecodeStrict(encoded, 8<<20, &retained)
		if err != nil || !bytes.Equal(canonical, encoded) || retained.Schema != 1 || !wire.EqualCanonical(retained.Input, input) ||
			retained.Base.ClusterID != endpoint.ClusterID || !wire.EqualCanonical(retained.Base.Service, endpoint.Service) {
			return errors.New("交付目录已绑定不同输入或网络，不能覆盖原请求")
		}
	}
	result, err := submitControlOperation(ctx, adminDir, endpoint, client, retained.Base, retained.Request)
	if err != nil {
		return err
	}
	if err := writeCanonicalAtomic(filepath.Join(output, "result.json"), result, 0o600); err != nil {
		return err
	}
	var payload controlCreateInvitePayloadV1
	if _, err := wire.DecodeStrict(retained.Request.Payload, 2<<20, &payload); err != nil {
		return err
	}
	var delivery controlInviteDeliveryV1
	if err := fetchControlInviteJSON(ctx, endpoint, client, privateControlInvitePrefix+payload.Invite.Record.InviteID+"/delivery", &delivery); err != nil {
		return fmt.Errorf("邀请事务已提交，交付读取失败；原结果保存在 result.json: %w", err)
	}
	if delivery.Schema != 1 || delivery.Descriptor.Token != payload.Token.Token ||
		!wire.EqualCanonical(delivery.Proof.CertifiedInviteRecord, payload.Invite.Record) || delivery.Proof.RecordHead.HeadHash != result.Head.HeadHash {
		return errors.New("邀请交付没有绑定本机原请求和认证结果")
	}
	if _, err := wire.VerifyInviteProofBundle(&delivery.Proof, &delivery.Descriptor, now().UTC(), wire.InviteProofTrustV2{}); err != nil {
		return err
	}
	for name, value := range map[string]any{"invite.loom-invite": delivery.Descriptor, "proof.json": delivery.Proof, "catalog.json": delivery.Catalog} {
		if err := writeCanonicalAtomic(filepath.Join(output, name), value, 0o600); err != nil {
			return err
		}
	}
	if len(distribution) == 1 {
		if err := publishControlInviteStatic(output, delivery, distribution[0]); err != nil {
			return fmt.Errorf("邀请事务已认证但静态镜像尚未完整发布；使用相同输出目录重试: %w", err)
		}
	}
	return nil
}

func publishControlInviteStatic(output string, delivery controlInviteDeliveryV1,
	options controlInviteDistributionOptionsV1) error {
	if len(options.Targets) != len(delivery.Descriptor.DistributionMirrors) || len(options.Targets) < 2 || len(options.Targets) > 3 {
		return errors.New("静态分发目标数量必须逐一覆盖 descriptor 的 2–3 个镜像")
	}
	proofBody, err := wire.MarshalCanonical(delivery.Proof)
	if err != nil {
		return err
	}
	catalogBody, err := wire.MarshalCanonical(delivery.Catalog)
	if err != nil {
		return err
	}
	proofHash, err := wire.InviteProofBundleHash(&delivery.Proof)
	if err != nil || proofHash != delivery.Descriptor.ProofBundleHash {
		return errors.New("静态 proof 与 descriptor hash 不一致")
	}
	catalogHash, err := wire.BootstrapEndpointCatalogHash(&delivery.Catalog)
	if err != nil || catalogHash != delivery.Descriptor.BootstrapCatalogHash {
		return errors.New("静态 catalog 与 descriptor hash 不一致")
	}
	pathFor := func(hash string) (string, error) {
		digest, err := wire.ParseHash(hash)
		if err != nil {
			return "", err
		}
		return filepath.ToSlash(filepath.Join("distribution", "sha256", hex.EncodeToString(digest))), nil
	}
	proofPath, err := pathFor(proofHash)
	if err != nil {
		return err
	}
	catalogPath, err := pathFor(catalogHash)
	if err != nil {
		return err
	}
	targets := make([]publish.Target, 0, len(options.Targets))
	for _, spec := range options.Targets {
		target, err := publish.ParseTarget(spec, options.SSHConfig)
		if err != nil {
			return err
		}
		targets = append(targets, target)
	}
	mirrors, err := publish.NewMirrorSet(targets...)
	if err != nil {
		return err
	}
	objects := map[string][]byte{proofPath: proofBody, catalogPath: catalogBody}
	if err := publish.PushImmutable(mirrors, objects); err != nil {
		return err
	}
	for path, expected := range objects {
		got, found, err := mirrors.ReadFile(path)
		if err != nil || !found || !bytes.Equal(got, expected) {
			return fmt.Errorf("静态镜像未回读 exact object %s", path)
		}
	}
	paths := []string{"/" + catalogPath, "/" + proofPath}
	sort.Strings(paths)
	receipt := controlInviteStaticPublicationV1{Schema: 1, CatalogHash: catalogHash,
		ProofHash: proofHash, Paths: paths, MirrorCount: int64(len(targets))}
	return writeCanonicalAtomic(filepath.Join(output, "static-publication.json"), receipt, 0o600)
}

func fetchControlInviteJSON(ctx context.Context, endpoint controlAdminEndpointV1, client *http.Client, path string, target any) error {
	address := net.JoinHostPort(endpoint.Service.OverlayIP, fmt.Sprint(endpoint.Service.Port))
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+address+path, nil)
	if err != nil {
		return err
	}
	response, err := client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, (8<<20)+1))
	if err != nil || len(body) > 8<<20 || response.StatusCode != http.StatusOK {
		return fmt.Errorf("私有邀请读取 HTTP %d", response.StatusCode)
	}
	canonical, err := wire.DecodeStrict(body, 8<<20, target)
	if err != nil || !bytes.Equal(canonical, body) {
		return errors.New("私有邀请返回了非规范数据")
	}
	return nil
}

func buildControlInviteRequest(adminDir string, endpoint controlAdminEndpointV1, options controlInviteContextV1,
	input controlCreateInviteInputV1, now time.Time) (controlOperationRequestV1, error) {
	if err := validateControlInviteContext(endpoint, options); err != nil {
		return controlOperationRequestV1{}, err
	}
	if input.Platform != "linux-server" && input.Platform != "android" && input.Platform != "windows-desktop" || strings.TrimSpace(input.Name) == "" ||
		!utf8.ValidString(input.Name) || utf8.RuneCountInString(input.Name) > 80 ||
		input.Platform != "linux-server" && !wire.EqualCanonical(input.Responsibilities, []string{"use_loom"}) ||
		input.TTLSeconds < options.Policy.MinimumTTLSeconds || input.TTLSeconds > options.Policy.MaximumTTLSeconds {
		return controlOperationRequestV1{}, errors.New("设备平台、职责、名称或邀请有效期无效")
	}
	if err := wire.ValidateEnrollmentResponsibilities(&wire.EnrollmentResponsibilitiesV1{Schema: 1, Values: input.Responsibilities}); err != nil {
		return controlOperationRequestV1{}, err
	}
	grants := []wire.EnrollmentDestinationGrantV1{}
	for _, raw := range input.Grants {
		matched := false
		for _, option := range options.Grants {
			if raw == option.Grant.Kind+":"+option.Grant.TargetID {
				grants = append(grants, option.Grant)
				matched = true
				break
			}
		}
		if !matched {
			return controlOperationRequestV1{}, errors.New("目标不在当前授权选项中；先使用 -list-grants")
		}
	}
	if containsControlValue(input.Responsibilities, "use_loom") && len(grants) == 0 {
		return controlOperationRequestV1{}, errors.New("use_loom 必须显式选择目标授权")
	}
	var selected *wire.DeviceCertificateProfileStateV1
	for _, profile := range options.Profiles {
		if profile.Status != "active" || !containsControlValue(profile.ProfileIntent.AllowedPlatforms, input.Platform) {
			continue
		}
		matches := true
		for _, role := range input.Responsibilities {
			matches = matches && containsControlValue(profile.ProfileIntent.AllowedResponsibilities, role)
		}
		if matches {
			if selected != nil {
				return controlOperationRequestV1{}, errors.New("有多个可用 Device profile，需先明确当前签发策略")
			}
			copy := profile
			selected = &copy
		}
	}
	if selected == nil {
		return controlOperationRequestV1{}, errors.New("当前网络没有与平台和职责匹配的 Device profile")
	}
	profileHash, err := wire.DeviceCertificateProfileStateHash(selected)
	if err != nil {
		return controlOperationRequestV1{}, err
	}
	seeds := make([]byte, 112)
	if _, err := rand.Read(seeds); err != nil {
		return controlOperationRequestV1{}, err
	}
	cluster := options.Status.ClusterID
	inviteID, deviceID, requestID := "i-"+hex.EncodeToString(seeds[:16]), "d-"+hex.EncodeToString(seeds[16:32]), "op-"+hex.EncodeToString(seeds[32:48])
	wrappingProfiles := []string{"p256-root-only-pkcs8-ecdh-v1"}
	if input.Platform == "android" {
		wrappingProfiles = []string{"p256-keystore-ecdh-v1", "rsa2048-keystore-decrypt-v1"}
	} else if input.Platform == "windows-desktop" {
		wrappingProfiles = []string{"p256-keystore-ecdh-v1"}
	}
	intent := wire.DeviceEnrollmentIntentV1{Schema: 1, ClusterID: cluster, InviteID: inviteID, DeviceID: deviceID,
		Platform: input.Platform, DeviceCertificateProfileRef: wire.DeviceCertificateProfileRefV1{ProfileID: selected.ProfileID,
			Generation: selected.Generation, DeviceCertificateProfileIntentHash: selected.DeviceCertificateProfileIntentHash, DeviceCertificateProfileStateHash: profileHash},
		WrappingKeyProfiles: wrappingProfiles, Membership: wire.EnrollmentMembershipV1{Schema: 1, DesiredState: "active_on_completion"},
		Responsibilities: wire.EnrollmentResponsibilitiesV1{Schema: 1, Values: input.Responsibilities},
		Grants:           wire.EnrollmentDestinationGrantsV1{Schema: 1, Values: grants}}
	intentHash, err := wire.EnrollmentIntentHash(&intent)
	if err != nil {
		return controlOperationRequestV1{}, err
	}
	opening := wire.DeviceEnrollmentIntentOpeningV1{Schema: 1, ClusterID: cluster, InviteID: inviteID,
		DeviceEnrollmentIntent: intent, DeviceEnrollmentIntentHash: intentHash, HidingNonce: base64.RawURLEncoding.EncodeToString(seeds[48:80])}
	commitment, commitmentHash, err := wire.IntentCommitment(&opening)
	if err != nil {
		return controlOperationRequestV1{}, err
	}
	token := wire.InviteTokenCommitmentInputV2{Schema: 2, ClusterID: cluster, InviteID: inviteID, Token: base64.RawURLEncoding.EncodeToString(seeds[80:])}
	tokenHash, _ := wire.TokenCommitment(cluster, inviteID, token.Token)
	tokenArtifact, _ := wire.HashObject(controlInviteTokenDomain, token)
	policyHash, _ := wire.InviteIssuancePolicyHash(&options.Policy)
	catalogHash, err := wire.BootstrapEndpointCatalogHash(&options.Catalog)
	if err != nil {
		return controlOperationRequestV1{}, err
	}
	serviceHash, err := wire.PrivateEnrollmentServiceRefHash(&options.Service)
	if err != nil {
		return controlOperationRequestV1{}, err
	}
	issuerHash := ""
	for _, issuer := range options.Issuers {
		active := issuer.Active
		if issuer.Status != "active" || active == nil || active.InviteIssuancePolicyHash != policyHash ||
			!containsControlValue(active.PermittedIngressSetHashes, options.Catalog.BootstrapIngressSetHash) ||
			!containsControlValue(active.PermittedServiceIDs, options.Service.ServiceID) || !containsControlValue(active.PermittedModes, "initial_claim") {
			continue
		}
		from, _ := wire.ParseTimeZ(active.ValidFrom)
		until, _ := wire.ParseTimeZ(active.ValidUntil)
		if now.Before(from) || now.Add(time.Duration(input.TTLSeconds)*time.Second).After(until) {
			continue
		}
		issuerHash, err = wire.BootstrapIssuerAuthorizationHash(&issuer)
		if err != nil {
			return controlOperationRequestV1{}, err
		}
		break
	}
	if issuerHash == "" {
		return controlOperationRequestV1{}, errors.New("当前网络没有覆盖邀请有效期的 bootstrap issuer")
	}
	operationID, _ := controlInviteRecordOperationID(cluster, requestID)
	record := wire.CertifiedInviteRecordV2{Schema: 2, ClusterID: cluster, InviteID: inviteID, Generation: 1,
		IssuedAt: now.Format(time.RFC3339), ExpiresAt: now.Add(time.Duration(input.TTLSeconds) * time.Second).Format(time.RFC3339),
		DeviceEnrollmentIntentCommitmentHash: commitmentHash, TokenCommitment: tokenHash, TokenArtifactBindingHash: tokenArtifact,
		InviteIssuancePolicyHash: policyHash, BootstrapIssuerAuthorizationHash: issuerHash,
		BootstrapIssuerRegistryRoot: options.Status.Head.Body.Payload.BootstrapIssuerRegistryRoot,
		BootstrapCatalogHash:        catalogHash, EnrollmentServiceRefHash: serviceHash, OperationID: operationID, ParentHeadHash: options.Status.Head.HeadHash}
	payload := controlCreateInvitePayloadV1{Schema: 1, Invite: controlInviteStateV1{Status: "available", DisplayName: input.Name, Record: record, Commitment: commitment, Opening: opening}, Token: token}
	raw, err := wire.MarshalCanonical(payload)
	if err != nil {
		return controlOperationRequestV1{}, err
	}
	return newControlInviteRequest(adminDir, endpoint, options.Status, requestID, raw, "create device invitation")
}

func validateControlInviteContext(endpoint controlAdminEndpointV1, options controlInviteContextV1) error {
	if options.Schema != 1 || options.Status.Schema != 1 || options.Status.ClusterID != endpoint.ClusterID ||
		options.Status.Head.Body.Payload.ClusterID != endpoint.ClusterID || options.Policy.ClusterID != endpoint.ClusterID ||
		!wire.EqualCanonical(options.Status.Service, endpoint.Service) ||
		wire.VerifyConfigQCAuthority(options.Status.Head.HeadHash, options.Status.ConfigQC, &options.Status.Head, &options.Status.ControlSet, nil) != nil {
		return errors.New("创建邀请的上下文缺当前网络 authority")
	}
	if _, err := wire.InviteIssuancePolicyHash(&options.Policy); err != nil {
		return err
	}
	if _, err := wire.PrivateEnrollmentServiceRefHash(&options.Service); err != nil {
		return err
	}
	if _, err := wire.BootstrapEndpointCatalogHash(&options.Catalog); err != nil {
		return err
	}
	if err := wire.ValidateDistributionMirrorRefs(options.Mirrors); err != nil {
		return err
	}
	if int64(len(options.Mirrors)) < options.Policy.MinimumDistributionMirrors ||
		int64(len(options.Mirrors)) > options.Policy.MaximumDistributionMirrors {
		return errors.New("创建邀请的镜像数量不满足当前 policy")
	}
	return nil
}

func (runtime *controlRuntime) serveInviteContext(writer http.ResponseWriter, request *http.Request) {
	address := net.JoinHostPort(runtime.config.OverlayIP, fmt.Sprint(runtime.config.ControlPort))
	local, ok := request.Context().Value(http.LocalAddrContextKey).(net.Addr)
	if request.Method != http.MethodGet || request.URL.Path != privateControlInviteContextPath || request.URL.RawPath != "" || request.URL.RawQuery != "" ||
		!ok || local == nil || local.String() != address || request.Host != address || request.TLS == nil || request.TLS.Version != tls.VersionTLS13 ||
		len(request.TLS.PeerCertificates) < 1 || request.Header.Get("Authorization") != "" || request.Header.Get("Cookie") != "" || request.ContentLength > 0 {
		writeControlRuntimeError(writer, http.StatusForbidden, "[D115 Invite] 私有管理员传输被拒绝")
		return
	}
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	if !runtime.inviteAdminAuthorizedLocked(request.TLS.PeerCertificates[0].Raw) {
		writeControlRuntimeError(writer, http.StatusForbidden, "[D115 Invite] 当前管理员无邀请权限")
		return
	}
	application, err := runtime.certifiedApplicationLocked()
	if err != nil {
		writeControlRuntimeError(writer, http.StatusServiceUnavailable, "[D115 Invite] 当前邀请状态不可读")
		return
	}
	if application.BootstrapInstallation != nil {
		writeControlRuntimeError(writer, http.StatusServiceUnavailable, "Bootstrap 入口尚未完成认证发布")
		return
	}
	state, raft := runtime.store.Snapshot(), runtime.storage.SnapshotRaft()
	qc, _ := wire.MarshalCanonical(state.CertifiedQC)
	quorum, _ := wire.Quorum(len(state.ControlSet.Members))
	options := controlInviteContextV1{Schema: 1, Status: controlStatusResponseV1{Schema: 1, ClusterID: runtime.config.ClusterID,
		MemberID: runtime.config.MemberID, Quorum: quorum, Head: *state.CertifiedHead, ConfigQC: qc, ControlSet: state.ControlSet,
		Raft: controlRaftStatusV1{Term: raft.CurrentTerm, CommitIndex: raft.CommitIndex, LastApplied: raft.LastApplied}, Service: runtime.config.ControlService},
		Policy: application.InvitePolicy, Profiles: application.CARegistry.DeviceProfiles, Issuers: application.BootstrapIssuers,
		Catalog: application.BootstrapCatalog, Service: application.EnrollmentService,
		Mirrors: append([]wire.DistributionMirrorRefV1(nil), application.Mirrors...), Grants: []controlInviteGrantOptionV1{}}
	ssot, err := model.Load([]byte(application.LegacySSOT))
	if err != nil {
		writeControlRuntimeError(writer, http.StatusServiceUnavailable, "[D115 Invite] 当前目标授权不可读")
		return
	}
	for _, service := range ssot.Services {
		options.Grants = append(options.Grants, controlInviteGrantOptionV1{Grant: wire.EnrollmentDestinationGrantV1{Kind: "service", TargetID: service.ID}, Name: service.ID})
	}
	for _, node := range ssot.Nodes {
		if node.Server != nil && node.Server.EgressCapable && !node.Decommission {
			options.Grants = append(options.Grants, controlInviteGrantOptionV1{Grant: wire.EnrollmentDestinationGrantV1{Kind: "egress", TargetID: node.ID}, Name: node.Name})
		}
	}
	sort.Slice(options.Grants, func(i, j int) bool {
		a, b := options.Grants[i].Grant, options.Grants[j].Grant
		return a.Kind+":"+a.TargetID < b.Kind+":"+b.TargetID
	})
	body, err := wire.MarshalCanonical(options)
	if err != nil {
		writeControlRuntimeError(writer, http.StatusInternalServerError, "[D115 Invite] 上下文编码失败")
		return
	}
	writer.Header().Set("Content-Type", "application/json")
	writer.Header().Set("Cache-Control", "no-store")
	writer.Header().Set("Referrer-Policy", "no-referrer")
	writer.Header().Set("X-Content-Type-Options", "nosniff")
	_, _ = writer.Write(body)
}

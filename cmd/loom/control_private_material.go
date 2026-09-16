package main

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"time"

	"loom/internal/enrollmentv2"
	"loom/internal/wire"
)

type controlPrivateServiceMaterialV1 struct {
	Service    wire.PrivateControlServiceV1 `json:"service"`
	ChainDER   []string                     `json:"chain_der"`
	KeyRefHash string                       `json:"key_ref_hash"`
}

type controlPrivateMaterialsV1 struct {
	Schema     int                               `json:"schema"`
	ClusterID  string                            `json:"cluster_id"`
	DeviceID   string                            `json:"device_id"`
	ProposalID string                            `json:"proposal_id"`
	PreparedAt string                            `json:"prepared_at"`
	Services   []controlPrivateServiceMaterialV1 `json:"services"`
}

// 首次准备沿用原 internal CA 和 overlay，分别生成三个 role 的 TLS key。
// 本地记录只保存公开链和封装引用；正式启动必须匹配 certified application。
func (runtime *controlRuntime) preparePrivateServiceMaterials(proposalID, deviceProfile string, ports map[string]int64,
	now time.Time) (controlPrivateMaterialsV1, error) {
	var prepared controlPrivateMaterialsV1
	if proposalID == "" || deviceProfile == "" || len(ports) != 3 || now.IsZero() || now != now.UTC().Truncate(time.Second) {
		return prepared, errors.New("[私有服务] 缺固定 proposal、证书 profile、端口或时间")
	}
	used := map[int64]bool{runtime.config.ControlPort: true, runtime.config.RaftPort: true}
	for _, role := range []string{"device_config", "device_report", "enroll"} {
		port := ports[role]
		if port < 1 || port > 65535 || used[port] {
			return prepared, errors.New("[私有服务] 端口未分离或超出范围")
		}
		used[port] = true
	}
	material, err := openControlSoftwareMaterial(runtime.dir, runtime.config.DeviceID, true)
	if err != nil {
		return prepared, err
	}
	defer material.Close()
	unlock, err := lockControlState(filepath.Join(runtime.dir, "software-material"))
	if err != nil {
		return prepared, err
	}
	defer unlock()
	path := filepath.Join(runtime.dir, "private-services.json")
	if err := readCanonicalFile(path, 4<<20, &prepared); err == nil {
		if prepared.Schema != 1 || prepared.ClusterID != runtime.config.ClusterID || prepared.DeviceID != runtime.config.DeviceID ||
			prepared.ProposalID != proposalID || len(prepared.Services) != 3 {
			return prepared, errors.New("[私有服务] 已有材料绑定不同准备请求")
		}
		for _, entry := range prepared.Services {
			if ports[entry.Service.Role] != entry.Service.Port || entry.Service.OverlayIP != runtime.config.OverlayIP ||
				!wire.EqualCanonical(entry.Service.AuthorizedSubjectProfiles, []string{deviceProfile}) {
				return prepared, errors.New("[私有服务] 重试改变了原 tuple 或客户端 profile")
			}
			certificate, err := runtime.privateServiceCertificate(material, entry, prepared.PreparedAt, now)
			if err != nil {
				return prepared, err
			}
			clearControlSigner(certificate.PrivateKey.(crypto.Signer))
		}
		return prepared, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return prepared, err
	}
	var secrets controlDiskSecretsV1
	if err := readCanonicalFile(filepath.Join(runtime.dir, controlSecretsName), 8<<20, &secrets); err != nil {
		return prepared, err
	}
	issuerKey, err := parsePrivateKeyPKCS8PEM([]byte(secrets.InternalCAPrivateKeyPKCS8PEM))
	if err != nil {
		return prepared, err
	}
	defer clear(issuerKey)
	if len(runtime.controlTLS.Certificate) != 2 {
		return prepared, errors.New("[私有服务] 原 control identity 缺完整 internal CA 链")
	}
	issuer, err := x509.ParseCertificate(runtime.controlTLS.Certificate[1])
	if err != nil || !issuer.IsCA || !now.Before(issuer.NotAfter) || now.Before(issuer.NotBefore) {
		return prepared, errors.New("[私有服务] 原 internal CA 无效或已过期")
	}
	policy, err := material.availabilityPolicy(runtime.config.ClusterID)
	if err != nil {
		return prepared, err
	}
	recipient, err := material.recipient()
	if err != nil {
		return prepared, err
	}
	sealing := wire.P256RootOnlySealingPolicyV1()
	recipients := []wire.SealedBlobRecipientKeyRefV1{recipient}
	prepared = controlPrivateMaterialsV1{Schema: 1, ClusterID: runtime.config.ClusterID, DeviceID: runtime.config.DeviceID,
		ProposalID: proposalID, PreparedAt: now.Format(time.RFC3339), Services: []controlPrivateServiceMaterialV1{}}
	for _, role := range []string{"device_config", "device_report", "enroll"} {
		public, key, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return prepared, err
		}
		defer clear(key)
		serial, err := randomCertificateSerial()
		if err != nil {
			return prepared, err
		}
		until := now.Add(365 * 24 * time.Hour)
		if issuer.NotAfter.Before(until) {
			until = issuer.NotAfter
		}
		template := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: role + "." + runtime.config.ClusterID},
			NotBefore: now, NotAfter: until, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature,
			ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, IPAddresses: []net.IP{net.ParseIP(runtime.config.OverlayIP)}}
		der, err := x509.CreateCertificate(rand.Reader, template, issuer, public, issuerKey)
		if err != nil {
			return prepared, err
		}
		certificate, err := x509.ParseCertificate(der)
		if err != nil {
			return prepared, err
		}
		secret, err := x509.MarshalPKCS8PrivateKey(key)
		if err != nil {
			return prepared, err
		}
		defer clear(secret)
		service := wire.PrivateControlServiceV1{ServiceID: "private-" + role, Role: role, OverlayIP: runtime.config.OverlayIP, Port: ports[role],
			CertificateProfileRef: "private-" + role + "-tls", SPKIPins: []string{fmt.Sprintf("sha256:%x", sha256.Sum256(certificate.RawSubjectPublicKeyInfo))},
			AuthorizedSubjectProfiles: []string{deviceProfile}}
		if err := wire.ValidatePrivateControlService(&service); err != nil {
			return prepared, err
		}
		context, err := wire.NewSealedSecretContext(runtime.config.ClusterID, proposalID, service.ServiceID+"-key", "tls_private_key",
			wire.SecretArtifactOwnerV1{Kind: "device", Device: &wire.SecretArtifactDeviceOwnerV1{DeviceID: material.deviceID}}, 1, &sealing, recipients)
		if err != nil {
			return prepared, err
		}
		evidence, err := enrollmentv2.CreateLocalSealedMaterial(material.store, context, sealing, recipients, secret, key,
			policy, material.deviceID, material.reporter, now, rand.Reader)
		if err != nil {
			return prepared, err
		}
		hash, err := material.saveEvidence(evidence)
		if err != nil {
			return prepared, err
		}
		prepared.Services = append(prepared.Services, controlPrivateServiceMaterialV1{Service: service, KeyRefHash: hash,
			ChainDER: []string{base64.RawURLEncoding.EncodeToString(der), base64.RawURLEncoding.EncodeToString(issuer.Raw)}})
	}
	return prepared, writeCanonicalAtomic(path, prepared, 0o600)
}

func (runtime *controlRuntime) privateServiceCertificate(material *controlSoftwareMaterial, entry controlPrivateServiceMaterialV1,
	preparedAt string, now time.Time) (tls.Certificate, error) {
	var result tls.Certificate
	if len(entry.ChainDER) != 2 || len(runtime.controlTLS.Certificate) != 2 || entry.Service.OverlayIP != runtime.config.OverlayIP {
		return result, errors.New("[私有服务] 本机证书链或 overlay 不匹配")
	}
	for _, encoded := range entry.ChainDER {
		der, err := base64.RawURLEncoding.DecodeString(encoded)
		if err != nil {
			return result, err
		}
		result.Certificate = append(result.Certificate, der)
	}
	if string(result.Certificate[1]) != string(runtime.controlTLS.Certificate[1]) {
		return result, errors.New("[私有服务] 证书不是由原 internal CA 签发")
	}
	leaf, err := x509.ParseCertificate(result.Certificate[0])
	if err != nil {
		return result, err
	}
	root, err := x509.ParseCertificate(result.Certificate[1])
	if err != nil {
		return result, err
	}
	pool := x509.NewCertPool()
	pool.AddCert(root)
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: pool, CurrentTime: now, DNSName: entry.Service.OverlayIP, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); err != nil {
		return result, err
	}
	pin := fmt.Sprintf("sha256:%x", sha256.Sum256(leaf.RawSubjectPublicKeyInfo))
	if !containsControlValue(entry.Service.SPKIPins, pin) || len(leaf.ExtKeyUsage) != 1 || leaf.ExtKeyUsage[0] != x509.ExtKeyUsageServerAuth {
		return result, errors.New("[私有服务] 证书 SPKI 或专用 EKU 不匹配")
	}
	at, err := wire.ParseTimeZ(preparedAt)
	if err != nil {
		return result, err
	}
	signer, err := material.LoadSigner(entry.KeyRefHash, "tls_private_key", at)
	if err != nil {
		return result, err
	}
	public, err := x509.MarshalPKIXPublicKey(signer.Public())
	if err != nil || string(public) != string(leaf.RawSubjectPublicKeyInfo) {
		clearControlSigner(signer)
		return result, errors.New("[私有服务] 解封私钥与 certificate 不匹配")
	}
	result.PrivateKey, result.Leaf = signer, leaf
	return result, nil
}

func (runtime *controlRuntime) loadPrivateServiceCertificates(application *controlApplicationV1) (map[string]tls.Certificate, error) {
	var prepared controlPrivateMaterialsV1
	if err := readCanonicalFile(filepath.Join(runtime.dir, "private-services.json"), 4<<20, &prepared); err != nil {
		return nil, err
	}
	if prepared.Schema != 1 || prepared.ClusterID != runtime.config.ClusterID || prepared.DeviceID != runtime.config.DeviceID || len(prepared.Services) != 3 {
		return nil, errors.New("[私有服务] 本机材料身份不匹配")
	}
	material, err := openControlSoftwareMaterial(runtime.dir, runtime.config.DeviceID, false)
	if err != nil {
		return nil, err
	}
	defer material.Close()
	certificates := make(map[string]tls.Certificate)
	loaded := false
	defer func() {
		if !loaded {
			clearPrivateRuntimeCertificates(certificates)
		}
	}()
	for _, entry := range prepared.Services {
		matched := false
		for _, service := range application.Services {
			matched = matched || wire.EqualCanonical(service, entry.Service)
		}
		if !matched {
			return nil, errors.New("[私有服务] 本机 listener 不属于当前 certified directory")
		}
		certificate, err := runtime.privateServiceCertificate(material, entry, prepared.PreparedAt, runtime.now().UTC())
		if err != nil {
			return nil, err
		}
		certificates[entry.Service.ServiceID] = certificate
	}
	loaded = true
	return certificates, nil
}

func (runtime *controlRuntime) devicePrivateControlCredentialLocked(application *controlApplicationV1, deviceID string) (wire.DevicePrivateControlCredentialV1, error) {
	var result wire.DevicePrivateControlCredentialV1
	state := runtime.store.Snapshot()
	if application == nil || state.CertifiedHead == nil || state.CertifiedQC == nil || state.Active != nil || len(runtime.controlTLS.Certificate) != 2 {
		return result, errors.New("[设备凭据] 缺实际认证 Head 或 internal CA")
	}
	qc, err := wire.MarshalCanonical(state.CertifiedQC)
	if err != nil {
		return result, err
	}
	services := append([]wire.PrivateControlServiceV1(nil), application.Services...)
	sort.Slice(services, func(i, j int) bool { return services[i].ServiceID < services[j].ServiceID })
	directory := wire.ControlServiceDirectoryV1{Schema: 1, ClusterID: runtime.config.ClusterID, Generation: 1,
		Services: services, ControlSetHash: state.CertifiedHead.Body.Payload.ControlSetHash, ParentHeadHash: state.CertifiedHead.HeadHash, ConfigQC: qc}
	hash, err := wire.ControlServiceDirectoryHash(&directory)
	if err != nil {
		return result, err
	}
	result = wire.DevicePrivateControlCredentialV1{Schema: 1, ClusterID: application.ClusterID, DeviceID: deviceID,
		ParentHead: *state.CertifiedHead, ControlSet: state.ControlSet, ControlServiceDirectory: directory, ControlServiceDirectoryHash: hash,
		InternalCARootsDER: []string{base64.RawURLEncoding.EncodeToString(runtime.controlTLS.Certificate[1])}}
	return result, wire.ValidateDevicePrivateControlCredential(&result)
}

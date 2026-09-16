package certmanager

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"loom/internal/wire"
)

const (
	domainExistingCertificate = "loom-existing-public-certificate-binding-v1"
	domainExistingKey         = "loom-existing-public-tls-key-pkcs8-v1"
)

// 导入只准备节点本地材料，不调用 DNS/ACME，也不修改 listener。公开绑定须
// 另经控制事务认证；成功读到证书不等于外部入口已经可达。
type ExistingCertificateRequestV1 struct {
	Schema                int      `json:"schema"`
	RequestID             string   `json:"request_id"`
	ClusterID             string   `json:"cluster_id"`
	DeviceID              string   `json:"device_id"`
	IdentityID            string   `json:"identity_id"`
	IdentityGeneration    int64    `json:"identity_generation"`
	CertificateGeneration int64    `json:"certificate_generation"`
	EndpointIDs           []string `json:"endpoint_ids"`
	DNSNames              []string `json:"dns_names"`
	IssuerProfileRef      string   `json:"issuer_profile_ref"`
	CertificatePath       string   `json:"certificate_path"`
	PrivateKeyPath        string   `json:"private_key_path"`
}

type ExistingCertificateBindingV1 struct {
	Schema                 int                                  `json:"schema"`
	Identity               wire.CertificateIdentityProjectionV1 `json:"identity"`
	IdentityProjectionHash string                               `json:"identity_projection_hash"`
	CertificateGeneration  int64                                `json:"certificate_generation"`
	CertificateChainHash   string                               `json:"certificate_chain_hash"`
	CertificateChainPEM    string                               `json:"certificate_chain_pem"`
	LeafCertificateHash    string                               `json:"leaf_certificate_hash"`
	NotBefore              string                               `json:"not_before"`
	NotAfter               string                               `json:"not_after"`
}

type existingCertificatePreparationV1 struct {
	Schema      int                          `json:"schema"`
	RequestHash string                       `json:"request_hash"`
	Binding     ExistingCertificateBindingV1 `json:"binding"`
}

func ExistingCertificateBindingHash(binding *ExistingCertificateBindingV1) (string, error) {
	if binding == nil || binding.Schema != 1 || binding.CertificateGeneration < 1 {
		return "", errors.New("[现有 TLS] 绑定格式或证书代无效")
	}
	hash, err := wire.CertificateIdentityProjectionHash(&binding.Identity)
	if err != nil || hash != binding.IdentityProjectionHash ||
		wire.HashRaw(domainPublicCertificateChain, []byte(binding.CertificateChainPEM)) != binding.CertificateChainHash {
		return "", errors.New("[现有 TLS] 身份或完整链摘要不匹配")
	}
	if _, err := wire.ParseHash(binding.LeafCertificateHash); err != nil {
		return "", err
	}
	from, err := wire.ParseTimeZ(binding.NotBefore)
	until, endErr := wire.ParseTimeZ(binding.NotAfter)
	if err != nil || endErr != nil || !from.Before(until) {
		return "", errors.New("[现有 TLS] 证书有效期无效")
	}
	return wire.HashObject(domainExistingCertificate, binding)
}

// 控制端只能验证公开绑定，不持有节点私钥。实际 listener 启动仍须在原节点
// 调用 LoadExistingRuntimeCertificate 验证本地 key artifact 与匹配私钥。
func VerifyExistingPublicCertificate(binding ExistingCertificateBindingV1, roots *x509.CertPool, now time.Time) error {
	if now.IsZero() {
		return errors.New("[现有 TLS] 缺可信时间")
	}
	if _, err := ExistingCertificateBindingHash(&binding); err != nil {
		return err
	}
	canonical, leaf, err := verifyExistingCertificateChain([]byte(binding.CertificateChainPEM), binding.Identity, roots, now)
	if err != nil {
		return err
	}
	if string(canonical) != binding.CertificateChainPEM || binding.LeafCertificateHash != wire.HashRaw(domainPublicCertificateLeaf, leaf.Raw) ||
		binding.NotBefore != leaf.NotBefore.UTC().Format(time.RFC3339) || binding.NotAfter != leaf.NotAfter.UTC().Format(time.RFC3339) {
		return errors.New("[现有 TLS] 公开 leaf、完整链或有效期与绑定不同")
	}
	return nil
}

// roots=nil 使用本机系统 WebPKI roots；测试必须显式提供合成根。指定名字是
// 此入口的授权子集，可由现有 wildcard/SAN 证书覆盖，不把其余 SAN 自动授权。
func PrepareExistingCertificate(directory string, request ExistingCertificateRequestV1, roots *x509.CertPool,
	now time.Time) (ExistingCertificateBindingV1, error) {
	var empty ExistingCertificateBindingV1
	if request.Schema != 1 || request.RequestID == "" || len(request.RequestID) > 128 || request.CertificateGeneration < 1 ||
		!filepath.IsAbs(request.CertificatePath) || !filepath.IsAbs(request.PrivateKeyPath) || now.IsZero() {
		return empty, errors.New("[现有 TLS] 缺固定请求、证书代、本地路径或可信时间")
	}
	if err := existingCertificateDirectory(directory, true); err != nil {
		return empty, err
	}
	requestHash, err := wire.HashObject("loom-existing-public-certificate-request-v1", request)
	if err != nil {
		return empty, err
	}
	slot := sha256.Sum256([]byte(request.RequestID))
	receiptPath := filepath.Join(directory, "request-"+hex.EncodeToString(slot[:])+".json")
	if body, err := readRegularFile(receiptPath, 2<<20, true); err == nil {
		var saved existingCertificatePreparationV1
		canonical, err := wire.DecodeStrict(body, 2<<20, &saved)
		if err != nil || !bytes.Equal(canonical, body) || saved.Schema != 1 || saved.RequestHash != requestHash {
			return empty, errors.New("[现有 TLS] 请求已经绑定不同导入输入")
		}
		if _, err := LoadExistingRuntimeCertificate(directory, saved.Binding, saved.Binding.Identity, roots, now); err != nil {
			return empty, err
		}
		return saved.Binding, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return empty, err
	}
	// 支持现有证书管理器的 live -> archive 链接；实际读取仍对规范化后的
	// regular file 检查权限与 inode，不在打开期间跟随一个变化的目标。
	certificatePath, err := filepath.EvalSymlinks(request.CertificatePath)
	if err != nil {
		return empty, err
	}
	keyPath, err := filepath.EvalSymlinks(request.PrivateKeyPath)
	if err != nil {
		return empty, err
	}
	chainPEM, err := readRegularFile(certificatePath, 1<<20, false)
	if err != nil {
		return empty, err
	}
	keyPEM, err := readRegularFile(keyPath, 64<<10, true)
	if err != nil {
		return empty, err
	}
	defer clear(keyPEM)
	pair, err := tls.X509KeyPair(chainPEM, keyPEM)
	if err != nil {
		return empty, errors.New("[现有 TLS] 完整链与本地私钥不匹配")
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(pair.PrivateKey)
	if err != nil {
		return empty, err
	}
	defer clear(keyDER)
	keyHash := wire.HashRaw(domainExistingKey, keyDER)
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return empty, err
	}
	spki := sha256.Sum256(leaf.RawSubjectPublicKeyInfo)
	identity := wire.CertificateIdentityProjectionV1{Schema: 1, ClusterID: request.ClusterID, IntentID: request.IdentityID,
		IdentityGeneration: request.IdentityGeneration, EndpointIDs: request.EndpointIDs, DNSNames: request.DNSNames,
		IssuerProfileRef: request.IssuerProfileRef, KeyOwnerDeviceID: request.DeviceID, KeyArtifactHash: keyHash, SPKIHash: fmt.Sprintf("sha256:%x", spki)}
	identityHash, err := wire.CertificateIdentityProjectionHash(&identity)
	if err != nil {
		return empty, err
	}
	canonical, leaf, err := verifyExistingCertificateChain(chainPEM, identity, roots, now)
	if err != nil {
		return empty, err
	}
	binding := ExistingCertificateBindingV1{Schema: 1, Identity: identity, IdentityProjectionHash: identityHash,
		CertificateGeneration: request.CertificateGeneration, CertificateChainPEM: string(canonical),
		CertificateChainHash: wire.HashRaw(domainPublicCertificateChain, canonical), LeafCertificateHash: wire.HashRaw(domainPublicCertificateLeaf, leaf.Raw),
		NotBefore: leaf.NotBefore.UTC().Format(time.RFC3339), NotAfter: leaf.NotAfter.UTC().Format(time.RFC3339)}
	if _, err := ExistingCertificateBindingHash(&binding); err != nil {
		return empty, err
	}
	encodedKey := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	defer clear(encodedKey)
	if err := saveExistingCertificateImmutable(existingCertificateArtifactPath(directory, keyHash, "key"), encodedKey); err != nil {
		return empty, err
	}
	if err := saveExistingCertificateImmutable(existingCertificateArtifactPath(directory, binding.CertificateChainHash, "chain"), canonical); err != nil {
		return empty, err
	}
	// 首次回执最后写入；崩溃遗留的不被引用材料不会成为 active 证书。
	receipt, err := wire.MarshalCanonical(existingCertificatePreparationV1{Schema: 1, RequestHash: requestHash, Binding: binding})
	if err != nil {
		return empty, err
	}
	if err := saveExistingCertificateImmutable(receiptPath, receipt); err != nil {
		return empty, err
	}
	return binding, nil
}

// identity 必须来自调用方已经认证的 listener 计划；不能只信磁盘中的 receipt。
func LoadExistingRuntimeCertificate(directory string, binding ExistingCertificateBindingV1,
	identity wire.CertificateIdentityProjectionV1, roots *x509.CertPool, now time.Time) (RuntimeCertificate, error) {
	var empty RuntimeCertificate
	if now.IsZero() || !wire.EqualCanonical(identity, binding.Identity) {
		return empty, errors.New("[现有 TLS] 缺可信时间或身份与认证计划不一致")
	}
	if err := existingCertificateDirectory(directory, false); err != nil {
		return empty, err
	}
	hash, err := ExistingCertificateBindingHash(&binding)
	if err != nil {
		return empty, err
	}
	chain, err := readRegularFile(existingCertificateArtifactPath(directory, binding.CertificateChainHash, "chain"), 1<<20, true)
	if err != nil || string(chain) != binding.CertificateChainPEM {
		return empty, errors.New("[现有 TLS] 本地完整链缺失或摘要不匹配")
	}
	_, leaf, err := verifyExistingCertificateChain(chain, identity, roots, now)
	if err != nil {
		return empty, err
	}
	if binding.LeafCertificateHash != wire.HashRaw(domainPublicCertificateLeaf, leaf.Raw) || binding.NotBefore != leaf.NotBefore.UTC().Format(time.RFC3339) || binding.NotAfter != leaf.NotAfter.UTC().Format(time.RFC3339) {
		return empty, errors.New("[现有 TLS] leaf 或有效期与绑定不同")
	}
	keyPEM, err := readRegularFile(existingCertificateArtifactPath(directory, identity.KeyArtifactHash, "key"), 64<<10, true)
	if err != nil {
		return empty, err
	}
	defer clear(keyPEM)
	pair, err := tls.X509KeyPair(chain, keyPEM)
	if err != nil {
		return empty, errors.New("[现有 TLS] 持久私钥与完整链不匹配")
	}
	der, err := x509.MarshalPKCS8PrivateKey(pair.PrivateKey)
	if err != nil {
		return empty, err
	}
	keyHash := wire.HashRaw(domainExistingKey, der)
	clear(der)
	if keyHash != identity.KeyArtifactHash {
		return empty, errors.New("[现有 TLS] 持久私钥不属于认证 artifact")
	}
	pair.Leaf = leaf
	return RuntimeCertificate{TLSCertificate: pair, IdentityProjectionHash: binding.IdentityProjectionHash,
		ExistingCertificateBindingHash: hash, SPKIPins: []string{identity.SPKIHash}}, nil
}

// ExistingRuntimeCertificatePaths 只在完整验证本地不可变副本后返回 Nginx
// 可直接消费的绝对路径。调用方不能由 hash 自行拼接路径而绕过证书、私钥与
// 认证 identity 的一致性检查。
func ExistingRuntimeCertificatePaths(directory string, binding ExistingCertificateBindingV1,
	identity wire.CertificateIdentityProjectionV1, roots *x509.CertPool, now time.Time) (string, string, error) {
	if _, err := LoadExistingRuntimeCertificate(directory, binding, identity, roots, now); err != nil {
		return "", "", err
	}
	return existingCertificateArtifactPath(directory, binding.CertificateChainHash, "chain"),
		existingCertificateArtifactPath(directory, identity.KeyArtifactHash, "key"), nil
}

func verifyExistingCertificateChain(body []byte, identity wire.CertificateIdentityProjectionV1, roots *x509.CertPool,
	now time.Time) ([]byte, *x509.Certificate, error) {
	if _, err := wire.CertificateIdentityProjectionHash(&identity); err != nil {
		return nil, nil, err
	}
	certificates, err := decodeCertificatePEM(body)
	if err != nil || len(certificates) > 16 {
		return nil, nil, errors.New("[现有 TLS] 完整链格式或数量无效")
	}
	parsed := make([]*x509.Certificate, len(certificates))
	seen := map[string]bool{}
	intermediates := x509.NewCertPool()
	var canonical bytes.Buffer
	for i, der := range certificates {
		certificate, err := x509.ParseCertificate(der)
		if err != nil || !bytes.Equal(certificate.Raw, der) || seen[string(der)] {
			return nil, nil, errors.New("[现有 TLS] 链中 DER 无效或重复")
		}
		parsed[i] = certificate
		seen[string(der)] = true
		if i > 0 {
			if parsed[i-1].CheckSignatureFrom(certificate) != nil {
				return nil, nil, errors.New("[现有 TLS] 链未按 leaf/issuer 顺序连接")
			}
			intermediates.AddCert(certificate)
		}
		if err := pem.Encode(&canonical, &pem.Block{Type: "CERTIFICATE", Bytes: der}); err != nil {
			return nil, nil, err
		}
	}
	leaf := parsed[0]
	spki := sha256.Sum256(leaf.RawSubjectPublicKeyInfo)
	if leaf.IsCA || leaf.KeyUsage&x509.KeyUsageDigitalSignature == 0 || identity.SPKIHash != fmt.Sprintf("sha256:%x", spki) {
		return nil, nil, errors.New("[现有 TLS] leaf 用途或认证 SPKI 无效")
	}
	for _, name := range identity.DNSNames {
		if _, err := leaf.Verify(x509.VerifyOptions{DNSName: name, Roots: roots, Intermediates: intermediates, CurrentTime: now,
			KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); err != nil {
			return nil, nil, errors.New("[现有 TLS] 名字、完整链、有效期或服务器用途验证失败")
		}
	}
	return canonical.Bytes(), leaf, nil
}

func existingCertificateDirectory(directory string, create bool) error {
	if !filepath.IsAbs(directory) || filepath.Clean(directory) != directory {
		return errors.New("[现有 TLS] 材料目录必须是规范绝对路径")
	}
	if create {
		if err := os.MkdirAll(directory, 0700); err != nil {
			return err
		}
	}
	info, err := os.Lstat(directory)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0700 {
		return errors.New("[现有 TLS] 材料目录必须是 0700 实体目录")
	}
	return nil
}

func existingCertificateArtifactPath(directory, hash, kind string) string {
	return filepath.Join(directory, kind+"-"+strings.TrimPrefix(hash, "sha256:")+".pem")
}

func saveExistingCertificateImmutable(path string, body []byte) error {
	if original, err := readRegularFile(path, 2<<20, true); err == nil {
		if !bytes.Equal(original, body) {
			return errors.New("[现有 TLS] 不覆盖已有不同材料")
		}
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	temporary, err := os.CreateTemp(filepath.Dir(path), ".existing-tls-*")
	if err != nil {
		return err
	}
	defer os.Remove(temporary.Name())
	if err = temporary.Chmod(0600); err == nil {
		_, err = temporary.Write(body)
	}
	if err == nil {
		err = temporary.Sync()
	}
	closeErr := temporary.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	// link 是 no-replace 的原子就位，避免并发准备覆盖先到的合法回执。
	if err = os.Link(temporary.Name(), path); errors.Is(err, os.ErrExist) {
		return saveExistingCertificateImmutable(path, body)
	} else if err != nil {
		return err
	}
	directory, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}

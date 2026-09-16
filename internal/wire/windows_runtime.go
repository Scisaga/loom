package wire

import (
	"bytes"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"slices"
	"strings"
	"unicode/utf8"

	"loom/internal/secret"
)

const (
	WindowsRuntimeArtifactID     = "windows-runtime"
	WindowsRuntimeRenderContract = "windows-runtime-v1"
	maximumWindowsRuntimeFile    = 8 << 20
)

type WindowsRuntimeFileV1 struct {
	Path    string `json:"path"`
	Content string `json:"content"`
}

// WindowsRuntimeArtifactV1 是 Device view 认证的公开双文件 renderer 输出。
// credential_refs 只能以 `${secret:...}` 出现在文件中，明文由 Windows 在
// DPAPI LKG 内最后一刻 hydrate。
type WindowsRuntimeArtifactV1 struct {
	Schema           int                    `json:"schema"`
	ClusterID        string                 `json:"cluster_id"`
	DeviceID         string                 `json:"device_id"`
	DeviceGeneration int64                  `json:"device_generation"`
	Generation       int64                  `json:"generation"`
	SingBoxVersion   string                 `json:"sing_box_version"`
	CABundlePEM      string                 `json:"ca_bundle_pem"`
	CredentialRefs   []string               `json:"credential_refs"`
	Files            []WindowsRuntimeFileV1 `json:"files"`
}

func ValidateWindowsRuntimeArtifact(artifact *WindowsRuntimeArtifactV1) error {
	if artifact == nil || artifact.Schema != 1 || artifact.DeviceGeneration < 1 ||
		artifact.Generation < 1 || !validIdentifier(artifact.ClusterID, 128) ||
		!validIdentifier(artifact.DeviceID, 128) || !validIdentifier(artifact.SingBoxVersion, 128) ||
		artifact.CredentialRefs == nil || len(artifact.CredentialRefs) > 256 || len(artifact.Files) != 2 ||
		artifact.Files[0].Path != "agent/config.json" || artifact.Files[1].Path != "sing-box/config.json" {
		return errors.New("[Windows runtime] artifact header/files 无效")
	}
	if err := ValidateRuntimeCABundle(artifact.CABundlePEM); err != nil {
		return err
	}
	for index, ref := range artifact.CredentialRefs {
		if !validIdentifier(ref, 256) || index > 0 && artifact.CredentialRefs[index-1] >= ref {
			return errors.New("[Windows runtime] credential refs 必须规范排序且唯一")
		}
	}
	referenced := make(map[string]bool)
	total := 0
	for _, file := range artifact.Files {
		if file.Content == "" || len(file.Content) > maximumWindowsRuntimeFile ||
			!utf8.ValidString(file.Content) || strings.IndexByte(file.Content, 0) >= 0 {
			return errors.New("[Windows runtime] runtime file 内容无效")
		}
		total += len(file.Content)
		if total > 12<<20 {
			return errors.New("[Windows runtime] runtime files 超过总预算")
		}
		canonical, err := NormalizeRuntimeJSON([]byte(file.Content))
		var object map[string]any
		if err != nil || !bytes.Equal(canonical, []byte(file.Content)) ||
			json.Unmarshal([]byte(file.Content), &object) != nil || object == nil {
			return errors.New("[Windows runtime] runtime file 必须是 exact canonical JSON object")
		}
		if err := validateLinuxRuntimeJSONSecrets(object); err != nil {
			return errors.New("[Windows runtime] public runtime 含非引用形式的敏感字段")
		}
		for _, ref := range secret.Refs(file.Content) {
			referenced[ref] = true
		}
	}
	actual := make([]string, 0, len(referenced))
	for ref := range referenced {
		actual = append(actual, ref)
	}
	slices.Sort(actual)
	if !slices.Equal(actual, artifact.CredentialRefs) {
		return errors.New("[Windows runtime] credential_refs 未 exact 覆盖 runtime placeholders")
	}
	return nil
}

// ValidateRuntimeCABundle 校验已认证运行配置中的公共 CA；不接收私钥或叶证书。
func ValidateRuntimeCABundle(value string) error {
	if value == "" || len(value) > 1<<20 || !utf8.ValidString(value) || strings.IndexByte(value, 0) >= 0 {
		return errors.New("[Windows runtime] CA bundle 大小或编码无效")
	}
	rest := []byte(value)
	canonical := make([]byte, 0, len(rest))
	seen := make(map[string]bool)
	count := 0
	for len(rest) > 0 {
		block, next := pem.Decode(rest)
		if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
			return errors.New("[Windows runtime] CA bundle 必须只含规范 CERTIFICATE PEM")
		}
		certificate, err := x509.ParseCertificate(block.Bytes)
		if err != nil || !bytes.Equal(certificate.Raw, block.Bytes) || !certificate.IsCA ||
			!certificate.BasicConstraintsValid || seen[string(certificate.Raw)] {
			return errors.New("[Windows runtime] CA bundle 含无效或重复 CA certificate")
		}
		seen[string(certificate.Raw)] = true
		canonical = append(canonical, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: block.Bytes})...)
		count++
		if count > 16 {
			return errors.New("[Windows runtime] CA bundle 超过 certificate 数量边界")
		}
		rest = next
	}
	if count == 0 || !bytes.Equal(canonical, []byte(value)) {
		return errors.New("[Windows runtime] CA bundle 不是 exact canonical PEM")
	}
	return nil
}

package clientv2

import (
	"crypto"
	"crypto/x509"
	"errors"
	"loom/internal/devicehttp"
	"loom/internal/wire"
	"time"
)

const MaximumPrivateDeviceViewBytes = devicehttp.MaximumPrivateDeviceViewBytes

// VerifyPrivateControlDirectory 要求 directory 的 exact hash pin、parent Head、
// ControlSet 与 config QC 同时成立；directory bytes 不能靠公网 URL 自行授权。
func VerifyPrivateControlDirectory(directory *wire.ControlServiceDirectoryV1,
	pinnedDirectoryHash string, head *wire.HeadEntryV2, set, previousSet *wire.ControlSetV1) error {
	if directory == nil || head == nil || set == nil {
		return errors.New("[client] private directory authority 不完整")
	}
	if err := wire.ValidateControlServiceDirectory(directory); err != nil {
		return err
	}
	directoryHash, err := wire.ControlServiceDirectoryHash(directory)
	if err != nil || directoryHash != pinnedDirectoryHash {
		return errors.New("[client] private directory 与 protected hash pin 不一致")
	}
	setHash, err := wire.ControlSetHash(set)
	if err != nil || directory.ClusterID != head.Body.Payload.ClusterID ||
		directory.ClusterID != set.ClusterID || directory.ParentHeadHash != head.HeadHash ||
		directory.ControlSetHash != setHash || head.Body.Payload.ControlSetHash != setHash {
		return errors.New("[client] private directory 未绑定 certified Head/ControlSet")
	}
	return wire.VerifyConfigQCAuthority(directory.ParentHeadHash, directory.ConfigQC,
		head, set, previousSet)
}

// SelectPrivateControlServices 返回 certified 顺序中的获权副本。指定 serviceID
// 时必须恰好命中一个；未指定时宿主可按顺序故障切换但不得扫描额外地址。
func SelectPrivateControlServices(directory *wire.ControlServiceDirectoryV1, role,
	serviceID, certificateProfileID string) ([]wire.PrivateControlServiceV1, error) {
	if directory == nil || (role != "device_config" && role != "device_report") ||
		certificateProfileID == "" {
		return nil, errors.New("[client] private service selection 输入无效")
	}
	if err := wire.ValidateControlServiceDirectory(directory); err != nil {
		return nil, err
	}
	selected := make([]wire.PrivateControlServiceV1, 0)
	for index := range directory.Services {
		candidate := &directory.Services[index]
		if candidate.Role != role || serviceID != "" && candidate.ServiceID != serviceID ||
			!containsString(candidate.AuthorizedSubjectProfiles, certificateProfileID) {
			continue
		}
		copy := *candidate
		copy.SPKIPins = append([]string(nil), candidate.SPKIPins...)
		copy.AuthorizedSubjectProfiles = append([]string(nil), candidate.AuthorizedSubjectProfiles...)
		selected = append(selected, copy)
	}
	if len(selected) == 0 || serviceID != "" && len(selected) != 1 {
		return nil, errors.New("[client] certified private directory 缺唯一获权目标 service")
	}
	return selected, nil
}

type PrivateDeviceHTTPClient = devicehttp.PrivateDeviceHTTPClient

func NewPrivateDeviceHTTPClient(service wire.PrivateControlServiceV1, expectedRole,
	certificateProfileID string, certificateChainDER [][]byte, identitySigner crypto.Signer,
	roots *x509.CertPool, dial TunnelDialContext, now func() time.Time,
	timeout time.Duration) (*PrivateDeviceHTTPClient, error) {
	return devicehttp.NewPrivateDeviceHTTPClient(service, expectedRole, certificateProfileID,
		certificateChainDER, identitySigner, roots, devicehttp.DialContext(dial), now, timeout)
}

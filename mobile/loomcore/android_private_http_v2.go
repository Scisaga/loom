package loomcore

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"time"

	"loom/internal/devicehttp"
	"loom/internal/wire"
)

// AndroidIdentitySigner 仅将 TLS 待签名消息交给原 Keystore；不导出私钥，
// 也不要求旧身份新增 NONE 摘要权限。Go TLS 使用 MessageSigner 避免重复哈希。
type AndroidIdentitySigner interface {
	SignP256(message []byte) ([]byte, error)
}

type androidMessageSigner struct {
	public   *ecdsa.PublicKey
	callback AndroidIdentitySigner
}

func (s androidMessageSigner) Public() crypto.PublicKey { return s.public }
func (s androidMessageSigner) Sign(io.Reader, []byte, crypto.SignerOpts) ([]byte, error) {
	return nil, errors.New("[Android TLS] 原 Keystore 身份仅接受完整 SHA-256 消息")
}
func (s androidMessageSigner) SignMessage(_ io.Reader, message []byte, opts crypto.SignerOpts) ([]byte, error) {
	if s.callback == nil || opts == nil || opts.HashFunc() != crypto.SHA256 || len(message) == 0 {
		return nil, errors.New("[Android TLS] 身份签名算法或消息无效")
	}
	signature, err := s.callback.SignP256(append([]byte(nil), message...))
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256(message)
	if !ecdsa.VerifyASN1(s.public, digest[:], signature) {
		return nil, errors.New("[Android TLS] Keystore 签名不属于当前身份或完整消息")
	}
	return signature, nil
}

// FetchAndroidV2DeviceConfig 使用与其他平台相同的 TLS 1.3、CA、SPKI 和
// exact overlay tuple 校验。socket 不 protect，继续经过当前 VPN 的私有 WG。
func FetchAndroidV2DeviceConfig(stateJSON, identitySPKIDER []byte, signer AndroidIdentitySigner,
	trustedTime string) ([]byte, error) {
	return androidPrivateRequest(stateJSON, identitySPKIDER, signer, "device_config", trustedTime,
		func(ctx context.Context, client *devicehttp.PrivateDeviceHTTPClient) ([]byte, error) {
			delivery, err := client.FetchDeviceConfigDelivery(ctx)
			if err != nil {
				return nil, err
			}
			return wire.MarshalCanonical(delivery)
		})
}

func PostAndroidV2DeviceReport(stateJSON, identitySPKIDER, reportJSON []byte, signer AndroidIdentitySigner,
	trustedTime string) ([]byte, error) {
	if err := ValidateAndroidV2DeviceReport(stateJSON, identitySPKIDER, reportJSON, trustedTime); err != nil {
		return nil, err
	}
	var envelope wire.DeviceReportEnvelopeV2
	if err := decodeExactAndroidV2(reportJSON, maximumAndroidDeviceReportBytes, &envelope, "Device report"); err != nil {
		return nil, err
	}
	return androidPrivateRequest(stateJSON, identitySPKIDER, signer, "device_report", trustedTime,
		func(ctx context.Context, client *devicehttp.PrivateDeviceHTTPClient) ([]byte, error) {
			status, observations, err := client.PostDeviceReportWithResponse(ctx, &envelope)
			if err != nil {
				return nil, err
			}
			return wire.MarshalCanonical(struct {
				StatusCode   int               `json:"status_code"`
				Observations []json.RawMessage `json:"observations"`
			}{status, observations})
		})
}

func androidPrivateRequest(stateJSON, identitySPKIDER []byte, callback AndroidIdentitySigner,
	role, trustedTime string, request func(context.Context, *devicehttp.PrivateDeviceHTTPClient) ([]byte, error)) ([]byte, error) {
	plans, err := prepareAndroidV2PrivateControlPlans(stateJSON, identitySPKIDER, role, "", trustedTime)
	if err != nil {
		return nil, err
	}
	state, err := decodeAndroidV2DeviceState(stateJSON)
	if err != nil {
		return nil, err
	}
	public, err := x509.ParsePKIXPublicKey(identitySPKIDER)
	key, ok := public.(*ecdsa.PublicKey)
	if err != nil || !ok || key.Curve != elliptic.P256() || callback == nil {
		return nil, errors.New("[Android TLS] 缺当前 P-256 Keystore 身份")
	}
	instant, err := wire.ParseTimeZ(trustedTime)
	if err != nil {
		return nil, err
	}
	// 每次请求持续检查时间，不能把握手或副本故障切换冻结在调用开始时。
	started := time.Now()
	now := func() time.Time { return instant.Add(time.Since(started)) }
	profile := state.material().DeviceProfile.ProfileID
	var failures []error
	for _, plan := range plans {
		roots := x509.NewCertPool()
		var chain [][]byte
		for _, value := range plan.InternalCARootsDER {
			der, err := base64.RawURLEncoding.Strict().DecodeString(value)
			if err != nil {
				return nil, err
			}
			root, err := x509.ParseCertificate(der)
			if err != nil {
				return nil, err
			}
			roots.AddCert(root)
		}
		for _, value := range plan.ClientCertificateChainDER {
			der, err := base64.RawURLEncoding.Strict().DecodeString(value)
			if err != nil {
				return nil, err
			}
			chain = append(chain, der)
		}
		service := wire.PrivateControlServiceV1{ServiceID: plan.ServiceID, Role: plan.Role,
			OverlayIP: plan.OverlayIP, Port: plan.Port, CertificateProfileRef: plan.CertificateProfileRef,
			SPKIPins: plan.ServerSPKIPins, AuthorizedSubjectProfiles: []string{profile}}
		client, err := devicehttp.NewPrivateDeviceHTTPClient(service, role, profile, chain,
			androidMessageSigner{key, callback}, roots, nil, now, 30*time.Second)
		if err != nil {
			return nil, err
		}
		body, err := request(context.Background(), client)
		client.CloseIdleConnections()
		if err == nil {
			return body, nil
		}
		failures = append(failures, err)
	}
	return nil, errors.Join(failures...)
}

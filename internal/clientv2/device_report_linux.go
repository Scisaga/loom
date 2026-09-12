//go:build linux

package clientv2

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"loom/internal/wire"
)

const maximumPrivateDeviceReportResponseBytes = 4096

type LinuxDeviceReportOptions struct {
	StatePath           string
	IdentityPath        string
	Directory           wire.ControlServiceDirectoryV1
	PinnedDirectoryHash string
	ControlSet          wire.ControlSetV1
	PreviousControlSet  *wire.ControlSetV1
	ServiceID           string
	Roots               *x509.CertPool
	Dial                TunnelDialContext
	Now                 func() time.Time
	Timeout             time.Duration
	ReportID            string
	ReportSequence      int64
	Kind                string
	PayloadSchema       int64
	Payload             json.RawMessage
	Schemas             wire.DeviceReportSchemaRegistry
	RetryEnvelope       *wire.DeviceReportEnvelopeV2
}

// SendLinuxDeviceReport 只用 durable LKG floors 和 Enrollment identity 签名，
// 并经 pinned private directory 中的 device_report overlay service 发送。
// report sequence 的原子 CAS 由服务端强制；重试时调用方必须复用返回的 exact envelope（D131）。
func SendLinuxDeviceReport(ctx context.Context,
	options LinuxDeviceReportOptions) (wire.DeviceReportEnvelopeV2, error) {
	if ctx == nil {
		return wire.DeviceReportEnvelopeV2{}, errors.New("[D131 Linux report] context 缺失")
	}
	store, err := Open(options.StatePath)
	if err != nil {
		return wire.DeviceReportEnvelopeV2{}, err
	}
	current := store.Envelope()
	installation := store.Enrollment()
	if current == nil || installation == nil || current.Payload.Active == nil {
		return wire.DeviceReportEnvelopeV2{}, errors.New("[D131 Linux report] 正式 active enrollment/LKG 尚未安装")
	}
	if err := VerifyControlServiceDirectory(&options.Directory, options.PinnedDirectoryHash,
		&current.SignedCurrent.Head, &options.ControlSet, options.PreviousControlSet); err != nil {
		return wire.DeviceReportEnvelopeV2{}, err
	}
	service, err := SelectPrivateControlService(&options.Directory, "device_report", options.ServiceID)
	if err != nil {
		return wire.DeviceReportEnvelopeV2{}, err
	}
	identity, err := LoadEnrollmentIdentityForResume(options.IdentityPath)
	if err != nil {
		return wire.DeviceReportEnvelopeV2{}, err
	}
	identityKey, _, err := identity.keys()
	if err != nil {
		return wire.DeviceReportEnvelopeV2{}, err
	}
	identityHash, err := identity.IdentitySPKIHash()
	if err != nil || identityHash != installation.IdentityKeyHash ||
		identityHash != current.Payload.Active.IdentitySPKIHash {
		return wire.DeviceReportEnvelopeV2{}, errors.New("[D131 Linux report] 本机 identity 与 durable installation/view 不一致")
	}
	certificateDER, err := wire.EnrollmentResultCertificateDER(&installation.ResultArtifact)
	if err != nil {
		return wire.DeviceReportEnvelopeV2{}, err
	}
	certificateHash, err := wire.DeviceCertificateHash(certificateDER)
	if err != nil || certificateHash != installation.DeviceCertificateHash {
		return wire.DeviceReportEnvelopeV2{}, errors.New("[D131 Linux report] Device certificate 与 durable installation 不一致")
	}
	now := options.Now
	if now == nil {
		now = time.Now
	}
	generatedAt := now().UTC().Truncate(time.Second)
	if generatedAt.IsZero() {
		return wire.DeviceReportEnvelopeV2{}, errors.New("[D131 Linux report] trusted time 无效")
	}
	var envelope wire.DeviceReportEnvelopeV2
	if options.RetryEnvelope == nil {
		payloadHash, err := wire.DeviceReportPayloadHash(options.Payload)
		if err != nil {
			return wire.DeviceReportEnvelopeV2{}, err
		}
		body := wire.DeviceReportBodyV2{
			Schema: 2, ClusterID: current.Payload.ClusterID, DeviceID: current.Payload.DeviceID,
			ReportID: options.ReportID, ReportSequence: options.ReportSequence,
			GeneratedAt: generatedAt.Format(time.RFC3339), AcceptedFloors: store.Floors(),
			Kind: options.Kind, PayloadSchema: options.PayloadSchema, PayloadHash: payloadHash,
		}
		envelope, err = wire.SignDeviceReport(body, options.Payload, identityKey, options.Schemas)
		if err != nil {
			return wire.DeviceReportEnvelopeV2{}, err
		}
	} else {
		canonical, err := wire.MarshalCanonical(options.RetryEnvelope)
		if err != nil {
			return wire.DeviceReportEnvelopeV2{}, err
		}
		if _, err := wire.DecodeStrict(canonical, 4<<20, &envelope); err != nil ||
			!wire.EqualCanonical(envelope.Body.AcceptedFloors, store.Floors()) ||
			wire.VerifyDeviceReport(&envelope, &identityKey.PublicKey, current.Payload.DeviceID,
				identityHash, generatedAt, 24*time.Hour, 5*time.Minute, options.Schemas) != nil {
			return wire.DeviceReportEnvelopeV2{}, errors.New("[D131 Linux report] retry envelope 与当前 identity/floors/schema 不一致")
		}
	}
	client, err := newPrivateDeviceHTTPClient(service, "device_report", certificateDER, identityKey,
		options.Roots, options.Dial, now, options.Timeout)
	if err != nil {
		return wire.DeviceReportEnvelopeV2{}, err
	}
	defer client.CloseIdleConnections()
	if err := client.postDeviceReport(ctx, &envelope); err != nil {
		return envelope, err
	}
	return envelope, nil
}

func (client *privateDeviceHTTPClient) postDeviceReport(ctx context.Context,
	envelope *wire.DeviceReportEnvelopeV2) error {
	if client == nil || client.client == nil || envelope == nil {
		return errors.New("[D131 Linux report] private client/report 缺失")
	}
	body, err := wire.MarshalCanonical(envelope)
	if err != nil {
		return err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost,
		client.baseURL+"/private/v2/device/report", bytes.NewReader(body))
	if err != nil {
		return err
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json")
	response, err := client.client.Do(request)
	if err != nil {
		return fmt.Errorf("[D131 Linux report] private device_report 请求失败: %w", err)
	}
	defer response.Body.Close()
	responseBody, readErr := io.ReadAll(io.LimitReader(response.Body,
		maximumPrivateDeviceReportResponseBytes+1))
	if readErr != nil || len(responseBody) > maximumPrivateDeviceReportResponseBytes {
		return errors.New("[D131 Linux report] private device_report 响应无效或过大")
	}
	if response.StatusCode != http.StatusNoContent || len(responseBody) != 0 ||
		response.Header.Get("Content-Encoding") != "" {
		return fmt.Errorf("[D131 Linux report] private device_report 未接受: status=%d", response.StatusCode)
	}
	return nil
}

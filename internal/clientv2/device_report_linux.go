//go:build linux

package clientv2

import (
	"bytes"
	"context"
	"crypto/ecdsa"
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
// report sequence 的原子 CAS 由服务端强制；重试时调用方必须复用返回的 exact envelope。
func SendLinuxDeviceReport(ctx context.Context,
	options LinuxDeviceReportOptions) (wire.DeviceReportEnvelopeV2, error) {
	envelope, err := PrepareLinuxDeviceReport(options)
	if err != nil {
		return wire.DeviceReportEnvelopeV2{}, err
	}
	if err := SubmitLinuxDeviceReport(ctx, options, &envelope); err != nil {
		return envelope, err
	}
	return envelope, nil
}

// PrepareLinuxDeviceReport 只从 root-only identity/LKG 生成可持久化的 exact
// envelope。生产调用方必须先落盘，再调用 SubmitLinuxDeviceReport。
func PrepareLinuxDeviceReport(options LinuxDeviceReportOptions) (wire.DeviceReportEnvelopeV2, error) {
	store, current, _, identityKey, identityHash, _, err := linuxDeviceReportIdentity(options)
	if err != nil {
		return wire.DeviceReportEnvelopeV2{}, err
	}
	now := options.Now
	if now == nil {
		now = time.Now
	}
	generatedAt := now().UTC().Truncate(time.Second)
	if generatedAt.IsZero() {
		return wire.DeviceReportEnvelopeV2{}, errors.New("[Linux report] trusted time 无效")
	}
	if options.RetryEnvelope != nil {
		canonical, err := wire.MarshalCanonical(options.RetryEnvelope)
		var envelope wire.DeviceReportEnvelopeV2
		if err != nil {
			return wire.DeviceReportEnvelopeV2{}, err
		}
		if _, err := wire.DecodeStrict(canonical, 4<<20, &envelope); err != nil ||
			!wire.EqualCanonical(envelope.Body.AcceptedFloors, store.Floors()) ||
			wire.VerifyDeviceReport(&envelope, &identityKey.PublicKey, current.Payload.DeviceID,
				identityHash, generatedAt, 24*time.Hour, 5*time.Minute, options.Schemas) != nil {
			return wire.DeviceReportEnvelopeV2{}, errors.New("[Linux report] retry envelope 与当前 identity/floors/schema 不一致")
		}
		return envelope, nil
	}
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
	return wire.SignDeviceReport(body, options.Payload, identityKey, options.Schemas)
}

// SubmitLinuxDeviceReport 在每次发送前重新校验 current LKG、directory pin、
// Device certificate/private key 和 report signature；它不会为重试重新签名。
func SubmitLinuxDeviceReport(ctx context.Context, options LinuxDeviceReportOptions,
	envelope *wire.DeviceReportEnvelopeV2) error {
	if ctx == nil {
		return errors.New("[Linux report] context 缺失")
	}
	store, current, installation, identityKey, identityHash, certificateDER, err := linuxDeviceReportIdentity(options)
	if err != nil {
		return err
	}
	directory, directoryHash, roots := options.Directory, options.PinnedDirectoryHash, options.Roots
	installedContext, foundInstalledContext, err := installedLinuxPrivateControlContext(
		installation, store.Floors(), current.Payload.DeviceID)
	if err != nil {
		return err
	}
	if foundInstalledContext {
		directory, directoryHash, roots = installedContext.directory,
			installedContext.directoryHash, installedContext.roots
	} else {
		currentSet, currentPreviousSet := store.ControlSets()
		if currentSet == nil {
			currentSet, currentPreviousSet = &options.ControlSet, options.PreviousControlSet
		}
		if err := VerifyControlServiceDirectory(&directory, directoryHash,
			&current.SignedCurrent.Head, currentSet, currentPreviousSet); err != nil {
			return err
		}
	}
	service, err := SelectPrivateControlService(&directory, "device_report", options.ServiceID)
	if err != nil {
		return err
	}
	now := options.Now
	if now == nil {
		now = time.Now
	}
	instant := now().UTC().Truncate(time.Second)
	if envelope == nil || !wire.EqualCanonical(envelope.Body.AcceptedFloors, store.Floors()) ||
		wire.VerifyDeviceReport(envelope, &identityKey.PublicKey, current.Payload.DeviceID,
			identityHash, instant, 24*time.Hour, 5*time.Minute, options.Schemas) != nil {
		return errors.New("[Linux report] envelope 与当前 identity/floors/schema 不一致")
	}
	client, err := newPrivateDeviceHTTPClient(service, "device_report", certificateDER, identityKey,
		roots, options.Dial, now, options.Timeout)
	if err != nil {
		return err
	}
	defer client.CloseIdleConnections()
	return client.postDeviceReport(ctx, envelope)
}

func linuxDeviceReportIdentity(options LinuxDeviceReportOptions) (*Store, *wire.DeviceViewEnvelopeV2,
	*DeviceInstallationV1, *ecdsa.PrivateKey, string, []byte, error) {
	store, err := Open(options.StatePath)
	if err != nil {
		return nil, nil, nil, nil, "", nil, err
	}
	current := store.Envelope()
	installation := store.Installation()
	if current == nil || installation == nil || current.Payload.Active == nil {
		return nil, nil, nil, nil, "", nil, errors.New("[Linux report] 正式 active enrollment/LKG 尚未安装")
	}
	identity, err := LoadEnrollmentIdentityForResume(options.IdentityPath)
	if err != nil {
		return nil, nil, nil, nil, "", nil, err
	}
	identityKey, _, err := identity.keys()
	if err != nil {
		return nil, nil, nil, nil, "", nil, err
	}
	identityHash, err := identity.IdentitySPKIHash()
	if err != nil || identityHash != installation.IdentityKeyHash ||
		identityHash != current.Payload.Active.IdentitySPKIHash {
		return nil, nil, nil, nil, "", nil, errors.New("[Linux report] 本机 identity 与 durable installation/view 不一致")
	}
	certificateDER, err := installation.certificateDER()
	if err != nil {
		return nil, nil, nil, nil, "", nil, err
	}
	certificateHash, err := wire.DeviceCertificateHash(certificateDER)
	if err != nil || certificateHash != installation.DeviceCertificateHash {
		return nil, nil, nil, nil, "", nil, errors.New("[Linux report] Device certificate 与 durable installation 不一致")
	}
	return store, current, installation, identityKey, identityHash, certificateDER, nil
}

func (client *privateDeviceHTTPClient) postDeviceReport(ctx context.Context,
	envelope *wire.DeviceReportEnvelopeV2) error {
	if client == nil || client.client == nil || envelope == nil {
		return errors.New("[Linux report] private client/report 缺失")
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
		return fmt.Errorf("[Linux report] private device_report 请求失败: %w", err)
	}
	defer response.Body.Close()
	responseBody, readErr := io.ReadAll(io.LimitReader(response.Body,
		maximumPrivateDeviceReportResponseBytes+1))
	if readErr != nil || len(responseBody) > maximumPrivateDeviceReportResponseBytes {
		return errors.New("[Linux report] private device_report 响应无效或过大")
	}
	if response.StatusCode != http.StatusNoContent || len(responseBody) != 0 ||
		response.Header.Get("Content-Encoding") != "" {
		return fmt.Errorf("[Linux report] private device_report 未接受: status=%d", response.StatusCode)
	}
	return nil
}

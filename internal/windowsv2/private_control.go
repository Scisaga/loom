package windowsv2

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"loom/internal/clientsecret"
	"loom/internal/clientv2"
	"loom/internal/wire"
)

type privateControlContext struct {
	state        *StateV1
	identityHash string
	chain        [][]byte
	roots        *x509.CertPool
	services     []wire.PrivateControlServiceV1
}

func buildPrivateControlContext(state *StateV1, identity *Identity, role, serviceID string,
	now time.Time) (privateControlContext, error) {
	if state == nil || identity == nil || state.Envelope.Payload.State != "active" ||
		state.Envelope.Payload.Active == nil || now.IsZero() {
		return privateControlContext{}, errors.New("[Windows control] active Device/identity/time 不完整")
	}
	identitySPKI := identity.IdentitySPKIDER()
	defer clear(identitySPKI)
	identityPublic, err := x509.ParsePKIXPublicKey(identitySPKI)
	publicKey, ok := identityPublic.(*ecdsa.PublicKey)
	identityHash, hashErr := identity.IdentitySPKIHash()
	if err != nil || !ok || publicKey.Curve != elliptic.P256() || hashErr != nil ||
		identityHash != state.material().IdentityKeyHash ||
		identityHash != state.Envelope.Payload.Active.IdentitySPKIHash {
		return privateControlContext{}, errors.New("[Windows control] DPAPI signer 与 protected Device 不一致")
	}
	certificateDER, err := state.certificateDER()
	if err != nil {
		return privateControlContext{}, err
	}
	certificate, err := x509.ParseCertificate(certificateDER)
	approvedAt, approvedErr := wire.ParseTimeZ(state.material().DeviceApprovedAt)
	if err != nil || approvedErr != nil || !bytes.Equal(certificate.RawSubjectPublicKeyInfo, identitySPKI) {
		return privateControlContext{}, errors.New("[Windows control] Device certificate/signer 不匹配")
	}
	if _, err := wire.VerifyDeviceCertificateAt(certificateDER, &state.material().DeviceProfile,
		state.Envelope.Payload.DeviceID, identityHash, "windows-desktop",
		state.Envelope.Payload.Active.Responsibilities.Values, state.material().DeviceIssuance,
		approvedAt, now.UTC()); err != nil {
		return privateControlContext{}, err
	}
	credentialBytes, err := state.Credential(wire.DevicePrivateControlCredentialSecretIDV1,
		"device_credential")
	if err != nil {
		return privateControlContext{}, err
	}
	defer clear(credentialBytes)
	var credential wire.DevicePrivateControlCredentialV1
	canonical, err := wire.DecodeStrict(credentialBytes, 1<<20, &credential)
	if err != nil || !bytes.Equal(canonical, credentialBytes) ||
		credential.ClusterID != state.Envelope.Payload.ClusterID ||
		credential.DeviceID != state.Envelope.Payload.DeviceID ||
		wire.ValidateDevicePrivateControlCredentialAtFloor(&credential, state.Floors) != nil {
		return privateControlContext{}, errors.New("[Windows control] private credential 未绑定 durable authority")
	}
	services, err := clientv2.SelectPrivateControlServices(&credential.ControlServiceDirectory,
		role, serviceID, state.material().DeviceProfile.ProfileID)
	if err != nil {
		return privateControlContext{}, err
	}
	roots := x509.NewCertPool()
	for _, encoded := range credential.InternalCARootsDER {
		der, decodeErr := base64.RawURLEncoding.DecodeString(encoded)
		root, parseErr := x509.ParseCertificate(der)
		if decodeErr != nil || parseErr != nil || !bytes.Equal(root.Raw, der) {
			return privateControlContext{}, errors.New("[Windows control] internal CA root DER 无效")
		}
		roots.AddCert(root)
	}
	chain := make([][]byte, 0, 1+len(state.material().DeviceProfile.ProfileIntent.IssuerChainDER))
	chain = append(chain, append([]byte(nil), certificateDER...))
	for _, encoded := range state.material().DeviceProfile.ProfileIntent.IssuerChainDER {
		der, decodeErr := base64.RawURLEncoding.DecodeString(encoded)
		certificate, parseErr := x509.ParseCertificate(der)
		if decodeErr != nil || parseErr != nil || !bytes.Equal(certificate.Raw, der) {
			return privateControlContext{}, errors.New("[Windows control] client issuer chain DER 无效")
		}
		chain = append(chain, der)
	}
	return privateControlContext{state: state, identityHash: identityHash,
		chain: chain, roots: roots, services: services}, nil
}

type DeviceConfigSyncOptions struct {
	StatePath         string
	IdentityPath      string
	Protector         clientsecret.Protector
	ServiceID         string
	Dial              clientv2.TunnelDialContext
	Now               func() time.Time
	Timeout           time.Duration
	Fetcher           clientv2.MirrorFetcher
	ValidateCandidate func(*StateV1) error
}

// SyncDeviceConfig 通过正式 Device mTLS identity 获取 delivery；只有变化的
// public configs 与 sealed credentials 全部到齐后才推进 LKG。
func SyncDeviceConfig(ctx context.Context, options DeviceConfigSyncOptions) (wire.ClientFloorsV2, error) {
	if ctx == nil || options.Protector == nil {
		return wire.ClientFloorsV2{}, errors.New("[Windows config] context/protector 缺失")
	}
	store, err := OpenState(options.StatePath, options.Protector)
	if err != nil {
		return wire.ClientFloorsV2{}, err
	}
	state := store.Snapshot()
	if state == nil || state.Envelope.Payload.State != "active" {
		return store.Floors(), errors.New("[Windows config] active v2 LKG 尚未安装")
	}
	identity, err := LoadIdentity(options.IdentityPath, options.Protector)
	if err != nil {
		return store.Floors(), err
	}
	defer identity.Close()
	now := options.Now
	if now == nil {
		now = time.Now
	}
	timeout := options.Timeout
	if timeout == 0 {
		timeout = 30 * time.Second
	}
	control, err := buildPrivateControlContext(state, identity, "device_config", options.ServiceID, now().UTC())
	if err != nil {
		return store.Floors(), err
	}
	var delivery wire.DeviceConfigDeliveryV1
	var fetchErr error
	for _, service := range control.services {
		client, err := clientv2.NewPrivateDeviceHTTPClient(service, "device_config",
			state.material().DeviceProfile.ProfileID, control.chain, identity.Signer(),
			control.roots, options.Dial, now, timeout)
		if err != nil {
			fetchErr = err
			continue
		}
		delivery, fetchErr = client.FetchDeviceConfigDelivery(ctx)
		client.CloseIdleConnections()
		if fetchErr == nil {
			break
		}
	}
	if fetchErr != nil {
		return store.Floors(), fetchErr
	}
	verified, err := wire.VerifyDeviceConfigDeliveryFromProtected(&delivery, &state.Envelope,
		state.Floors, state.ControlSet, state.PreviousControlSet, state.Envelope.Payload.DeviceID,
		control.identityHash)
	if err != nil {
		return store.Floors(), err
	}
	finalEnvelope := verified.Envelope()
	configChanged, secretChanged := artifactRefsChanged(&state.Envelope, &finalEnvelope)
	var configs *[]InstalledConfigV1
	var credentials *[]InstalledSecretV1
	if finalEnvelope.Payload.State == "active" {
		if configChanged {
			fetcher := options.Fetcher
			if fetcher.Timeout == 0 {
				fetcher.Timeout = timeout
			}
			installed, err := FetchConfigArtifacts(ctx, state.material().DistributionMirrors,
				finalEnvelope.Payload.Active.ConfigArtifactRefs, fetcher)
			if err != nil {
				return store.Floors(), err
			}
			configs = &installed
		}
		if secretChanged {
			refs, err := decodeSecretArtifactRefs(finalEnvelope.SecretArtifactRefs)
			if err != nil {
				return store.Floors(), err
			}
			installed, err := InstallSecretArtifacts(identity, refs, delivery.SecretEnvelopes,
				state.Envelope.Payload.DeviceID)
			if err != nil {
				return store.Floors(), err
			}
			credentials = &installed
		}
	}
	return store.AcceptDeviceConfigDeliveryValidated(&delivery, identity, configs, credentials,
		options.ValidateCandidate)
}

type DeviceReportOptions struct {
	StatePath      string
	IdentityPath   string
	Protector      clientsecret.Protector
	ServiceID      string
	Dial           clientv2.TunnelDialContext
	Now            func() time.Time
	Timeout        time.Duration
	ReportID       string
	ReportSequence int64
	Kind           string
	PayloadSchema  int64
	Payload        json.RawMessage
	Schemas        wire.DeviceReportSchemaRegistry
	Observations   func([]json.RawMessage)
}

func PrepareDeviceReport(options DeviceReportOptions) (wire.DeviceReportEnvelopeV2, error) {
	store, err := OpenState(options.StatePath, options.Protector)
	if err != nil {
		return wire.DeviceReportEnvelopeV2{}, err
	}
	state := store.Snapshot()
	if state == nil || state.Envelope.Payload.State != "active" || state.Envelope.Payload.Active == nil {
		return wire.DeviceReportEnvelopeV2{}, errors.New("[Windows report] active v2 LKG 尚未安装")
	}
	identity, err := LoadIdentity(options.IdentityPath, options.Protector)
	if err != nil {
		return wire.DeviceReportEnvelopeV2{}, err
	}
	defer identity.Close()
	identityHash, err := identity.IdentitySPKIHash()
	if err != nil || identityHash != state.material().IdentityKeyHash ||
		identityHash != state.Envelope.Payload.Active.IdentitySPKIHash {
		return wire.DeviceReportEnvelopeV2{}, errors.New("[Windows report] signer 与 protected Device 不一致")
	}
	now := options.Now
	if now == nil {
		now = time.Now
	}
	generatedAt := now().UTC().Truncate(time.Second)
	payloadHash, err := wire.DeviceReportPayloadHash(options.Payload)
	if err != nil {
		return wire.DeviceReportEnvelopeV2{}, err
	}
	reportID := options.ReportID
	if reportID == "" {
		digest := strings.TrimPrefix(payloadHash, "sha256:")
		if len(digest) > 16 {
			digest = digest[:16]
		}
		reportID = fmt.Sprintf("report-%020d-%s", options.ReportSequence, digest)
	}
	body := wire.DeviceReportBodyV2{
		Schema: 2, ClusterID: state.Envelope.Payload.ClusterID,
		DeviceID: state.Envelope.Payload.DeviceID, ReportID: reportID,
		ReportSequence: options.ReportSequence, GeneratedAt: generatedAt.Format(time.RFC3339),
		AcceptedFloors: state.Floors, Kind: options.Kind,
		PayloadSchema: options.PayloadSchema, PayloadHash: payloadHash,
	}
	return wire.SignDeviceReportWithSigner(body, options.Payload, identity.Signer(), options.Schemas)
}

func SubmitDeviceReport(ctx context.Context, options DeviceReportOptions,
	envelope *wire.DeviceReportEnvelopeV2) error {
	if ctx == nil || envelope == nil {
		return errors.New("[Windows report] context/envelope 缺失")
	}
	store, err := OpenState(options.StatePath, options.Protector)
	if err != nil {
		return err
	}
	state := store.Snapshot()
	if state == nil || state.Envelope.Payload.State != "active" {
		return errors.New("[Windows report] tombstone/inactive Device 禁止上报")
	}
	identity, err := LoadIdentity(options.IdentityPath, options.Protector)
	if err != nil {
		return err
	}
	defer identity.Close()
	identityHash, err := identity.IdentitySPKIHash()
	if err != nil {
		return err
	}
	now := options.Now
	if now == nil {
		now = time.Now
	}
	instant := now().UTC().Truncate(time.Second)
	public, ok := identity.Signer().Public().(*ecdsa.PublicKey)
	if !ok || !wire.EqualCanonical(envelope.Body.AcceptedFloors, state.Floors) ||
		wire.VerifyDeviceReport(envelope, public, state.Envelope.Payload.DeviceID,
			identityHash, instant, 24*time.Hour, 5*time.Minute, options.Schemas) != nil {
		return errors.New("[Windows report] envelope 与当前 identity/floors/schema 不一致")
	}
	control, err := buildPrivateControlContext(state, identity, "device_report", options.ServiceID, instant)
	if err != nil {
		return err
	}
	timeout := options.Timeout
	if timeout == 0 {
		timeout = 30 * time.Second
	}
	var submitErr error
	for _, service := range control.services {
		client, err := clientv2.NewPrivateDeviceHTTPClient(service, "device_report",
			state.material().DeviceProfile.ProfileID, control.chain, identity.Signer(),
			control.roots, options.Dial, now, timeout)
		if err != nil {
			submitErr = err
			continue
		}
		var observations []json.RawMessage
		observations, submitErr = client.PostDeviceReportWithObservations(ctx, envelope)
		client.CloseIdleConnections()
		if submitErr == nil {
			if options.Observations != nil && observations != nil {
				options.Observations(observations)
			}
			return nil
		}
	}
	return submitErr
}

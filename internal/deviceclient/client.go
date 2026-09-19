package deviceclient

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"sort"
	"time"

	"loom/internal/control"
)

// IdentityStore is the private device wire boundary. Linux owner-only storage
// and Windows DPAPI profiles implement the same claim/resume/sync/report state
// machine without copying protocol logic.
type IdentityStore interface {
	Capability() control.BootstrapCapability
	ClaimRequestID() string
	PublicKey() string
	PrivateKey() ed25519.PrivateKey
	LKG() *control.DeviceViewEnvelope
	SaveLKG(control.DeviceViewEnvelope) error
}

func tunnelHTTPClient(connection net.Conn) *http.Client {
	used := false
	return &http.Client{Timeout: 30 * time.Second, Transport: &http.Transport{Proxy: nil, DialContext: func(context.Context, string, string) (net.Conn, error) {
		if used {
			return nil, errors.New("private tunnel connection already used")
		}
		used = true
		return connection, nil
	}}}
}

func postJSON(ctx context.Context, connection net.Conn, path string, requestValue, responseValue any) (int, error) {
	body, err := json.Marshal(requestValue)
	if err != nil {
		return 0, err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://loom.private"+path, bytes.NewReader(body))
	if err != nil {
		return 0, err
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := tunnelHTTPClient(connection).Do(request)
	if err != nil {
		return 0, err
	}
	defer response.Body.Close()
	responseBody, err := io.ReadAll(io.LimitReader(response.Body, 8<<20))
	if err != nil {
		return response.StatusCode, err
	}
	if response.StatusCode != http.StatusOK && response.StatusCode != http.StatusAccepted {
		return response.StatusCode, errors.New("private device service rejected request")
	}
	decoder := json.NewDecoder(bytes.NewReader(responseBody))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(responseValue); err != nil {
		return response.StatusCode, err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return response.StatusCode, errors.New("private device response has trailing content")
	}
	return response.StatusCode, nil
}

func endpointOrder(endpoints []control.EndpointReference) []control.EndpointReference {
	result := append([]control.EndpointReference(nil), endpoints...)
	sort.Slice(result, func(i, j int) bool {
		if result[i].Preference != result[j].Preference {
			return result[i].Preference < result[j].Preference
		}
		if result[i].EndpointID != result[j].EndpointID {
			return result[i].EndpointID < result[j].EndpointID
		}
		return result[i].Generation < result[j].Generation
	})
	return result
}

func Claim(ctx context.Context, store IdentityStore) (control.EnrollmentResponse, error) {
	capability := store.Capability()
	claim, err := control.SignEnrollmentClaim(control.EnrollmentClaimRequest{Schema: 1, Capability: capability,
		RequestID: store.ClaimRequestID(), DevicePublicKey: store.PublicKey()}, store.PrivateKey())
	if err != nil {
		return control.EnrollmentResponse{}, err
	}
	var failures []error
	for _, endpoint := range endpointOrder(capability.Endpoints) {
		hello := control.TunnelHello{Schema: 1, Mode: "bootstrap", EndpointID: endpoint.EndpointID,
			Generation: endpoint.Generation, Capability: &capability}
		connection, err := control.DialEndpoint(ctx, endpoint, hello, nil)
		if err != nil {
			failures = append(failures, err)
			continue
		}
		var response control.EnrollmentResponse
		_, err = postJSON(ctx, connection, "/v2/enrollment/claim", claim, &response)
		_ = connection.Close()
		if err != nil {
			failures = append(failures, err)
			continue
		}
		if response.Transaction.ID != capability.TransactionID || response.Transaction.DevicePublicKey != store.PublicKey() {
			return control.EnrollmentResponse{}, errors.New("enrollment response is bound to another transaction or identity")
		}
		if response.DeviceView != nil {
			if err := store.SaveLKG(*response.DeviceView); err != nil {
				return control.EnrollmentResponse{}, err
			}
		}
		return response, nil
	}
	return control.EnrollmentResponse{}, errors.Join(failures...)
}

func Resume(ctx context.Context, store IdentityStore) (control.EnrollmentResponse, error) {
	capability := store.Capability()
	resume, err := control.SignEnrollmentResume(control.EnrollmentResumeRequest{Schema: 1,
		TransactionID: capability.TransactionID, RequestID: store.ClaimRequestID(), DevicePublicKey: store.PublicKey()}, store.PrivateKey())
	if err != nil {
		return control.EnrollmentResponse{}, err
	}
	var failures []error
	for _, endpoint := range endpointOrder(capability.Endpoints) {
		hello := control.TunnelHello{Schema: 1, Mode: "bootstrap", EndpointID: endpoint.EndpointID,
			Generation: endpoint.Generation, Capability: &capability}
		connection, err := control.DialEndpoint(ctx, endpoint, hello, nil)
		if err != nil {
			failures = append(failures, err)
			continue
		}
		var response control.EnrollmentResponse
		_, err = postJSON(ctx, connection, "/v2/enrollment/resume", resume, &response)
		_ = connection.Close()
		if err != nil {
			failures = append(failures, err)
			continue
		}
		if response.Transaction.ID != capability.TransactionID || response.Transaction.DevicePublicKey != store.PublicKey() {
			return control.EnrollmentResponse{}, errors.New("enrollment response is bound to another transaction or identity")
		}
		if response.DeviceView != nil {
			if err := store.SaveLKG(*response.DeviceView); err != nil {
				return control.EnrollmentResponse{}, err
			}
		}
		return response, nil
	}
	return control.EnrollmentResponse{}, errors.Join(failures...)
}

func deviceConnection(ctx context.Context, store IdentityStore) (net.Conn, error) {
	lkg := store.LKG()
	if lkg == nil {
		return nil, errors.New("device has no certified LKG")
	}
	var failures []error
	for _, endpoint := range endpointOrder(lkg.View.Endpoints) {
		if endpoint.State != "serving" {
			continue
		}
		hello := control.TunnelHello{Schema: 1, Mode: "device", EndpointID: endpoint.EndpointID,
			Generation: endpoint.Generation, DeviceID: lkg.View.DeviceID}
		connection, err := control.DialEndpoint(ctx, endpoint, hello, store.PrivateKey())
		if err == nil {
			return connection, nil
		}
		failures = append(failures, err)
	}
	if len(failures) == 0 {
		return nil, errors.New("device LKG has no serving endpoint generation")
	}
	return nil, errors.Join(failures...)
}

func Sync(ctx context.Context, store IdentityStore) (control.DeviceViewEnvelope, error) {
	connection, err := deviceConnection(ctx, store)
	if err != nil {
		return control.DeviceViewEnvelope{}, err
	}
	defer connection.Close()
	var envelope control.DeviceViewEnvelope
	if _, err := postJSON(ctx, connection, "/v2/device/config", struct{}{}, &envelope); err != nil {
		return envelope, err
	}
	if err := store.SaveLKG(envelope); err != nil {
		return control.DeviceViewEnvelope{}, err
	}
	return envelope, nil
}

func Report(ctx context.Context, store IdentityStore, report control.DeviceReport) error {
	lkg := store.LKG()
	if lkg == nil {
		return errors.New("device has no certified LKG")
	}
	digest, err := control.DeviceViewDigest(lkg.View)
	if err != nil {
		return err
	}
	report.Schema = 1
	report.DeviceID = lkg.View.DeviceID
	report.ViewDigest = digest
	report, err = control.SignDeviceReport(report, store.PrivateKey())
	if err != nil {
		return err
	}
	connection, err := deviceConnection(ctx, store)
	if err != nil {
		return err
	}
	defer connection.Close()
	var response struct {
		DeviceID   string `json:"device_id"`
		ReportedAt string `json:"reported_at"`
	}
	if _, err = postJSON(ctx, connection, "/v2/device/report", report, &response); err != nil {
		return err
	}
	if response.DeviceID != report.DeviceID || response.ReportedAt != report.ReportedAt {
		return errors.New("device report acknowledgement mismatch")
	}
	return nil
}

package deviceclient

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"sort"
	"strings"
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
	return ClaimWithServer(ctx, store, nil)
}

func ClaimWithServer(ctx context.Context, store IdentityStore, server *control.ServerClaimV2) (control.EnrollmentResponse, error) {
	capability := store.Capability()
	claim, err := control.SignEnrollmentClaim(control.EnrollmentClaimRequest{Schema: 2, Capability: capability,
		RequestID: store.ClaimRequestID(), DevicePublicKey: store.PublicKey(), Server: server}, store.PrivateKey())
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
		if response.Schema != 2 || response.Transaction.Intent.Schema != 2 {
			return control.EnrollmentResponse{}, errors.New("enrollment response does not use schema 2")
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
	resume, err := control.SignEnrollmentResume(control.EnrollmentResumeRequest{Schema: 2,
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
		if response.Schema != 2 || response.Transaction.Intent.Schema != 2 {
			return control.EnrollmentResponse{}, errors.New("enrollment response does not use schema 2")
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
		addresses, err := endpointDialAddresses(ctx, endpoint.Address, lkg.View.DNS)
		if err != nil {
			failures = append(failures, err)
			continue
		}
		for _, address := range addresses {
			resolved := endpoint
			resolved.Address = address
			connection, dialErr := control.DialEndpoint(ctx, resolved, hello, store.PrivateKey())
			if dialErr == nil {
				return connection, nil
			}
			failures = append(failures, dialErr)
		}
	}
	if len(failures) == 0 {
		return nil, errors.New("device LKG has no serving endpoint generation")
	}
	return nil, errors.Join(failures...)
}

func endpointDialAddresses(ctx context.Context, address string, dnsAddresses []string) ([]string, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil || host == "" || port == "" {
		return nil, errors.New("device endpoint address is invalid")
	}
	if net.ParseIP(host) != nil || len(dnsAddresses) == 0 {
		return []string{address}, nil
	}
	dns := net.ParseIP(dnsAddresses[0])
	if dns == nil {
		return nil, errors.New("certified device DNS address is invalid")
	}
	resolver := &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, "udp", net.JoinHostPort(dns.String(), "53"))
	}}
	addresses, err := resolver.LookupHost(ctx, host)
	if err != nil {
		return nil, errors.New("certified device DNS could not resolve an endpoint")
	}
	return canonicalEndpointAddresses(addresses, port)
}

func canonicalEndpointAddresses(addresses []string, port string) ([]string, error) {
	values := append([]string(nil), addresses...)
	sort.Slice(values, func(i, j int) bool {
		leftV4, rightV4 := strings.Count(values[i], ":") == 0, strings.Count(values[j], ":") == 0
		if leftV4 != rightV4 {
			return leftV4
		}
		return values[i] < values[j]
	})
	result := make([]string, 0, len(values))
	previous := ""
	for _, value := range values {
		parsed := net.ParseIP(value)
		if parsed == nil || parsed.String() == previous {
			continue
		}
		previous = parsed.String()
		result = append(result, net.JoinHostPort(previous, port))
	}
	if len(result) == 0 {
		return nil, errors.New("certified device DNS returned no endpoint addresses")
	}
	return result, nil
}

// EndpointRouteExclusions resolves only certified serving EndpointGeneration
// addresses and returns exact host prefixes suitable for a platform TUN
// exclusion. The result is local runtime input: endpoint identity continues to
// come from the certified server name and SPKI.
func EndpointRouteExclusions(ctx context.Context, endpoints []control.EndpointReference, dnsAddresses []string) ([]string, error) {
	prefixes := map[string]bool{}
	serving := 0
	for _, endpoint := range endpointOrder(endpoints) {
		if endpoint.State != "serving" {
			continue
		}
		serving++
		addresses, err := endpointDialAddresses(ctx, endpoint.Address, dnsAddresses)
		if err != nil {
			return nil, err
		}
		for _, address := range addresses {
			host, _, err := net.SplitHostPort(address)
			if err != nil {
				return nil, errors.New("resolved device endpoint address is invalid")
			}
			ip := net.ParseIP(host)
			if ip == nil {
				return nil, errors.New("resolved device endpoint is not an IP address")
			}
			bits := 128
			if ip.To4() != nil {
				ip, bits = ip.To4(), 32
			}
			prefixes[fmt.Sprintf("%s/%d", ip.String(), bits)] = true
		}
	}
	if serving == 0 || len(prefixes) == 0 {
		return nil, errors.New("device view has no resolvable serving endpoint")
	}
	result := make([]string, 0, len(prefixes))
	for prefix := range prefixes {
		result = append(result, prefix)
	}
	sort.Strings(result)
	return result, nil
}

// Fetch retrieves and verifies the next certified view without advancing the
// device floor. Host adapters use it to prepare, apply and read back the real
// runtime before SaveLKG promotes the view.
func Fetch(ctx context.Context, store IdentityStore) (control.DeviceViewEnvelope, error) {
	connection, err := deviceConnection(ctx, store)
	if err != nil {
		return control.DeviceViewEnvelope{}, err
	}
	defer connection.Close()
	var envelope control.DeviceViewEnvelope
	if _, err := postJSON(ctx, connection, "/v2/device/config", struct{}{}, &envelope); err != nil {
		return envelope, err
	}
	if err := control.VerifyDeviceViewEnvelope(envelope, store.Capability()); err != nil || envelope.View.DevicePublicKey != store.PublicKey() {
		return control.DeviceViewEnvelope{}, errors.New("device view is not certified for this identity")
	}
	if current := store.LKG(); current != nil && envelope.Head.Index < current.Head.Index {
		return control.DeviceViewEnvelope{}, errors.New("device view rolls back the certified floor")
	}
	return envelope, nil
}

// Sync is retained for adapters that provide their own SaveLKG preflight
// hook. Linux uses Fetch directly so persistence follows runtime readback.
func Sync(ctx context.Context, store IdentityStore) (control.DeviceViewEnvelope, error) {
	envelope, err := Fetch(ctx, store)
	if err != nil {
		return control.DeviceViewEnvelope{}, err
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
	if lkg.View.Schema == 2 {
		report.Schema = 2
		if report.Selection != "" {
			return errors.New("schema-2 report contains a legacy single selection")
		}
		if report.Runtime == nil {
			return errors.New("schema-2 report has no measured runtime readback")
		}
	}
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

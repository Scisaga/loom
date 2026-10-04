package deviceclient

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"io"
	"loom/internal/control"
	"loom/internal/netx"
	"net"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"
)

type IdentityStore interface {
	Invite() control.BootstrapInvite
	Platform() string
	ClaimRequestID() string
	PublicKey() string
	PrivateKey() ed25519.PrivateKey
	LKG() *control.DeviceViewEnvelope
	SaveLKG(control.DeviceViewEnvelope) error
	ReserveReportSequence() (control.U64, error)
}

func tunnelHTTPClient(connection net.Conn) *http.Client {
	used := false
	return &http.Client{Timeout: 30 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("private device redirect is forbidden") }, Transport: &http.Transport{Proxy: nil, DisableKeepAlives: true, DialContext: func(context.Context, string, string) (net.Conn, error) {
		if used {
			return nil, errors.New("private tunnel already used")
		}
		used = true
		return connection, nil
	}}}
}
func postJSON(ctx context.Context, connection net.Conn, path string, requestValue, responseValue any) (int, error) {
	body, err := control.CanonicalEncode(requestValue)
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
	responseBody, err := io.ReadAll(io.LimitReader(response.Body, 8<<20+1))
	if err != nil {
		return response.StatusCode, err
	}
	if response.StatusCode != http.StatusOK && response.StatusCode != http.StatusAccepted {
		return response.StatusCode, errors.New("private device service rejected request")
	}
	if err := control.DecodeCanonical(responseBody, responseValue, control.ContractDecodeLimits{MaxBytes: 8 << 20, MaxDepth: 128, MaxItems: 1 << 20}); err != nil {
		return response.StatusCode, err
	}
	return response.StatusCode, nil
}
func endpointOrder(endpoints []control.EndpointGeneration) []control.EndpointGeneration {
	result := append([]control.EndpointGeneration{}, endpoints...)
	sort.Slice(result, func(i, j int) bool {
		if result[i].Preference != result[j].Preference {
			return result[i].Preference < result[j].Preference
		}
		if result[i].ID != result[j].ID {
			return result[i].ID < result[j].ID
		}
		return result[i].Generation < result[j].Generation
	})
	return result
}
func Claim(ctx context.Context, store IdentityStore) (control.EnrollmentResponse, error) {
	return enroll(ctx, store, false)
}
func Resume(ctx context.Context, store IdentityStore) (control.EnrollmentResponse, error) {
	return enroll(ctx, store, true)
}
func enroll(ctx context.Context, store IdentityStore, resume bool) (control.EnrollmentResponse, error) {
	invite := store.Invite()
	if err := invite.Validate(); err != nil {
		return control.EnrollmentResponse{}, err
	}
	payload := invite.Material.Payload.(control.Invite)
	materialID, err := control.MaterialID(invite.Material)
	if err != nil {
		return control.EnrollmentResponse{}, err
	}
	request := control.EnrollmentClaimRequest{Schema: 3, NetworkID: invite.NetworkID, GenesisDigest: invite.GenesisDigest, TransactionID: payload.ID, InviteMaterialID: materialID, RequestID: store.ClaimRequestID(), DevicePublicKey: store.PublicKey(), Platform: store.Platform()}
	path := "/enrollment/claim"
	var signed any
	if resume {
		value, err := control.SignEnrollmentResume(control.EnrollmentResumeRequest(request), store.PrivateKey())
		if err != nil {
			return control.EnrollmentResponse{}, err
		}
		signed = value
		path = "/enrollment/resume"
	} else {
		value, err := control.SignEnrollmentClaim(request, store.PrivateKey())
		if err != nil {
			return control.EnrollmentResponse{}, err
		}
		signed = value
	}
	// Once joined, resume uses device authentication. Bootstrap remains the
	// original issuer's frozen endpoint and is never redirected to another peer.
	var connection net.Conn
	if resume && store.LKG() != nil {
		connection, err = deviceConnection(ctx, store)
	} else {
		endpoint := payload.Endpoint
		hello := control.TunnelHello{Schema: 3, Mode: "bootstrap", EndpointID: endpoint.ID, Generation: endpoint.Generation, Invite: &invite}
		connection, err = control.DialEndpoint(withCertifiedDNS(ctx, payload.DNSServers), endpoint, hello, nil)
	}
	if err != nil {
		return control.EnrollmentResponse{}, err
	}
	defer connection.Close()
	var response control.EnrollmentResponse
	if _, err := postJSON(ctx, connection, path, signed, &response); err != nil {
		return control.EnrollmentResponse{}, err
	}
	if response.TransactionID != payload.ID {
		return control.EnrollmentResponse{}, errors.New("enrollment response belongs to another transaction")
	}
	if response.DeviceView != nil {
		if err := store.SaveLKG(*response.DeviceView); err != nil {
			return control.EnrollmentResponse{}, err
		}
	}
	return response, nil
}
func deviceConnection(ctx context.Context, store IdentityStore) (net.Conn, error) {
	lkg := store.LKG()
	if lkg == nil {
		return nil, errors.New("device has no accepted LKG")
	}
	ctx = withCertifiedDNS(ctx, lkg.View.DNSServers)
	var failures []error
	for _, endpoint := range endpointOrder(lkg.View.Endpoints) {
		if endpoint.State != "serving" {
			continue
		}
		hello := control.TunnelHello{Schema: 3, Mode: "device", EndpointID: endpoint.ID, Generation: endpoint.Generation, DeviceID: lkg.View.DeviceID}
		connection, err := control.DialEndpoint(ctx, endpoint, hello, store.PrivateKey())
		if err == nil {
			return connection, nil
		}
		failures = append(failures, err)
	}
	if len(failures) == 0 {
		return nil, errors.New("device LKG has no serving endpoint")
	}
	return nil, errors.Join(failures...)
}

// Callers verify their Invite or LKG before supplying its DNS addresses. The
// inherited dialer keeps Android socket protection on both DNS and TLS traffic.
func withCertifiedDNS(ctx context.Context, servers []string) context.Context {
	underlay := control.EndpointDialer(ctx)
	return control.WithEndpointDialer(ctx, func(ctx context.Context, network, address string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(address)
		if err != nil {
			return nil, err
		}
		addresses, err := netx.ResolveCertifiedIPs(ctx, host, servers, underlay)
		if err != nil {
			return nil, err
		}
		var failures []error
		for _, ip := range addresses {
			attempt, cancel := context.WithTimeout(ctx, 5*time.Second)
			connection, err := underlay(attempt, network, net.JoinHostPort(ip.String(), port))
			cancel()
			if err == nil {
				return connection, nil
			}
			failures = append(failures, err)
		}
		return nil, errors.Join(failures...)
	})
}
func endpointDialAddresses(ctx context.Context, address string, dnsAddresses []string) ([]string, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil || host == "" || port == "" {
		return nil, errors.New("device endpoint address is invalid")
	}
	ips, err := netx.ResolveCertifiedIPs(ctx, host, dnsAddresses, control.EndpointDialer(ctx))
	if err != nil {
		return nil, err
	}
	values := make([]string, 0, len(ips))
	for _, ip := range ips {
		values = append(values, ip.String())
	}
	return canonicalEndpointAddresses(values, port)
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
func EndpointRouteExclusions(ctx context.Context, endpoints []control.EndpointGeneration, dnsAddresses []string) ([]string, error) {
	prefixes := map[string]bool{}
	serving := 0
	for _, endpoint := range endpointOrder(endpoints) {
		if endpoint.State != "serving" {
			continue
		}
		serving++
		addresses, err := endpointDialAddresses(ctx, net.JoinHostPort(endpoint.Host, strconv.Itoa(endpoint.Port)), dnsAddresses)
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

// Fetch verifies authentication without applying a runtime. SaveLKG is the
// durable acceptance boundary; execution and probes happen only afterward.
func Fetch(ctx context.Context, store IdentityStore) (control.DeviceViewEnvelope, error) {
	connection, err := deviceConnection(ctx, store)
	if err != nil {
		return control.DeviceViewEnvelope{}, err
	}
	defer connection.Close()
	var envelope control.DeviceViewEnvelope
	if _, err := postJSON(ctx, connection, "/device/config", struct{}{}, &envelope); err != nil {
		return control.DeviceViewEnvelope{}, err
	}
	if err := control.VerifyDeviceViewEnvelope(envelope, store.Invite()); err != nil {
		return control.DeviceViewEnvelope{}, err
	}
	if envelope.View.DevicePublicKey != store.PublicKey() || envelope.View.Platform != store.Platform() {
		return control.DeviceViewEnvelope{}, errors.New("device view identity changed")
	}
	if previous := store.LKG(); previous != nil {
		if err := control.CheckDeviceViewAdvance(envelope, *previous, previous.FactFrontier); err != nil {
			return control.DeviceViewEnvelope{}, err
		}
	}
	return envelope, nil
}
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
	sequence, err := store.ReserveReportSequence()
	if err != nil {
		return err
	}
	lkg := store.LKG()
	if lkg == nil {
		return errors.New("device has no accepted LKG")
	}
	if report.ViewDigest != "" && report.ViewDigest != lkg.ViewDigest {
		return errors.New("report observations belong to another accepted view")
	}
	report.Schema = 3
	report.NetworkID = lkg.NetworkID
	report.DeviceID = lkg.View.DeviceID
	report.ViewDigest = lkg.ViewDigest
	report.ReportSequence = sequence
	report, err = control.SignDeviceReport(report, store.PrivateKey())
	if err != nil {
		return err
	}
	return PostSignedReport(ctx, store, report)
}

// PostSignedReport sends an already reserved and signed report. Mobile hosts
// first commit ReserveReportSequence in their protected state, then call this
// same transport; this function never invents or advances persistent progress.
func PostSignedReport(ctx context.Context, store IdentityStore, report control.DeviceReport) error {
	lkg := store.LKG()
	if lkg == nil || report.NetworkID != lkg.NetworkID || report.DeviceID != lkg.View.DeviceID || report.ViewDigest != lkg.ViewDigest {
		return errors.New("signed report is not bound to this accepted view")
	}
	if err := report.Verify(store.PublicKey()); err != nil {
		return err
	}
	connection, err := deviceConnection(ctx, store)
	if err != nil {
		return err
	}
	defer connection.Close()
	var response control.DeviceReportResponse
	if _, err := postJSON(ctx, connection, "/device/report", report, &response); err != nil {
		return err
	}
	if response.ReportSequence != report.ReportSequence {
		return errors.New("device report acknowledgement sequence mismatch")
	}
	return nil
}

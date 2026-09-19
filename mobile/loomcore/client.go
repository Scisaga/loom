package loomcore

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"sort"
	"time"

	"loom/internal/clientmodel"
)

type deviceState struct {
	Schema         int                 `json:"schema"`
	PrivateKey     string              `json:"private_key"`
	PublicKey      string              `json:"public_key"`
	ClaimRequestID string              `json:"claim_request_id"`
	Capability     bootstrapCapability `json:"capability"`
	Claimed        bool                `json:"claimed"`
	Floor          uint64              `json:"floor"`
	LKG            *deviceViewEnvelope `json:"certified_lkg,omitempty"`
}

type androidProfile struct {
	Schema     int                          `json:"schema"`
	NodeID     string                       `json:"node_id"`
	Name       string                       `json:"name"`
	Head       string                       `json:"head"`
	Generation uint64                       `json:"generation"`
	ViewDigest string                       `json:"view_digest"`
	Config     string                       `json:"config"`
	Routes     []clientmodel.RouteCandidate `json:"routes"`
	RecordID   string                       `json:"record_id"`
}

func validateState(state deviceState) error {
	private, privateErr := base64.RawURLEncoding.DecodeString(state.PrivateKey)
	public, publicErr := rawKey(state.PublicKey)
	if state.Schema != 1 || privateErr != nil || len(private) != ed25519.PrivateKeySize || publicErr != nil ||
		!ed25519.PrivateKey(private).Public().(ed25519.PublicKey).Equal(public) || !validName(state.ClaimRequestID) || validateCapability(state.Capability) != nil {
		return errors.New("invalid protected device state")
	}
	if state.LKG == nil {
		if state.Floor != 0 {
			return errors.New("device floor has no LKG")
		}
		return nil
	}
	if verifyEnvelope(*state.LKG, state.Capability) != nil || state.LKG.View.DevicePublicKey != state.PublicKey ||
		state.Floor != state.LKG.Head.Index || state.Floor < state.LKG.View.Floor {
		return errors.New("invalid certified LKG")
	}
	return nil
}

func decodeState(body []byte) (deviceState, error) {
	var state deviceState
	if err := decodeStrictJSON(body, 8<<20, &state); err != nil {
		return state, err
	}
	return state, validateState(state)
}

func encodeState(state deviceState) ([]byte, error) {
	if err := validateState(state); err != nil {
		return nil, err
	}
	return canonical(state)
}

// NewAndroidDeviceState creates one durable Ed25519 identity bound to a private bootstrap capability.
func NewAndroidDeviceState(inviteRaw string) ([]byte, error) {
	invite, err := decodeInvite(inviteRaw)
	if err != nil {
		return nil, err
	}
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	request := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, request); err != nil {
		return nil, err
	}
	return encodeState(deviceState{Schema: 1, PrivateKey: base64.RawURLEncoding.EncodeToString(private),
		PublicKey: base64.RawURLEncoding.EncodeToString(public), ClaimRequestID: hex.EncodeToString(request), Capability: invite.Capability})
}

func ValidateAndroidDeviceState(body []byte) error {
	_, err := decodeState(body)
	return err
}

// AndroidDeviceProfile projects only the authenticated runtime data needed by the host.
func AndroidDeviceProfile(body []byte) ([]byte, error) {
	state, err := decodeState(body)
	if err != nil {
		return nil, err
	}
	if state.LKG == nil || state.LKG.View.Runtime == nil {
		return nil, errors.New("device has no certified runtime profile")
	}
	digest, _ := viewDigest(state.LKG.View)
	return canonical(androidProfile{Schema: 1, NodeID: state.LKG.View.DeviceID, Name: state.LKG.View.Name, Head: headID(state.LKG.Head),
		Generation: state.LKG.Head.Index, ViewDigest: digest, Config: state.LKG.View.Runtime.Config,
		Routes: state.LKG.View.Routes, RecordID: recordID(body)})
}

// AndroidEnrollmentState is a redacted status projection; it never returns capability or key bytes.
func AndroidEnrollmentState(body []byte) ([]byte, error) {
	state, err := decodeState(body)
	if err != nil {
		return nil, err
	}
	value := struct {
		Schema        int    `json:"schema"`
		TransactionID string `json:"transaction_id"`
		Claimed       bool   `json:"claimed"`
		Ready         bool   `json:"ready"`
		NodeID        string `json:"node_id,omitempty"`
		Generation    uint64 `json:"generation,omitempty"`
	}{Schema: 1, TransactionID: state.Capability.TransactionID, Claimed: state.Claimed, Ready: state.LKG != nil}
	if state.LKG != nil {
		value.NodeID, value.Generation = state.LKG.View.DeviceID, state.LKG.Head.Index
	}
	return canonical(value)
}

func privateKey(state deviceState) ed25519.PrivateKey {
	value, _ := base64.RawURLEncoding.DecodeString(state.PrivateKey)
	return ed25519.PrivateKey(value)
}

// AdvanceAndroidEnrollment submits claim or resume through the capability's pinned private tunnel.
func AdvanceAndroidEnrollment(body []byte) ([]byte, error) {
	state, err := decodeState(body)
	if err != nil {
		return nil, err
	}
	var request any
	path := "/v2/enrollment/claim"
	if state.Claimed {
		value := enrollmentResume{Schema: 1, TransactionID: state.Capability.TransactionID,
			RequestID: state.ClaimRequestID, DevicePublicKey: state.PublicKey}
		if err := signValue(resumeDomain, value, &value.Signature, privateKey(state)); err != nil {
			return nil, err
		}
		request, path = value, "/v2/enrollment/resume"
	} else {
		value := enrollmentClaim{Schema: 1, Capability: state.Capability, RequestID: state.ClaimRequestID, DevicePublicKey: state.PublicKey}
		if err := signValue(claimDomain, value, &value.Signature, privateKey(state)); err != nil {
			return nil, err
		}
		request = value
	}
	var response enrollmentResponse
	if err := postAcross(state.Capability.Endpoints, bootstrapHello(state.Capability), nil, path, request, &response); err != nil {
		return nil, err
	}
	if response.Schema != 1 || response.Transaction.ID != state.Capability.TransactionID || response.Transaction.DevicePublicKey != state.PublicKey ||
		response.Transaction.ClaimRequestID != state.ClaimRequestID {
		return nil, errors.New("enrollment response is bound to another transaction or identity")
	}
	state.Claimed = response.Transaction.State != "open"
	if response.DeviceView != nil {
		if err := installEnvelope(&state, *response.DeviceView); err != nil {
			return nil, err
		}
	}
	return encodeState(state)
}

// SyncAndroidDevice fetches the current certified view while retaining the old input bytes on failure.
func SyncAndroidDevice(body []byte) ([]byte, error) {
	state, err := decodeState(body)
	if err != nil {
		return nil, err
	}
	if state.LKG == nil {
		return nil, errors.New("device has no certified LKG")
	}
	var envelope deviceViewEnvelope
	if err := postAcross(state.LKG.View.Endpoints, deviceHello(state.LKG.View.DeviceID), privateKey(state),
		"/v2/device/config", struct{}{}, &envelope); err != nil {
		return nil, err
	}
	if err := installEnvelope(&state, envelope); err != nil {
		return nil, err
	}
	return encodeState(state)
}

func installEnvelope(state *deviceState, envelope deviceViewEnvelope) error {
	if err := verifyEnvelope(envelope, state.Capability); err != nil {
		return err
	}
	if envelope.View.DevicePublicKey != state.PublicKey || envelope.Head.Index < state.Floor {
		return errors.New("device view changes identity or rolls back floor")
	}
	state.Floor, state.LKG = envelope.Head.Index, &envelope
	return nil
}

// PostAndroidDeviceReport signs bounded business outcomes and sends them through the device tunnel.
func PostAndroidDeviceReport(stateBody, observationsBody []byte, selection, reportedAt string) error {
	state, err := decodeState(stateBody)
	if err != nil {
		return err
	}
	if state.LKG == nil {
		return errors.New("device has no certified LKG")
	}
	var observations []clientmodel.Observation
	if err := decodeStrictJSON(observationsBody, 1<<20, &observations); err != nil {
		return err
	}
	for index, observation := range observations {
		if observation.Validate() != nil || index > 0 && observations[index-1].CandidateID >= observation.CandidateID {
			return errors.New("observations are not uniquely sorted")
		}
	}
	if err := requireRFC3339(reportedAt); err != nil {
		return err
	}
	digest, _ := viewDigest(state.LKG.View)
	report := deviceReport{Schema: 1, DeviceID: state.LKG.View.DeviceID, ViewDigest: digest,
		Selection: selection, ReportedAt: reportedAt, Observations: observations}
	if err := signValue(reportDomain, report, &report.Signature, privateKey(state)); err != nil {
		return err
	}
	var response struct {
		DeviceID   string `json:"device_id"`
		ReportedAt string `json:"reported_at"`
	}
	if err := postAcross(state.LKG.View.Endpoints, deviceHello(state.LKG.View.DeviceID), privateKey(state),
		"/v2/device/report", report, &response); err != nil {
		return err
	}
	if response.DeviceID != report.DeviceID || response.ReportedAt != report.ReportedAt {
		return errors.New("report acknowledgement mismatch")
	}
	return nil
}

func bootstrapHello(capability bootstrapCapability) func(endpointReference) tunnelHello {
	return func(endpoint endpointReference) tunnelHello {
		copy := capability
		return tunnelHello{Schema: 1, Mode: "bootstrap", EndpointID: endpoint.EndpointID,
			Generation: endpoint.Generation, Capability: &copy}
	}
}

func deviceHello(deviceID string) func(endpointReference) tunnelHello {
	return func(endpoint endpointReference) tunnelHello {
		return tunnelHello{Schema: 1, Mode: "device", EndpointID: endpoint.EndpointID,
			Generation: endpoint.Generation, DeviceID: deviceID}
	}
}

type bufferedConn struct {
	net.Conn
	reader *bufio.Reader
}

func (connection *bufferedConn) Read(body []byte) (int, error) { return connection.reader.Read(body) }

func writeFrame(writer io.Writer, value any) error {
	body, err := canonical(value)
	if err != nil || len(body) == 0 || len(body) > 64<<10 {
		return errors.New("invalid tunnel frame")
	}
	header := make([]byte, 4)
	binary.BigEndian.PutUint32(header, uint32(len(body)))
	if _, err = writer.Write(header); err != nil {
		return err
	}
	_, err = writer.Write(body)
	return err
}

func readFrame(reader *bufio.Reader, value any) error {
	header := make([]byte, 4)
	if _, err := io.ReadFull(reader, header); err != nil {
		return err
	}
	size := binary.BigEndian.Uint32(header)
	if size == 0 || size > 64<<10 {
		return errors.New("invalid tunnel frame")
	}
	body := make([]byte, size)
	if _, err := io.ReadFull(reader, body); err != nil {
		return err
	}
	return decodeCanonical(body, value)
}

func dial(endpoint endpointReference, hello tunnelHello, private ed25519.PrivateKey) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	raw, err := (&net.Dialer{}).DialContext(ctx, "tcp", endpoint.Address)
	if err != nil {
		return nil, err
	}
	failed := true
	defer func() {
		if failed {
			_ = raw.Close()
		}
	}()
	config := &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13,
		ServerName: endpoint.ServerName, NextProtos: []string{"loom-tunnel/1"}, InsecureSkipVerify: true,
		VerifyConnection: func(state tls.ConnectionState) error {
			if len(state.PeerCertificates) == 0 {
				return errors.New("missing tunnel certificate")
			}
			sum := sha256.Sum256(state.PeerCertificates[0].RawSubjectPublicKeyInfo)
			if hex.EncodeToString(sum[:]) != endpoint.SPKISHA256 {
				return errors.New("tunnel SPKI mismatch")
			}
			return nil
		}}
	connection := tls.Client(raw, config)
	_ = connection.SetDeadline(time.Now().Add(20 * time.Second))
	if err := connection.HandshakeContext(ctx); err != nil {
		return nil, err
	}
	if err := writeFrame(connection, hello); err != nil {
		return nil, err
	}
	reader := bufio.NewReader(connection)
	if hello.Mode == "device" {
		var challenge tunnelChallenge
		if err := readFrame(reader, &challenge); err != nil || challenge.Schema != 1 {
			return nil, errors.New("invalid tunnel challenge")
		}
		message, _ := canonical(struct {
			Hello     tunnelHello     `json:"hello"`
			Challenge tunnelChallenge `json:"challenge"`
		}{hello, challenge})
		proof := tunnelProof{Schema: 1, Signature: base64.RawURLEncoding.EncodeToString(
			ed25519.Sign(private, append([]byte(tunnelDomain), message...)))}
		if err := writeFrame(connection, proof); err != nil {
			return nil, err
		}
	}
	var ready tunnelReady
	if err := readFrame(reader, &ready); err != nil || ready.Schema != 1 || ready.Status != "ready" {
		return nil, errors.New("tunnel rejected")
	}
	_ = connection.SetDeadline(time.Time{})
	failed = false
	return &bufferedConn{Conn: connection, reader: reader}, nil
}

func postAcross(endpoints []endpointReference, hello func(endpointReference) tunnelHello, private ed25519.PrivateKey,
	path string, request, response any) error {
	ordered := append([]endpointReference(nil), endpoints...)
	sort.Slice(ordered, func(i, j int) bool { return endpointLess(ordered[i], ordered[j]) })
	var failures []error
	for _, endpoint := range ordered {
		if endpoint.State != "serving" {
			continue
		}
		connection, err := dial(endpoint, hello(endpoint), private)
		if err != nil {
			failures = append(failures, err)
			continue
		}
		err = postJSON(connection, path, request, response)
		_ = connection.Close()
		if err == nil {
			return nil
		}
		failures = append(failures, err)
	}
	if len(failures) == 0 {
		return errors.New("no serving private endpoint")
	}
	return errors.Join(failures...)
}

func postJSON(connection net.Conn, path string, requestValue, responseValue any) error {
	body, err := canonical(requestValue)
	if err != nil {
		return err
	}
	request, err := http.NewRequest(http.MethodPost, "http://loom.private"+path, bytes.NewReader(body))
	if err != nil {
		return err
	}
	request.Header.Set("Content-Type", "application/json")
	used := false
	client := &http.Client{Timeout: 30 * time.Second, Transport: &http.Transport{Proxy: nil,
		DialContext: func(context.Context, string, string) (net.Conn, error) {
			if used {
				return nil, errors.New("tunnel already used")
			}
			used = true
			return connection, nil
		}}}
	httpResponse, err := client.Do(request)
	if err != nil {
		return err
	}
	defer httpResponse.Body.Close()
	responseBody, err := io.ReadAll(io.LimitReader(httpResponse.Body, 8<<20))
	if err != nil {
		return err
	}
	if httpResponse.StatusCode != http.StatusOK && httpResponse.StatusCode != http.StatusAccepted {
		return fmt.Errorf("private service rejected request: HTTP %d", httpResponse.StatusCode)
	}
	return decodeStrictJSON(responseBody, 8<<20, responseValue)
}

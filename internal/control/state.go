// Package control implements the five-concept v2 control authority. State is
// the one-time verified recovery input; the running daemon reads only the
// Material, Consensus, and Certified stores created from it.
package control

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"

	"loom/internal/model"
	"loom/internal/releasefloor"
	"loom/internal/validate"
)

const StateSchema = 1

type State struct {
	Schema       int              `json:"schema"`
	ClusterID    string           `json:"cluster_id"`
	Listen       string           `json:"listen"`
	Head         CertifiedHead    `json:"certified_head"`
	Recovery     RecoveryEvidence `json:"recovery"`
	BrowserTLS   BrowserTLS       `json:"browser_tls"`
	ReadCertDER  []string         `json:"read_cert_der"`
	AdminCertDER []string         `json:"admin_cert_der"`
	Projection   WebProjection    `json:"projection"`
}

type CertifiedHead struct {
	Hash     string `json:"hash"`
	Index    int64  `json:"index"`
	Revision int64  `json:"revision"`
}

type RecoveryEvidence struct {
	ConfigSHA256       string              `json:"config_sha256"`
	CertifiedSHA256    string              `json:"certified_sha256"`
	OperationsSHA256   string              `json:"operations_sha256"`
	ReleaseFloorSHA256 string              `json:"release_floor_sha256"`
	ReleaseFloor       releasefloor.Record `json:"release_floor"`
	V2Latch            bool                `json:"v2_latch"`
}

type BrowserTLS struct {
	CertificateChainPEM    string `json:"certificate_chain_pem"`
	PrivateKeyPKCS8PEM     string `json:"private_key_pkcs8_pem"`
	RootPrivateKeyPKCS8PEM string `json:"root_private_key_pkcs8_pem"`
}

// TLSIdentity is a node-local leaf and key. The browser authority private key
// remains only in BrowserTLS; the member identity never needs a second copy.
type TLSIdentity struct {
	CertificateChainPEM string `json:"certificate_chain_pem"`
	PrivateKeyPKCS8PEM  string `json:"private_key_pkcs8_pem"`
}

type WebProjection struct {
	Schema      int              `json:"schema"`
	UIState     UIState          `json:"ui_state"`
	Devices     []Device         `json:"devices"`
	Links       []Link           `json:"links"`
	Paths       []Path           `json:"paths"`
	Services    []Service        `json:"services"`
	Releases    []Release        `json:"releases"`
	Deployments []Deployment     `json:"deployments,omitempty"`
	Publisher   *PublisherStatus `json:"publisher,omitempty"`
	Events      []Event          `json:"events"`
	Traffic     []TrafficBucket  `json:"traffic,omitempty"`
}

type UIState struct {
	Head     string   `json:"head"`
	Revision int64    `json:"revision"`
	Writable bool     `json:"writable"`
	Warnings []string `json:"warnings"`
}

type Device struct {
	ID                  string                 `json:"id"`
	Name                string                 `json:"name"`
	Platform            string                 `json:"platform,omitempty"`
	Roles               []string               `json:"roles"`
	Endpoint            string                 `json:"endpoint,omitempty"`
	Authorized          bool                   `json:"authorized"`
	Availability        string                 `json:"availability"`
	EnrollmentID        string                 `json:"enrollment_id,omitempty"`
	Enrollment          string                 `json:"enrollment,omitempty"`
	EnrollmentReadiness string                 `json:"enrollment_readiness,omitempty"`
	WaitingFor          []string               `json:"waiting_for,omitempty"`
	ViewDigest          string                 `json:"view_digest,omitempty"`
	Presence            string                 `json:"presence,omitempty"`
	RuntimeState        string                 `json:"runtime_state,omitempty"`
	Components          string                 `json:"components,omitempty"`
	Deployment          string                 `json:"deployment,omitempty"`
	LastReportAt        string                 `json:"last_report_at,omitempty"`
	Direction           string                 `json:"direction,omitempty"`
	EgressCapable       bool                   `json:"egress_capable,omitempty"`
	Location            string                 `json:"location,omitempty"`
	ExpectedComponents  []ComponentExpectation `json:"expected_components,omitempty"`
	Evidence            *DeviceEvidence        `json:"evidence,omitempty"`
}

type DeviceEvidence struct {
	ReportedAt   string              `json:"reported_at"`
	ViewDigest   string              `json:"view_digest"`
	Selections   []ReportSelection   `json:"selections,omitempty"`
	Runtime      *RuntimeReadback    `json:"runtime,omitempty"`
	Components   []ComponentReadback `json:"components,omitempty"`
	Links        []LinkReadback      `json:"links,omitempty"`
	Measurements []Observation       `json:"measurements,omitempty"`
	Deployment   *DeploymentReadback `json:"deployment,omitempty"`
}

type Link struct {
	ID           string `json:"id,omitempty"`
	From         string `json:"from"`
	To           string `json:"to"`
	Transport    string `json:"transport"`
	Authorized   bool   `json:"authorized"`
	Availability string `json:"availability"`
	LatencyMS    int64  `json:"latency_ms,omitempty"`
}

type TrafficBucket struct {
	Device       string `json:"device"`
	LinkID       string `json:"link_id"`
	Hour         string `json:"hour"`
	TXBytes      uint64 `json:"tx_bytes"`
	RXBytes      uint64 `json:"rx_bytes"`
	ForwardBytes uint64 `json:"forward_bytes"`
}

type Path struct {
	CandidateID  string   `json:"candidate_id,omitempty"`
	Device       string   `json:"device"`
	Scope        string   `json:"scope,omitempty"`
	FinalExit    string   `json:"final_exit"`
	Chain        []string `json:"chain"`
	Selected     bool     `json:"selected"`
	Availability string   `json:"availability"`
}

type Service struct {
	ID       string   `json:"id"`
	Name     string   `json:"name"`
	Matchers []string `json:"matchers"`
	Policy   string   `json:"policy"`
}

type ServiceDelete struct {
	ID string `json:"id"`
}

type Release struct {
	Path         string       `json:"path"`
	Name         string       `json:"name"`
	Title        string       `json:"title"`
	Platform     string       `json:"platform"`
	Arch         string       `json:"arch"`
	Variant      string       `json:"variant"`
	Version      string       `json:"version"`
	SourceCommit string       `json:"source_commit"`
	SHA256       string       `json:"sha256"`
	Size         int64        `json:"size"`
	Signing      string       `json:"signing"`
	URL          string       `json:"url"`
	Checksum     *ReleaseFile `json:"checksum,omitempty"`
	Signature    *ReleaseFile `json:"signature,omitempty"`
	SBOM         *ReleaseFile `json:"sbom,omitempty"`
}

type ReleaseFile struct {
	Name   string `json:"name"`
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
	URL    string `json:"url"`
}

// Deployment is a read-only comparison between the signed publisher target
// and a device's independently signed application readback. It never grants
// authority and it is deliberately absent from Material.
type Deployment struct {
	Device           string `json:"device"`
	Generation       uint64 `json:"generation"`
	TargetSnapshot   string `json:"target_snapshot,omitempty"`
	AppliedSnapshot  string `json:"applied_snapshot,omitempty"`
	PublisherAt      string `json:"publisher_at"`
	DeviceReportedAt string `json:"device_reported_at,omitempty"`
	Stage            string `json:"stage"`
	Status           string `json:"status"`
	Detail           string `json:"detail"`
}

type PublisherStatus struct {
	ObservedAt      string `json:"observed_at"`
	IntervalSeconds int64  `json:"interval_seconds"`
	Generation      uint64 `json:"generation"`
	Snapshot        string `json:"snapshot"`
	Commit          string `json:"commit"`
	Binary          string `json:"binary,omitempty"`
	Status          string `json:"status"`
	Distribution    string `json:"distribution"`
}

type Event struct {
	ID      string `json:"id,omitempty"`
	At      string `json:"at"`
	Kind    string `json:"kind"`
	Subject string `json:"subject"`
	From    string `json:"from,omitempty"`
	To      string `json:"to,omitempty"`
	Detail  string `json:"detail"`
	Level   string `json:"level,omitempty"`
	Current bool   `json:"current"`
}

func ProjectionFromSSOT(body []byte, head CertifiedHead) (WebProjection, error) {
	ssot, err := model.Load(body)
	if err != nil {
		return WebProjection{}, err
	}
	if findings := validate.Validate(ssot); len(findings) != 0 {
		return WebProjection{}, fmt.Errorf("imported LKG is invalid: %s", validate.Format(findings))
	}
	projection := WebProjection{Schema: 1,
		UIState: UIState{Head: head.Hash, Revision: head.Revision, Writable: false,
			Warnings: []string{"Authority writes are unavailable until quorum governance is activated."}},
		Devices: []Device{}, Links: []Link{}, Paths: []Path{}, Services: []Service{}, Releases: []Release{}, Events: []Event{}}
	for _, node := range ssot.Nodes {
		roles := []string{}
		platform := ""
		if node.Access != nil {
			roles = append(roles, "access")
			platform = string(node.Access.Platform)
		}
		if node.Server != nil {
			roles = append(roles, "server")
		}
		name := node.Name
		if name == "" {
			name = node.ID
		}
		projection.Devices = append(projection.Devices, Device{ID: node.ID, Name: name, Platform: platform,
			Roles: roles, Authorized: !node.Decommission, Availability: "unknown"})
	}
	for _, tunnel := range ssot.Tunnels {
		projection.Links = append(projection.Links, Link{From: tunnel.From, To: tunnel.To,
			Transport: string(tunnel.Protocol), Authorized: true, Availability: "unknown"})
	}
	for _, service := range ssot.Services {
		name := service.Name
		if name == "" {
			name = service.ID
		}
		projection.Services = append(projection.Services, Service{ID: service.ID, Name: name,
			Matchers: append([]string(nil), service.Addresses...), Policy: service.Declaration})
	}
	sort.Slice(projection.Devices, func(i, j int) bool { return projection.Devices[i].ID < projection.Devices[j].ID })
	sort.Slice(projection.Links, func(i, j int) bool {
		return projection.Links[i].From+"\x00"+projection.Links[i].To < projection.Links[j].From+"\x00"+projection.Links[j].To
	})
	sort.Slice(projection.Services, func(i, j int) bool { return projection.Services[i].ID < projection.Services[j].ID })
	return projection, nil
}

func LoadState(path string) (State, error) {
	var state State
	info, err := os.Lstat(path)
	if err != nil {
		return state, err
	}
	if !controlPrivateRegular(info) {
		return state, errors.New("control state must be an owner-only regular file")
	}
	body, err := os.ReadFile(path)
	if err != nil {
		return state, err
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&state); err != nil {
		return State{}, err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return State{}, errors.New("control state has trailing content")
	}
	if err := state.Validate(); err != nil {
		return State{}, err
	}
	return state, nil
}

func SaveState(path string, state State) error {
	if err := state.Validate(); err != nil {
		return err
	}
	body, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}
	body = append(body, '\n')
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	file, err := os.CreateTemp(dir, ".state-*")
	if err != nil {
		return err
	}
	temporary := file.Name()
	defer os.Remove(temporary)
	if err = file.Chmod(0o600); err == nil {
		_, err = file.Write(body)
	}
	if err == nil {
		err = file.Sync()
	}
	closeErr := file.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	if err := replaceControlFile(temporary, path); err != nil {
		return err
	}
	return syncControlDirectory(dir)
}

func (state State) Validate() error {
	if state.Schema != StateSchema || state.ClusterID == "" || state.Listen == "" || !state.Recovery.V2Latch ||
		state.Head.Hash == "" || state.Head.Index < 1 || state.Head.Revision != state.Head.Index || state.Projection.Schema != 1 ||
		state.Projection.UIState.Head != state.Head.Hash || state.Projection.UIState.Revision != state.Head.Revision || state.Projection.UIState.Writable ||
		state.BrowserTLS.CertificateChainPEM == "" || state.BrowserTLS.PrivateKeyPKCS8PEM == "" ||
		state.BrowserTLS.RootPrivateKeyPKCS8PEM == "" || len(state.ReadCertDER) == 0 || len(state.AdminCertDER) == 0 {
		return errors.New("minimal control state is incomplete")
	}
	floor := state.Recovery.ReleaseFloor
	if floor.Schema != releasefloor.CurrentSchema || floor.Generation == 0 || len(floor.PayloadSHA256) != 64 ||
		len(floor.SelectedSnapshot) != 12 {
		return errors.New("minimal control release floor is invalid")
	}
	if _, err := hex.DecodeString(floor.PayloadSHA256); err != nil {
		return errors.New("minimal control release floor is invalid")
	}
	if _, err := hex.DecodeString(floor.SelectedSnapshot); err != nil {
		return errors.New("minimal control release floor is invalid")
	}
	for _, digest := range []string{state.Recovery.ConfigSHA256, state.Recovery.CertifiedSHA256,
		state.Recovery.OperationsSHA256, state.Recovery.ReleaseFloorSHA256} {
		if len(digest) != 64 {
			return errors.New("minimal control recovery digest is invalid")
		}
		if _, err := hex.DecodeString(digest); err != nil {
			return errors.New("minimal control recovery digest is invalid")
		}
	}
	return nil
}

func SHA256(body []byte) string {
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:])
}

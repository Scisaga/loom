// Package control implements the single signed-fact authority. These values
// are public UI projections and never persistence or authority inputs.
package control

type Device struct {
	ExpectedComponents []ComponentReadback `json:"expected_components"`
	ExpectedReferences []ExpectedComponent `json:"expected_component_references"`
	ComponentError     string              `json:"component_error,omitempty"`

	PolicyIDs           []string        `json:"policy_ids"`
	DistributionURLs    []string        `json:"distribution_urls"`
	DNSServers          []string        `json:"dns_servers"`
	Dependencies        []string        `json:"dependencies"`
	Conflicted          bool            `json:"conflicted"`
	Deleted             bool            `json:"deleted"`
	ID                  string          `json:"id"`
	Name                string          `json:"name"`
	Platform            string          `json:"platform,omitempty"`
	Roles               []string        `json:"roles"`
	Endpoint            string          `json:"endpoint,omitempty"`
	Authorized          bool            `json:"authorized"`
	Availability        string          `json:"availability"`
	EnrollmentID        string          `json:"enrollment_id,omitempty"`
	Enrollment          string          `json:"enrollment,omitempty"`
	EnrollmentReadiness string          `json:"enrollment_readiness,omitempty"`
	WaitingFor          []string        `json:"waiting_for,omitempty"`
	ViewDigest          string          `json:"view_digest,omitempty"`
	Presence            string          `json:"presence,omitempty"`
	RuntimeState        string          `json:"runtime_state,omitempty"`
	Components          string          `json:"components,omitempty"`
	Deployment          string          `json:"deployment,omitempty"`
	LastReportAt        string          `json:"last_report_at,omitempty"`
	Direction           string          `json:"direction,omitempty"`
	EgressCapable       bool            `json:"egress_capable,omitempty"`
	Location            string          `json:"location,omitempty"`
	Evidence            *DeviceEvidence `json:"evidence,omitempty"`
}

type DeviceEvidence struct {
	ReportedAt   string              `json:"reported_at"`
	ViewDigest   string              `json:"view_digest"`
	Selections   []ReportSelection   `json:"selections,omitempty"`
	Runtime      *RuntimeReadback    `json:"runtime,omitempty"`
	Components   []ComponentReadback `json:"components,omitempty"`
	Measurements []Observation       `json:"measurements,omitempty"`
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

type Release struct {
	CatalogDigest  string              `json:"catalog_digest"`
	ManifestDigest string              `json:"manifest_digest"`
	Components     []ComponentReadback `json:"components"`

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

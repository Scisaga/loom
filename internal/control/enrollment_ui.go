package control

import (
	"fmt"
	"net/http"
	"sort"
	"time"

	"github.com/skip2/go-qrcode"
)

type enrollmentPlatformOption struct {
	ID                   string   `json:"id"`
	Responsibilities     []string `json:"responsibilities"`
	RequiredServerFields []string `json:"required_server_fields,omitempty"`
	DisabledReason       string   `json:"disabled_reason,omitempty"`
}

func (server *Server) inviteValue(request *http.Request) (EnrollmentOpen, string, error) {
	if !server.admin(request) {
		return EnrollmentOpen{}, "", fmt.Errorf("administrator certificate required")
	}
	open, err := server.Runtime.Authority.EnrollmentOpen(request.PathValue("transaction"))
	if err != nil {
		return EnrollmentOpen{}, "", err
	}
	invite, err := EncodeInvite(BootstrapInvite{Schema: enrollmentSchema, Capability: open.Capability})
	return open, invite, err
}

type enrollmentGrantOption struct {
	ID              string   `json:"id"`
	Name            string   `json:"name"`
	CoveredServices []string `json:"covered_services"`
	DisabledReason  string   `json:"disabled_reason,omitempty"`
}

func (server *Server) enrollmentOptions(writer http.ResponseWriter, request *http.Request) {
	_, projection, certified := server.Runtime.Authority.Snapshot()
	platforms := []enrollmentPlatformOption{
		{ID: "android", Responsibilities: []string{"use_loom"}},
		{ID: "linux", Responsibilities: []string{"forward", "internet_egress", "use_loom"},
			RequiredServerFields: []string{"public_endpoint", "inbound_port", "inbound_protocol", "wg_public_key"}},
		{ID: "windows", Responsibilities: []string{"use_loom"}},
	}
	grants := []enrollmentGrantOption{}
	if projection.NetworkIntent == nil {
		for index := range platforms {
			platforms[index].DisabledReason = "Network intent has not been imported."
		}
	} else {
		for _, policy := range projection.NetworkIntent.Policies {
			services := []string{}
			for _, service := range projection.NetworkIntent.Services {
				if service.Policy == policy.ID {
					services = append(services, service.ID)
				}
			}
			sort.Strings(services)
			option := enrollmentGrantOption{ID: policy.ID, Name: policy.Name, CoveredServices: services}
			if !policy.AllowDirect && len(policy.AllowedExits) == 0 {
				option.DisabledReason = "Policy has no authorized route."
			}
			grants = append(grants, option)
		}
	}
	writeJSON(writer, http.StatusOK, map[string]any{
		"schema": 2, "head": HeadID(certified.Head), "platforms": platforms, "grants": grants,
		"directions":         []string{"bidirectional", "direct_only", "reverse_only"},
		"expires_in_seconds": 900,
	})
}

func (server *Server) inviteReadback(writer http.ResponseWriter, request *http.Request) {
	transactionID := request.PathValue("transaction")
	open, invite, err := server.inviteValue(request)
	if err != nil {
		http.Error(writer, "invite readback unavailable", http.StatusForbidden)
		return
	}
	_, projection, _ := server.Runtime.Authority.Snapshot()
	_, transaction := findEnrollment(&projection, transactionID)
	if transaction == nil {
		http.NotFound(writer, request)
		return
	}
	readiness, waiting := "awaiting_claim", []string{}
	if snapshot, snapshotErr := server.snapshotValue(request); snapshotErr == nil {
		for _, device := range snapshot.Devices {
			if device.EnrollmentID == transactionID {
				readiness, waiting = device.EnrollmentReadiness, append([]string(nil), device.WaitingFor...)
				break
			}
		}
	}
	writeJSON(writer, http.StatusOK, map[string]any{
		"schema": 2, "transaction": transaction, "invite": invite,
		"expires_at": open.Capability.ExpiresAt, "readiness": readiness, "waiting_for": waiting,
	})
}

// projectEnrollmentReadiness is a disposable UI projection. Completion of the
// enrollment Material proves authorization only; it does not prove that the
// device and every server whose users/ACL changed have consumed the resulting
// exact DeviceView. Only fresh signed schema-2 runtime readback can advance the
// product state to ready.
func projectEnrollmentReadiness(web *WebProjection, authority Projection, reports []DeviceReport, now time.Time) {
	if web == nil {
		return
	}
	latest := map[string]DeviceReport{}
	for _, report := range reports {
		reportedAt, err := time.Parse(time.RFC3339, report.ReportedAt)
		if err != nil || now.Before(reportedAt) || now.Sub(reportedAt) > 3*time.Minute {
			continue
		}
		previous, found := latest[report.DeviceID]
		if !found || previous.ReportedAt < report.ReportedAt {
			latest[report.DeviceID] = report
		}
	}
	exact := func(deviceID string) bool {
		report, found := latest[deviceID]
		if !found || report.Schema != enrollmentSchemaV2 || report.Runtime == nil ||
			report.Runtime.State != "running" || !report.Runtime.Exact {
			return false
		}
		view, found := projectDeviceView(authority, deviceID)
		if !found {
			return false
		}
		digest, err := DeviceViewDigest(view)
		return err == nil && report.ViewDigest == digest && report.Runtime.AppliedViewDigest == digest
	}
	for index := range web.Devices {
		device := &web.Devices[index]
		if device.EnrollmentID == "" {
			continue
		}
		switch device.Enrollment {
		case "open":
			device.EnrollmentReadiness = "awaiting_claim"
		case "bound":
			device.EnrollmentReadiness = "awaiting_approval"
		case "completed":
			authorization, found := authorizationFor(authority, device.ID)
			if !found || authorization.Schema != enrollmentSchemaV2 {
				device.EnrollmentReadiness = "awaiting_deployment"
				device.WaitingFor = []string{device.ID}
				continue
			}
			dependencies := map[string]bool{device.ID: true}
			routes, _, err := projectAuthorizationRuntime(authority, authorization)
			if err != nil {
				device.EnrollmentReadiness = "awaiting_deployment"
				device.WaitingFor = []string{device.ID}
				continue
			}
			for _, route := range routes {
				for _, serverID := range route.Chain {
					dependencies[serverID] = true
				}
			}
			waiting := make([]string, 0, len(dependencies))
			for deviceID := range dependencies {
				if !exact(deviceID) {
					waiting = append(waiting, deviceID)
				}
			}
			sort.Strings(waiting)
			device.WaitingFor = waiting
			if len(waiting) == 0 {
				device.EnrollmentReadiness = "ready"
			} else {
				device.EnrollmentReadiness = "awaiting_deployment"
			}
		default:
			device.EnrollmentReadiness = "unknown"
		}
	}
}

func (server *Server) inviteQR(writer http.ResponseWriter, request *http.Request) {
	_, invite, err := server.inviteValue(request)
	if err != nil {
		http.Error(writer, "invite unavailable", http.StatusForbidden)
		return
	}
	png, err := qrcode.Encode(invite, qrcode.Medium, 384)
	if err != nil {
		http.Error(writer, "invite QR unavailable", http.StatusServiceUnavailable)
		return
	}
	writer.Header().Set("Content-Type", "image/png")
	writer.Header().Set("Content-Disposition", "inline; filename=loom-enrollment.png")
	writer.WriteHeader(http.StatusOK)
	_, _ = writer.Write(png)
}

func (server *Server) inviteDownload(writer http.ResponseWriter, request *http.Request) {
	open, invite, err := server.inviteValue(request)
	if err != nil {
		http.Error(writer, "invite unavailable", http.StatusForbidden)
		return
	}
	writer.Header().Set("Content-Type", "text/plain; charset=utf-8")
	writer.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=loom-enrollment-%s.txt", open.TransactionID))
	writer.WriteHeader(http.StatusOK)
	_, _ = writer.Write([]byte(invite + "\n"))
}

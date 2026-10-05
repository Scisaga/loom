package control

import (
	"errors"
	"net/http"
	"time"

	"github.com/skip2/go-qrcode"
)

type enrollmentPlatformOption struct {
	ID               string   `json:"id"`
	Responsibilities []string `json:"responsibilities"`
}
type enrollmentPolicyOption struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	ServiceID string `json:"service_id"`
	Action    string `json:"action"`
}

func (server *Server) enrollmentOptions(w http.ResponseWriter, r *http.Request) {
	projection := server.Runtime.Authority.Snapshot()
	policies := []enrollmentPolicyOption{}
	for _, policy := range projection.NetworkIntent.Policies {
		for _, service := range projection.NetworkIntent.Services {
			if service.ID == policy.ServiceID {
				policies = append(policies, enrollmentPolicyOption{ID: policy.ID, Name: policy.Name, ServiceID: policy.ServiceID, Action: policy.Action})
				break
			}
		}
	}
	endpoints := []EndpointGeneration{}
	for _, endpoint := range projection.EndpointGenerations {
		if endpoint.OwnerControlID == server.Runtime.Config.ControlID && endpoint.State == "serving" && containsString(endpoint.Modes, "bootstrap") {
			endpoints = append(endpoints, endpoint)
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"schema": 3, "genesis_digest": server.Runtime.Config.GenesisID, "issuer_control_id": server.Runtime.Config.ControlID, "platforms": []enrollmentPlatformOption{
		{ID: "android", Responsibilities: []string{"access"}}, {ID: "linux", Responsibilities: []string{"access", "control", "forward", "internet_egress"}}, {ID: "windows", Responsibilities: []string{"access"}},
	}, "policies": policies, "endpoints": endpoints, "targets": projection.Targets})
}

// Re-displaying an open Invite uses the same persisted signed Material. A
// completed or terminated transaction cannot issue a fresh-looking QR code.
func (server *Server) inviteValue(r *http.Request) (Invite, string, error) {
	if !server.admin(r) {
		return Invite{}, "", errors.New("administrator certificate required")
	}
	transactionID := r.PathValue("transaction")
	state, err := server.Runtime.Authority.EnrollmentState(transactionID)
	if err != nil {
		return Invite{}, "", err
	}
	bootstrap, err := server.bootstrapInvite(transactionID)
	if err != nil {
		return Invite{}, "", err
	}
	invite := bootstrap.Material.Payload.(Invite)
	if state != "open" || !server.now().Before(time.UnixMilli(invite.ExpiresAt)) {
		return Invite{}, "", errors.New("invite is not open for a new claim")
	}
	encoded, err := EncodeInvite(bootstrap)
	return invite, encoded, err
}
func (server *Server) inviteReadback(w http.ResponseWriter, r *http.Request) {
	transactionID := r.PathValue("transaction")
	material, err := server.Runtime.Authority.Invite(transactionID)
	if err != nil {
		http.Error(w, "invite readback unavailable", http.StatusNotFound)
		return
	}
	state, err := server.Runtime.Authority.EnrollmentState(transactionID)
	if err != nil {
		http.Error(w, "invite state unavailable", http.StatusConflict)
		return
	}
	value := material.Payload.(Invite)
	encoded := ""
	if state == "open" && server.now().Before(time.UnixMilli(value.ExpiresAt)) {
		_, encoded, err = server.inviteValue(r)
		if err != nil {
			http.Error(w, "invite readback unavailable", http.StatusConflict)
			return
		}
	}
	id, _ := MaterialID(material)
	command, deliveryError := "", ""
	qrAvailable := false
	if encoded != "" && value.Medium == "qr" {
		_, qrErr := inviteQRCode(encoded)
		qrAvailable = qrErr == nil
		if qrErr != nil {
			deliveryError = "This invitation is too large for one QR code. Copy or download the complete invitation."
		}
	}
	if encoded != "" && value.Medium == "sh" {
		command, err = server.shellInviteBlock(r.Context(), encoded)
		if err != nil {
			deliveryError = "The signed installer is not available from an authenticated public distribution URL."
		}
		// A download check may overlap completion, revocation or expiry. Do not
		// hand out a stale command after that real transaction has closed.
		if _, current, checkErr := server.inviteValue(r); checkErr != nil || current != encoded {
			encoded, command, deliveryError = "", "", ""
			if latest, checkErr := server.Runtime.Authority.EnrollmentState(transactionID); checkErr == nil {
				state = latest
			}
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"schema": 3, "transaction": value, "state": state, "material_id": id, "invite": encoded, "expires_at": value.ExpiresAt, "shell_command": command, "qr_available": qrAvailable, "delivery_error": deliveryError})
}

// QR correction levels are image encoding choices. Every image contains the
// identical canonical Invite, including its full signed member proof.
func inviteQRCode(invite string) (*qrcode.QRCode, error) {
	code, err := qrcode.New(invite, qrcode.Medium)
	if err != nil {
		return qrcode.New(invite, qrcode.Low)
	}
	return code, nil
}

func (server *Server) inviteQR(w http.ResponseWriter, r *http.Request) {
	value, invite, err := server.inviteValue(r)
	if err != nil || value.Medium != "qr" {
		http.Error(w, "QR invite unavailable", http.StatusForbidden)
		return
	}
	code, err := inviteQRCode(invite)
	if err != nil {
		http.Error(w, "invite exceeds QR capacity; copy or download the complete invitation", http.StatusUnprocessableEntity)
		return
	}
	png, err := code.PNG(-5)
	if err != nil {
		http.Error(w, "invite QR unavailable", http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Content-Type", "image/png")
	w.Header().Set("Content-Disposition", "inline; filename=loom-enrollment.png")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(png)
}
func (server *Server) inviteDownload(w http.ResponseWriter, r *http.Request) {
	_, invite, err := server.inviteValue(r)
	if err != nil {
		http.Error(w, "invite unavailable", http.StatusForbidden)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Content-Disposition", "attachment; filename=loom-enrollment.txt")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(invite + "\n"))
}

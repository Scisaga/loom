package control

import (
	"errors"
	"net/http"
	"time"

	"github.com/makiuchi-d/gozxing"
	zxingqr "github.com/makiuchi-d/gozxing/qrcode"
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
	sshTargets := []string{}
	if server.SSH != nil {
		if values, err := server.SSH.Targets(); err == nil {
			sshTargets = values
		}
	}
	for _, endpoint := range projection.EndpointGenerations {
		if endpoint.OwnerControlID == server.Runtime.Config.ControlID && endpoint.State == "serving" && containsString(endpoint.Modes, "bootstrap") {
			endpoints = append(endpoints, endpoint)
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"schema": 3, "genesis_digest": server.Runtime.Config.GenesisID, "issuer_control_id": server.Runtime.Config.ControlID, "platforms": []enrollmentPlatformOption{
		{ID: "android", Responsibilities: []string{"access"}}, {ID: "linux", Responsibilities: []string{"access", "control", "forward", "internet_egress"}}, {ID: "windows", Responsibilities: []string{"access"}},
	}, "policies": policies, "endpoints": endpoints, "targets": projection.Targets, "ssh_targets": sshTargets})
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
	authority := server.Runtime.Authority
	authority.mu.RLock()
	material, err := authority.inviteOriginalLocked(transactionID)
	state, stateErr := authority.enrollmentStateLocked(transactionID)
	target, _ := authority.projection.CurrentTarget("invite", transactionID)
	memberEnrollment := err == nil && authority.memberEnrollmentLocked(material)
	if stateErr != nil && target.Conflicted {
		state, stateErr = "conflicted", nil
		if _, bound, bindingErr := authority.bindingLocked(transactionID); memberEnrollment && bound && bindingErr == nil {
			state = "bound"
		}
	}
	authority.mu.RUnlock()
	if err != nil {
		http.Error(w, "invite readback unavailable", http.StatusNotFound)
		return
	}
	if stateErr != nil {
		http.Error(w, "invite state unavailable", http.StatusConflict)
		return
	}
	value := material.Payload.(Invite)
	encoded := ""
	if state == "open" && !target.Conflicted && server.now().Before(time.UnixMilli(value.ExpiresAt)) {
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
			deliveryError = "A readable QR could not be generated. Copy or download the complete invitation."
			if errors.Is(qrErr, errInviteQRCapacity) {
				deliveryError = "This invitation is too large for one QR code. Copy or download the complete invitation."
			}
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
	response := map[string]any{"schema": 3, "transaction": value, "state": state, "material_id": id, "invite": encoded, "expires_at": value.ExpiresAt, "shell_command": command, "qr_available": qrAvailable, "delivery_error": deliveryError}
	response["member_enrollment"], response["identity_conflicted"] = memberEnrollment, target.Conflicted
	if value.Medium == "ssh" {
		response["ssh_execution"] = server.sshObservation(value.ID, value.SSHTarget)
		_, _, err := server.sshInvite(value.ID)
		response["ssh_executable"] = err == nil && server.SSH != nil
	}
	writeJSON(w, http.StatusOK, response)
}

var errInviteQRCapacity = errors.New("invite exceeds single QR capacity")

// QR sizes and correction levels are image encoding choices. Dense content can
// resemble extra finder patterns, so capacity alone does not prove readability.
// Choose deterministically using an independent client decoder, preserving every
// byte of the same canonical Invite and its complete signed member proof.
func inviteQRCode(invite string) (*qrcode.QRCode, error) {
	fits := false
	for _, level := range []qrcode.RecoveryLevel{qrcode.Medium, qrcode.Low} {
		code, err := qrcode.New(invite, level)
		if err != nil {
			continue
		}
		fits = true
		for size := code.VersionNumber; size <= 40; size++ {
			candidate, err := qrcode.NewWithForcedVersion(invite, size, level)
			if err != nil {
				return nil, err
			}
			bitmap, err := gozxing.NewBinaryBitmapFromImage(candidate.Image(-5))
			if err != nil {
				return nil, err
			}
			decoded, err := zxingqr.NewQRCodeReader().Decode(bitmap, map[gozxing.DecodeHintType]interface{}{gozxing.DecodeHintType_TRY_HARDER: true})
			if err == nil && decoded.GetText() == invite {
				return candidate, nil
			}
		}
	}
	if !fits {
		return nil, errInviteQRCapacity
	}
	return nil, errors.New("no single QR image passed independent client decoding")
}

func (server *Server) inviteQR(w http.ResponseWriter, r *http.Request) {
	value, invite, err := server.inviteValue(r)
	if err != nil || value.Medium != "qr" {
		http.Error(w, "QR invite unavailable", http.StatusForbidden)
		return
	}
	code, err := inviteQRCode(invite)
	if err != nil {
		http.Error(w, "a readable QR is unavailable; copy or download the complete invitation", http.StatusUnprocessableEntity)
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

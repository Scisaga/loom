package control

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"time"
)

// SSHExecutor is a transport adapter over explicitly selected operator inputs.
// Only the control's verified generic installer and original Invite reach Run.
type SSHExecutor interface {
	Targets() ([]string, error)
	Resolve(context.Context, string) (SSHTargetReadback, error)
	Run(context.Context, string, string) ([]byte, error)
}

type SSHTargetReadback struct {
	Alias             string `json:"alias"`
	Local             bool   `json:"local"`
	ConfiguredHost    string `json:"configured_host"`
	ConfiguredPort    int    `json:"configured_port"`
	ResolvedHost      string `json:"resolved_host"`
	ResolvedPort      int    `json:"resolved_port"`
	CoordinatesDiffer bool   `json:"coordinates_differ"`
}

type SSHInspection struct {
	Target       SSHTargetReadback    `json:"target"`
	Installation InstallationReadback `json:"installation"`
}

// SSHExecution is disposable process observation, keyed by the existing Invite.
// It is never persisted, replicated, or used to decide device authorization.
type SSHExecution struct {
	Target     string         `json:"target"`
	State      string         `json:"state"`
	ErrorCode  string         `json:"error_code,omitempty"`
	ExitCode   int            `json:"exit_code,omitempty"`
	Inspection *SSHInspection `json:"inspection,omitempty"`
}

type sshCheckRequest struct {
	Target           string   `json:"target"`
	Responsibilities []string `json:"responsibilities"`
}

func (request sshCheckRequest) Validate() error {
	if ValidateSSHTarget(request.Target) != nil || len(request.Responsibilities) == 0 || validateResponsibilities(request.Responsibilities, true) != nil || len(request.Responsibilities) == 1 && request.Responsibilities[0] == "access" {
		return errors.New("SSH requires a configured target and server responsibilities")
	}
	return nil
}

func (server *Server) inspectSSHTarget(ctx context.Context, target string, bases []string, artifact ReleaseArtifact) (SSHInspection, error) {
	var result SSHInspection
	if server.SSH == nil {
		return result, errors.New("ssh_executor_unavailable")
	}
	resolved, err := server.SSH.Resolve(ctx, target)
	if err != nil {
		return result, err
	}
	result.Target = resolved
	script, err := SSHInspectionDelivery(bases, artifact)
	if err != nil {
		return result, errors.New("verified_installer_unavailable")
	}
	body, err := server.SSH.Run(ctx, target, script)
	if err != nil {
		return result, err
	}
	// The inspector emits exactly one canonical value and a final newline.
	if len(body) == 0 || body[len(body)-1] != '\n' || DecodeCanonical(bytes.TrimSuffix(body, []byte{'\n'}), &result.Installation, ContractDecodeLimits{MaxBytes: 64 << 10, MaxDepth: 8, MaxItems: 128}) != nil {
		return result, errors.New("target_inspection_invalid")
	}
	return result, nil
}

func (server *Server) checkNewSSHTarget(ctx context.Context, target string) (SSHInspection, error) {
	ctx, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()
	bases, artifact, err := server.verifiedBootstrap(ctx)
	if err != nil {
		return SSHInspection{}, errors.New("verified_installer_unavailable")
	}
	return server.inspectSSHTarget(ctx, target, bases, artifact)
}

func (server *Server) sshAdminMutation(w http.ResponseWriter, r *http.Request) bool {
	if !server.admin(r) {
		http.Error(w, "administrator certificate required", http.StatusForbidden)
		return false
	}
	if origin := r.Header.Get("Origin"); !localAdmin(r) && origin != "" && origin != "https://"+r.Host {
		http.Error(w, "same-origin request required", http.StatusForbidden)
		return false
	}
	return true
}

func (server *Server) sshPreflight(w http.ResponseWriter, r *http.Request) {
	if !server.sshAdminMutation(w, r) {
		return
	}
	body, err := boundedBody(w, r)
	var request sshCheckRequest
	if err != nil || DecodeCanonical(body, &request, ContractDecodeLimits{MaxBytes: 4096, MaxDepth: 4, MaxItems: 16}) != nil {
		http.Error(w, "invalid SSH target check", http.StatusBadRequest)
		return
	}
	result, err := server.checkNewSSHTarget(r.Context(), request.Target)
	if err != nil {
		http.Error(w, sshErrorCode(err), http.StatusUnprocessableEntity)
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func sshErrorCode(err error) string {
	var failure interface{ SSHFailure() (string, int) }
	if errors.As(err, &failure) {
		code, _ := failure.SSHFailure()
		return code
	}
	// Internal adapter errors are deliberately not echoed; operator inputs and
	// remote banners must never become a public error/log transport.
	switch err.Error() {
	case "ssh_executor_unavailable", "verified_installer_unavailable", "target_inspection_invalid", "existing_device_identity", "existing_installation_unverified", "enrollment_identity_differs", "enrollment_identity_missing", "enrollment_not_executable", "enrollment_binding_differs", "device_no_longer_authorized":
		return err.Error()
	default:
		return "ssh_target_check_failed"
	}
}

func (server *Server) sshInvite(transaction string) (BootstrapInvite, string, error) {
	invite, err := server.bootstrapInvite(transaction)
	if err != nil {
		return invite, "", errors.New("enrollment_not_executable")
	}
	value := invite.Material.Payload.(Invite)
	state, err := server.Runtime.Authority.EnrollmentState(transaction)
	if err != nil || value.Medium != "ssh" || value.SSHTarget == "" || value.IssuerControlID != server.Config.ControlID || state != "open" && state != "bound" && state != "completed" || state == "open" && !server.now().Before(time.UnixMilli(value.ExpiresAt)) {
		return invite, state, errors.New("enrollment_not_executable")
	}
	if state == "completed" {
		found := false
		projection := server.Runtime.Authority.Snapshot()
		for _, authorization := range projection.DeviceAuthorizations {
			if authorization.ID == value.DeviceID && authorization.TransactionID == value.ID {
				current, ok := projection.CurrentTarget("device", value.DeviceID)
				found = ok && !current.Conflicted && !current.Deleted && len(current.MaterialIDs) == 1
			}
		}
		if !found {
			return invite, state, errors.New("device_no_longer_authorized")
		}
	}
	return invite, state, nil
}

func (server *Server) checkSSHIdentity(invite BootstrapInvite, inspection InstallationReadback) error {
	if err := inspection.Validate(); err != nil {
		return errors.New("target_inspection_invalid")
	}
	value := invite.Material.Payload.(Invite)
	_, state, err := server.sshInvite(value.ID)
	if err != nil {
		return err
	}
	binding, bound, err := server.Runtime.Authority.Binding(value.ID)
	if err != nil {
		return errors.New("enrollment_binding_differs")
	}
	identity := inspection.Identity
	if identity == nil {
		if bound || state != "open" {
			return errors.New("enrollment_identity_missing")
		}
	} else {
		id, _ := MaterialID(invite.Material)
		if identity.NetworkID != invite.NetworkID || identity.GenesisDigest != invite.GenesisDigest || identity.InviteMaterialID != id || identity.TransactionID != value.ID || identity.DeviceID != value.DeviceID || identity.Platform != "linux" {
			return errors.New("enrollment_identity_differs")
		}
		if bound && (identity.DevicePublicKey != binding.DevicePublicKey || identity.ClaimRequestID != binding.ClaimRequestID || identity.Platform != binding.Platform) {
			return errors.New("enrollment_binding_differs")
		}
	}
	if !inspection.CanInstall {
		return errors.New("existing_installation_unverified")
	}
	return nil
}

func (server *Server) startSSHWorkers(ctx context.Context) func() {
	server.sshMu.Lock()
	workerContext, cancel := context.WithCancel(ctx)
	server.sshContext = workerContext
	server.sshExecutions = map[string]SSHExecution{}
	server.sshMu.Unlock()
	return func() {
		server.sshMu.Lock()
		server.sshContext = nil
		cancel()
		server.sshMu.Unlock()
		server.sshWorkers.Wait()
	}
}

func (server *Server) sshObservation(transaction, target string) SSHExecution {
	server.sshMu.Lock()
	defer server.sshMu.Unlock()
	if value, ok := server.sshExecutions[transaction]; ok {
		return value
	}
	return SSHExecution{Target: target, State: "unknown"}
}

func (server *Server) startSSHInstallation(transaction string) (SSHExecution, error) {
	invite, _, err := server.sshInvite(transaction)
	if err != nil {
		return SSHExecution{}, err
	}
	value := invite.Material.Payload.(Invite)
	server.sshMu.Lock()
	defer server.sshMu.Unlock()
	if server.SSH == nil || server.sshContext == nil || server.sshContext.Err() != nil {
		return SSHExecution{}, errors.New("ssh_executor_unavailable")
	}
	if previous, ok := server.sshExecutions[transaction]; ok && (previous.State == "running" || previous.State == "succeeded") {
		return previous, nil
	}
	for _, current := range server.sshExecutions {
		if current.Target == value.SSHTarget && current.State == "running" {
			return SSHExecution{}, errors.New("another SSH execution is using this target")
		}
	}
	observation := SSHExecution{Target: value.SSHTarget, State: "running"}
	server.sshExecutions[transaction] = observation
	server.sshWorkers.Add(1)
	go server.executeSSH(server.sshContext, invite, observation)
	return observation, nil
}

func (server *Server) executeSSH(ctx context.Context, invite BootstrapInvite, observation SSHExecution) {
	defer server.sshWorkers.Done()
	ctx, cancel := context.WithTimeout(ctx, 15*time.Minute)
	defer cancel()
	value := invite.Material.Payload.(Invite)
	bases, artifact, err := server.verifiedBootstrap(ctx)
	observation.State = "failed"
	if err == nil {
		observation, err = server.installSSH(ctx, invite, bases, artifact)
	} else {
		err = errors.New("verified_installer_unavailable")
	}
	if err != nil {
		observation.ErrorCode = sshErrorCode(err)
		var failure interface{ SSHFailure() (string, int) }
		if errors.As(err, &failure) {
			observation.ErrorCode, observation.ExitCode = failure.SSHFailure()
			if observation.ErrorCode == "connection_interrupted" || observation.ErrorCode == "connection_unconfirmed" || observation.ErrorCode == "readback_exceeds_limit" || observation.ErrorCode == "executor_unavailable" {
				observation.State = "unknown"
			}
		}
		if ctx.Err() != nil {
			observation.State, observation.ErrorCode = "unknown", "connection_interrupted"
		}
	}
	server.sshMu.Lock()
	server.sshExecutions[value.ID] = observation
	server.sshMu.Unlock()
}

// installSSH retains the last successful target inspection. Once the installer
// returns successfully, a failed final readback leaves the outcome unknown; it
// cannot retroactively assert that installation failed or erase an earlier read.
func (server *Server) installSSH(ctx context.Context, invite BootstrapInvite, bases []string, artifact ReleaseArtifact) (SSHExecution, error) {
	value := invite.Material.Payload.(Invite)
	observation := SSHExecution{Target: value.SSHTarget, State: "failed"}
	inspection, err := server.inspectSSHTarget(ctx, value.SSHTarget, bases, artifact)
	if err != nil {
		return observation, err
	}
	observation.Inspection = &inspection
	if err := server.checkSSHIdentity(invite, inspection.Installation); err != nil {
		return observation, err
	}
	encoded, err := EncodeInvite(invite)
	if err != nil {
		return observation, err
	}
	script, err := SSHInviteDelivery(bases, artifact, encoded)
	if err != nil {
		return observation, err
	}
	if _, err = server.SSH.Run(ctx, value.SSHTarget, script); err != nil {
		return observation, err
	}
	observation.State = "unknown"
	after, err := server.inspectSSHTarget(ctx, value.SSHTarget, bases, artifact)
	if err != nil {
		return observation, err
	}
	observation.Inspection = &after
	if after.Installation.Identity == nil || !after.Installation.Identity.Joined {
		return observation, errors.New("enrollment_identity_missing")
	}
	if err := server.checkSSHIdentity(invite, after.Installation); err != nil {
		return observation, err
	}
	observation.State = "succeeded"
	return observation, nil
}

func (server *Server) sshExecute(w http.ResponseWriter, r *http.Request) {
	if !server.sshAdminMutation(w, r) {
		return
	}
	// No request-supplied command, target override, or Invite is executable.
	body, err := boundedBody(w, r)
	if err != nil || len(body) != 0 {
		http.Error(w, "SSH execution does not accept a body", http.StatusBadRequest)
		return
	}
	value, err := server.startSSHInstallation(r.PathValue("transaction"))
	if err != nil {
		http.Error(w, sshErrorCode(err), http.StatusConflict)
		return
	}
	writeJSON(w, http.StatusAccepted, value)
}

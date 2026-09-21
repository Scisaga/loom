//go:build !windows

package control

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"time"

	"loom/internal/clientrelease"
	"loom/internal/publish"
)

func (server *Server) verifiedPublisherObservation() (*publish.PublisherObservation, []byte, error) {
	if server.PublisherObservationPath == "" {
		return nil, nil, errors.New("publisher observation path is unavailable")
	}
	body, err := os.ReadFile(server.PublisherObservationPath)
	if err != nil {
		return nil, nil, err
	}
	observation, err := publish.DecodePublisherObservation(body)
	if err != nil {
		return nil, nil, err
	}
	key, err := clientrelease.PublicKey(server.ReleaseKey)
	if err != nil || observation.Verify(key) != nil {
		return nil, nil, errors.New("publisher observation authentication failed")
	}
	return observation, body, nil
}

func (server *Server) registerPublisherRoutes(mux *http.ServeMux) {
	mux.HandleFunc("POST /internal/publisher-observation", server.internalPublisherObservation)
	mux.HandleFunc("PUT /internal/publisher-observation", server.internalPublisherObservation)
}

func (server *Server) internalPublisherObservation(writer http.ResponseWriter, request *http.Request) {
	body, ok := server.internalBody(writer, request)
	if !ok {
		return
	}
	if request.Method == http.MethodPost {
		_, current, err := server.verifiedPublisherObservation()
		if err != nil {
			http.Error(writer, "publisher observation unavailable", http.StatusServiceUnavailable)
			return
		}
		writer.Header().Set("Content-Type", "application/json")
		_, _ = writer.Write(current)
		return
	}
	incoming, err := publish.DecodePublisherObservation(body)
	key, keyErr := clientrelease.PublicKey(server.ReleaseKey)
	if err != nil || keyErr != nil || incoming.Verify(key) != nil {
		http.Error(writer, "publisher observation authentication failed", http.StatusConflict)
		return
	}
	current, currentBody, currentErr := server.verifiedPublisherObservation()
	if currentErr == nil {
		incomingAt, _ := time.Parse(time.RFC3339Nano, incoming.ObservedAt)
		currentAt, _ := time.Parse(time.RFC3339Nano, current.ObservedAt)
		if incomingAt.Before(currentAt) || incomingAt.Equal(currentAt) && !bytes.Equal(body, currentBody) {
			http.Error(writer, "publisher observation does not advance the authenticated cache", http.StatusConflict)
			return
		}
		if bytes.Equal(body, currentBody) {
			writer.WriteHeader(http.StatusOK)
			return
		}
	}
	if err := atomicWrite(server.PublisherObservationPath, body); err != nil {
		http.Error(writer, "publisher observation persistence failed", http.StatusServiceUnavailable)
		return
	}
	writer.WriteHeader(http.StatusOK)
}

func (server *Server) startPublisherSync(ctx context.Context) {
	if server.PublisherObservationPath != "" && server.ReleaseKey != "" {
		go server.syncPublisher(ctx)
	}
}

func (server *Server) syncPublisher(ctx context.Context) {
	interval := server.PublisherSyncInterval
	if interval <= 0 {
		interval = 30 * time.Second
	}
	server.syncPublisherOnce(ctx)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			server.syncPublisherOnce(ctx)
		}
	}
}

func (server *Server) syncPublisherOnce(ctx context.Context) {
	if server.Runtime == nil || server.Runtime.Channel == nil {
		return
	}
	local, localBody, localErr := server.verifiedPublisherObservation()
	_, _, certified := server.Runtime.Authority.Snapshot()
	for _, member := range uniqueMembers(certified.Projection.Config) {
		if member.ID == server.Config.MemberID {
			continue
		}
		var remoteBody json.RawMessage
		peerContext, cancel := context.WithTimeout(ctx, 5*time.Second)
		remoteErr := server.Runtime.peerJSON(peerContext, member, http.MethodPost, "/internal/publisher-observation", nil, &remoteBody)
		cancel()
		if remoteErr == nil {
			remote, decodeErr := publish.DecodePublisherObservation(remoteBody)
			key, keyErr := clientrelease.PublicKey(server.ReleaseKey)
			if decodeErr == nil && keyErr == nil && remote.Verify(key) == nil {
				remoteAt, _ := time.Parse(time.RFC3339Nano, remote.ObservedAt)
				localAt := time.Time{}
				if localErr == nil {
					localAt, _ = time.Parse(time.RFC3339Nano, local.ObservedAt)
				}
				if localErr != nil || remoteAt.After(localAt) {
					if atomicWrite(server.PublisherObservationPath, remoteBody) == nil {
						local, localBody, localErr = remote, append([]byte(nil), remoteBody...), nil
					}
				}
			}
		}
		if localErr == nil {
			peerContext, cancel = context.WithTimeout(ctx, 5*time.Second)
			_ = server.Runtime.peerJSON(peerContext, member, http.MethodPut, "/internal/publisher-observation", localBody, nil)
			cancel()
		}
	}
}

func (server *Server) projectDeployments(projection *WebProjection, reports []DeviceReport) error {
	observation, _, err := server.verifiedPublisherObservation()
	if err != nil {
		return err
	}
	observedAt, _ := time.Parse(time.RFC3339Nano, observation.ObservedAt)
	freshFor := 3 * time.Duration(observation.IntervalSeconds) * time.Second
	if freshFor < 3*time.Minute {
		freshFor = 3 * time.Minute
	}
	if server.now().Before(observedAt) || server.now().Sub(observedAt) > freshFor {
		return errors.New("publisher observation is stale")
	}
	payloadDigest, err := observation.Current.PayloadSHA256()
	if err != nil {
		return err
	}
	latest := make(map[string]DeviceReport, len(reports))
	for _, report := range reports {
		reportedAt, parseErr := time.Parse(time.RFC3339, report.ReportedAt)
		if parseErr != nil || server.now().Before(reportedAt) || server.now().Sub(reportedAt) > 3*time.Minute {
			continue
		}
		previous, found := latest[report.DeviceID]
		if !found || previous.ReportedAt < report.ReportedAt {
			latest[report.DeviceID] = report
		}
	}
	checksOK := observation.Success && len(observation.DistributionChecks) > 0
	for _, check := range observation.DistributionChecks {
		checksOK = checksOK && check.Success
	}
	distribution := "verified"
	if !checksOK {
		distribution = "incomplete"
	}
	projection.Publisher = &PublisherStatus{ObservedAt: observation.ObservedAt,
		IntervalSeconds: observation.IntervalSeconds, Generation: observation.Current.Generation,
		Snapshot: observation.Current.Snapshot, Commit: observation.Version.Commit,
		Binary: observation.Version.Binary, Status: map[bool]string{true: "healthy", false: "error"}[observation.Success],
		Distribution: distribution}
	projection.Deployments = make([]Deployment, 0, len(projection.Devices))
	for index := range projection.Devices {
		device := &projection.Devices[index]
		target, selectErr := observation.Current.Select(device.ID)
		state := Deployment{Device: device.ID, Generation: observation.Current.Generation,
			TargetSnapshot: target, PublisherAt: observation.ObservedAt, Stage: "signed",
			Status: "waiting", Detail: "signed deployment target has not been distributed"}
		if selectErr != nil {
			state.Stage, state.Status, state.Detail = "unknown", "unknown", "publisher target has no assignment for this device"
		} else if !checksOK {
			state.Status, state.Detail = "unknown", "publisher distribution verification is incomplete"
		} else {
			state.Stage, state.Detail = "distributed", "waiting for a current device readback"
		}
		if state.Stage == "distributed" {
			report, found := latest[device.ID]
			if !found || report.Deployment == nil {
				device.Deployment = state.Status
				projection.Deployments = append(projection.Deployments, state)
				continue
			}
			readback := report.Deployment
			state.DeviceReportedAt, state.AppliedSnapshot = report.ReportedAt, readback.AppliedSnapshot
			switch {
			case readback.Generation != observation.Current.Generation:
				state.Stage, state.Status, state.Detail = "unknown", "mismatch", "device generation does not match the publisher target"
			case readback.PayloadSHA256 != payloadDigest:
				state.Stage, state.Status, state.Detail = "unknown", "mismatch", "device payload digest does not match the signed pointer"
			case readback.SelectedSnapshot != target:
				state.Stage, state.Status, state.Detail = "unknown", "mismatch", "device selected a different snapshot"
			case readback.AppliedSnapshot != target:
				state.Stage, state.Status, state.Detail = "selected", "waiting", "signed target is selected but not applied"
			case !readback.RolloutVerified:
				state.Stage, state.Status, state.Detail = "applied", "waiting", "target is applied but the rollout is not verified"
			case report.Runtime == nil || report.Runtime.State != "running" || !report.Runtime.Exact:
				state.Stage, state.Status, state.Detail = "applied", "waiting", "device runtime has not read back the exact certified view"
			default:
				state.Stage, state.Status, state.Detail = "verified", "current", "signed target and device application readback match"
			}
		}
		device.Deployment = state.Status
		projection.Deployments = append(projection.Deployments, state)
	}
	return nil
}

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
	body, readErr := boundedBody(writer, request)
	if readErr != nil {
		http.Error(writer, "publisher observation exceeds entry-point bounds", http.StatusRequestEntityTooLarge)
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
	projection := server.Runtime.Authority.Snapshot()
	for _, member := range projection.Config.Members {
		if member.ControlID == server.Config.ControlID {
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

func (server *Server) projectDeployments(projection *WebSnapshot) error {
	observation, _, err := server.verifiedPublisherObservation()
	if err != nil {
		return err
	}
	checksOK := observation.Success && len(observation.DistributionChecks) > 0
	for _, check := range observation.DistributionChecks {
		checksOK = checksOK && check.Success
	}
	distribution := "incomplete"
	if checksOK {
		distribution = "verified"
	}
	status := "error"
	if observation.Success {
		status = "healthy"
	}
	projection.Publisher = &PublisherStatus{ObservedAt: observation.ObservedAt, IntervalSeconds: observation.IntervalSeconds, Generation: observation.Current.Generation, Snapshot: observation.Current.Snapshot, Commit: observation.Version.Commit, Binary: observation.Version.Binary, Status: status, Distribution: distribution}
	for index := range projection.Devices {
		device := &projection.Devices[index]
		target, selectErr := observation.Current.Select(device.ID)
		detail := "Device application readback is not defined in the current report contract."
		if selectErr != nil {
			target = ""
			detail = "Publisher target has no assignment for this device."
		}
		projection.Deployments = append(projection.Deployments, Deployment{Device: device.ID, Generation: observation.Current.Generation, TargetSnapshot: target, PublisherAt: observation.ObservedAt, Stage: "unknown", Status: "unknown", Detail: detail})
		device.Deployment = "unknown"
	}
	return nil
}

package deviceclient

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"sync"
	"time"

	"loom/internal/control"
)

const releaseHeaderTimeout = 30 * time.Second

// Release reads only immutable delivery material for an already persisted LKG.
// The updater never writes the daemon's identity, LKG, or report sequence.
func Release(ctx context.Context, store IdentityStore, platform string, validate func(control.DeviceReleaseDelivery) error) (control.DeviceReleaseDelivery, error) {
	var result control.DeviceReleaseDelivery
	lkg := store.LKG()
	if lkg == nil || validate == nil {
		return result, errors.New("accepted device configuration required")
	}
	request := control.DeviceReleaseRequest{Schema: 3, Platform: platform, ViewDigest: lkg.ViewDigest}
	return requestDevice(ctx, store, lkg, 2, deviceRequestTimeout, func(attempt context.Context, connection net.Conn) (control.DeviceReleaseDelivery, error) {
		var result control.DeviceReleaseDelivery
		if _, err := postJSON(attempt, connection, "/device/release", request, &result); err != nil {
			return control.DeviceReleaseDelivery{}, err
		}
		if result.Platform != platform || result.ViewDigest != lkg.ViewDigest {
			return control.DeviceReleaseDelivery{}, errors.New("release delivery belongs to another accepted configuration")
		}
		if current := store.LKG(); current == nil || current.ViewDigest != lkg.ViewDigest {
			return control.DeviceReleaseDelivery{}, errors.New("device View changed during release fetch")
		}
		return result, validate(result)
	})
}

// DownloadReleaseTo streams the exact signed-length body to caller-owned
// protected storage. It never changes the device's identity or accepted View.
func DownloadReleaseTo(ctx context.Context, store IdentityStore, request control.DeviceReleaseDownload, size int64, workspace string, destination io.Writer) (resultErr error) {
	return downloadReleaseTo(ctx, store, request, size, workspace, destination, releaseHeaderTimeout, deviceRequestTimeout)
}

func downloadReleaseTo(ctx context.Context, store IdentityStore, request control.DeviceReleaseDownload, size int64, workspace string, destination io.Writer, headerTimeout, idleTimeout time.Duration) (resultErr error) {
	if destination == nil || request.Validate() != nil || size <= 0 || size > 256<<20 || !validStatePath(workspace) {
		return errors.New("release download bounds are invalid")
	}
	if headerTimeout <= 0 || idleTimeout <= 0 {
		return errors.New("release download I/O deadlines are invalid")
	}
	lkg := store.LKG()
	if lkg == nil || lkg.ViewDigest != request.ViewDigest {
		return errors.New("release download is not bound to accepted configuration")
	}
	// The updater supplies its existing protected disk workspace. OS temporary
	// roots may be tmpfs and must not turn the bounded file into resident memory.
	info, err := os.Lstat(workspace)
	if err != nil || !info.IsDir() || info.Mode().Perm()&0077 != 0 {
		return errors.New("release download requires its protected disk workspace")
	}
	body, err := control.CanonicalEncode(request)
	if err != nil {
		return err
	}
	// A slow but progressing transfer must leave another authenticated candidate
	// an opportunity to finish. Each of the at most two active candidates owns
	// separate protected storage and cannot write to caller storage.
	var completedMu sync.Mutex
	var completed []*os.File
	defer func() {
		for _, staged := range completed {
			resultErr = errors.Join(resultErr, staged.Close(), os.Remove(staged.Name()))
		}
	}()
	// Reserve a share of the caller's total budget for every wave of two. Two
	// live slow bodies must not prevent later accepted endpoints being tried.
	var candidateTimeout time.Duration
	if deadline, ok := ctx.Deadline(); ok {
		waves := (len(servingDeviceEndpoints(lkg)) + 1) / 2
		if waves > 0 {
			candidateTimeout = time.Until(deadline) / time.Duration(waves)
			if candidateTimeout <= 0 {
				return context.DeadlineExceeded
			}
		}
	}
	staged, err := requestDevice(ctx, store, lkg, 2, candidateTimeout, func(attempt context.Context, connection net.Conn) (_ *os.File, candidateErr error) {
		candidate, err := os.CreateTemp(workspace, "download-")
		if err != nil {
			return nil, err
		}
		complete := false
		defer func() {
			if !complete {
				candidateErr = errors.Join(candidateErr, candidate.Close(), os.Remove(candidate.Name()))
			}
		}()
		httpRequest, err := http.NewRequestWithContext(attempt, http.MethodPost, "http://loom.private/device/release/download", bytes.NewReader(body))
		if err != nil {
			return nil, err
		}
		httpRequest.Header.Set("Content-Type", "application/json")
		idle := &releaseIdleConnection{Conn: connection, timeout: idleTimeout, readTimeout: headerTimeout}
		client := tunnelHTTPClient(idle)
		client.Timeout = 0
		// Preparing the first verified archive may exceed a body idle window.
		// Bound the complete header wait even when partial headers arrive, while
		// preserving the caller's original total budget for a progressing body.
		client.Transport.(*http.Transport).ResponseHeaderTimeout = headerTimeout
		response, err := client.Do(httpRequest)
		if err != nil {
			return nil, err
		}
		defer response.Body.Close()
		if err := idle.setReadTimeout(idleTimeout); err != nil {
			return nil, err
		}
		hash := sha256.New()
		if err := copyReleaseBody(attempt, response, size, io.MultiWriter(candidate, hash)); err != nil {
			return nil, err
		}
		if "sha256:"+hex.EncodeToString(hash.Sum(nil)) != request.ArtifactDigest {
			return nil, errors.New("release body differs from signed digest")
		}
		if current := store.LKG(); current == nil || current.ViewDigest != request.ViewDigest {
			return nil, errors.New("device View changed during release download")
		}
		completedMu.Lock()
		completed = append(completed, candidate)
		completedMu.Unlock()
		complete = true
		return candidate, nil
	})
	if err != nil {
		return err
	}
	// Writer failure is final: replaying another candidate could duplicate a
	// prefix already committed by the caller. No candidate is active here.
	_, err = io.CopyBuffer(destination, &releaseBodyReader{ctx: ctx, reader: io.NewSectionReader(staged, 0, size)}, make([]byte, 32<<10))
	return err
}

type releaseIdleConnection struct {
	net.Conn
	timeout     time.Duration
	readMu      sync.Mutex
	readTimeout time.Duration
}

func (connection *releaseIdleConnection) Read(body []byte) (int, error) {
	connection.readMu.Lock()
	timeout := connection.readTimeout
	if timeout == 0 {
		timeout = connection.timeout
	}
	err := connection.Conn.SetReadDeadline(time.Now().Add(timeout))
	connection.readMu.Unlock()
	if err != nil {
		return 0, err
	}
	return connection.Conn.Read(body)
}

// net/http may already be waiting for body bytes when Do returns headers.
// Update that pending read as well as future reads under the same lock, so an
// in-flight header read cannot later restore its longer deadline.
func (connection *releaseIdleConnection) setReadTimeout(timeout time.Duration) error {
	connection.readMu.Lock()
	defer connection.readMu.Unlock()
	connection.readTimeout = timeout
	return connection.Conn.SetReadDeadline(time.Now().Add(timeout))
}

func (connection *releaseIdleConnection) Write(body []byte) (int, error) {
	if err := connection.SetWriteDeadline(time.Now().Add(connection.timeout)); err != nil {
		return 0, err
	}
	return connection.Conn.Write(body)
}

func copyReleaseBody(ctx context.Context, response *http.Response, size int64, destination io.Writer) error {
	if response.StatusCode != http.StatusOK || response.ContentLength != size {
		return errors.New("exact release body unavailable")
	}
	reader := &releaseBodyReader{ctx: ctx, reader: io.LimitReader(response.Body, size+1)}
	n, err := io.CopyBuffer(destination, reader, make([]byte, 32<<10))
	if err != nil {
		return err
	}
	if n != size {
		return errors.New("release body length differs from signed coordinates")
	}
	return nil
}

type releaseBodyReader struct {
	ctx    context.Context
	reader io.Reader
}

func (reader *releaseBodyReader) Read(body []byte) (int, error) {
	if err := reader.ctx.Err(); err != nil {
		return 0, err
	}
	return reader.reader.Read(body)
}

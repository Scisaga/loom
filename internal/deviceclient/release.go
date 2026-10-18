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
	"time"

	"loom/internal/control"
)

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
	if destination == nil || request.Validate() != nil || size <= 0 || size > 256<<20 || !validStatePath(workspace) {
		return errors.New("release download bounds are invalid")
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
	staged, err := os.CreateTemp(workspace, "download-")
	if err != nil {
		return err
	}
	defer func() { resultErr = errors.Join(resultErr, staged.Close(), os.Remove(staged.Name())) }()
	body, err := control.CanonicalEncode(request)
	if err != nil {
		return err
	}
	// Download candidates are sequential and never write to caller storage. A
	// live transfer keeps its caller's original total budget; only stalled I/O
	// is bounded independently so another authenticated candidate can be tried.
	_, err = requestDevice(ctx, store, lkg, 1, 0, func(attempt context.Context, connection net.Conn) (struct{}, error) {
		if err := staged.Truncate(0); err != nil {
			return struct{}{}, err
		}
		if _, err := staged.Seek(0, io.SeekStart); err != nil {
			return struct{}{}, err
		}
		httpRequest, err := http.NewRequestWithContext(attempt, http.MethodPost, "http://loom.private/device/release/download", bytes.NewReader(body))
		if err != nil {
			return struct{}{}, err
		}
		httpRequest.Header.Set("Content-Type", "application/json")
		client := tunnelHTTPClient(&releaseIdleConnection{Conn: connection, timeout: deviceRequestTimeout})
		client.Timeout = 0
		response, err := client.Do(httpRequest)
		if err != nil {
			return struct{}{}, err
		}
		defer response.Body.Close()
		hash := sha256.New()
		if err := copyReleaseBody(attempt, response, size, io.MultiWriter(staged, hash)); err != nil {
			return struct{}{}, err
		}
		if "sha256:"+hex.EncodeToString(hash.Sum(nil)) != request.ArtifactDigest {
			return struct{}{}, errors.New("release body differs from signed digest")
		}
		if current := store.LKG(); current == nil || current.ViewDigest != request.ViewDigest {
			return struct{}{}, errors.New("device View changed during release download")
		}
		return struct{}{}, nil
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
	timeout time.Duration
}

func (connection *releaseIdleConnection) Read(body []byte) (int, error) {
	if err := connection.SetReadDeadline(time.Now().Add(connection.timeout)); err != nil {
		return 0, err
	}
	return connection.Conn.Read(body)
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

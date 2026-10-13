package deviceclient

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"

	"loom/internal/control"
)

// Release reads only immutable delivery material for an already persisted LKG.
// The updater never writes the daemon's identity, LKG, or report sequence.
func Release(ctx context.Context, store IdentityStore, platform string) (control.DeviceReleaseDelivery, error) {
	var result control.DeviceReleaseDelivery
	lkg := store.LKG()
	if lkg == nil {
		return result, errors.New("accepted device configuration required")
	}
	connection, err := deviceConnection(ctx, store)
	if err != nil {
		return result, err
	}
	defer connection.Close()
	request := control.DeviceReleaseRequest{Schema: 3, Platform: platform, ViewDigest: lkg.ViewDigest}
	_, err = postJSON(ctx, connection, "/device/release", request, &result)
	if err == nil && (result.Platform != platform || result.ViewDigest != lkg.ViewDigest) {
		err = errors.New("release delivery belongs to another accepted configuration")
	}
	return result, err
}

// DownloadReleaseTo streams the exact signed-length body to caller-owned
// protected storage. It never changes the device's identity or accepted View.
func DownloadReleaseTo(ctx context.Context, store IdentityStore, request control.DeviceReleaseDownload, size int64, destination io.Writer) error {
	if destination == nil || request.Validate() != nil || size <= 0 || size > 256<<20 {
		return errors.New("release download bounds are invalid")
	}
	lkg := store.LKG()
	if lkg == nil || lkg.ViewDigest != request.ViewDigest {
		return errors.New("release download is not bound to accepted configuration")
	}
	connection, err := deviceConnection(ctx, store)
	if err != nil {
		return err
	}
	defer connection.Close()
	body, err := control.CanonicalEncode(request)
	if err != nil {
		return err
	}
	httpRequest, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://loom.private/device/release/download", bytes.NewReader(body))
	if err != nil {
		return err
	}
	httpRequest.Header.Set("Content-Type", "application/json")
	client := tunnelHTTPClient(connection)
	client.Timeout = 0
	response, err := client.Do(httpRequest)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	return copyReleaseBody(ctx, response, size, destination)
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

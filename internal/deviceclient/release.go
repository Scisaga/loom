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

func DownloadRelease(ctx context.Context, store IdentityStore, request control.DeviceReleaseDownload, size int64) ([]byte, error) {
	if request.Validate() != nil || size <= 0 || size > 256<<20 {
		return nil, errors.New("release download bounds are invalid")
	}
	lkg := store.LKG()
	if lkg == nil || lkg.ViewDigest != request.ViewDigest {
		return nil, errors.New("release download is not bound to accepted configuration")
	}
	connection, err := deviceConnection(ctx, store)
	if err != nil {
		return nil, err
	}
	defer connection.Close()
	body, err := control.CanonicalEncode(request)
	if err != nil {
		return nil, err
	}
	httpRequest, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://loom.private/device/release/download", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	httpRequest.Header.Set("Content-Type", "application/json")
	client := tunnelHTTPClient(connection)
	client.Timeout = 0 // The caller bounds the whole operation; body writes are streamed.
	response, err := client.Do(httpRequest)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK || response.ContentLength != size {
		return nil, errors.New("exact release body unavailable")
	}
	result, err := io.ReadAll(io.LimitReader(response.Body, size+1))
	if err != nil || int64(len(result)) != size {
		return nil, errors.New("release body length differs from signed coordinates")
	}
	return result, nil
}

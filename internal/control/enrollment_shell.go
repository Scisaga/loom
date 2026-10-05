package control

import (
	"context"
	"errors"
	"io"
	"net/http"
	"sort"
	"time"
)

func (server *Server) shellInviteBlock(ctx context.Context, encoded string) (string, error) {
	if server.Releases == nil {
		return "", errors.New("signed installer unavailable")
	}
	set, err := server.Releases.Read()
	if err != nil {
		return "", err
	}
	var artifact ReleaseArtifact
	for _, pkg := range set.Packages {
		if pkg.Entry.ComponentID == "linux-bootstrap-script" && pkg.Bootstrap != nil {
			artifact = pkg.Entry.Artifact
			break
		}
	}
	if artifact.Name == "" || artifact.Size > 64<<10 {
		return "", errors.New("signed installer unavailable")
	}
	bases := []string{}
	seen := map[string]bool{}
	for _, device := range server.Runtime.Authority.Snapshot().DeviceAuthorizations {
		for _, base := range device.DistributionURLs {
			if !seen[base] {
				seen[base] = true
				bases = append(bases, base)
			}
		}
	}
	sort.Strings(bases)
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	transport := &http.Transport{Proxy: nil, DisableCompression: true, DisableKeepAlives: true, ResponseHeaderTimeout: 10 * time.Second}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	for _, base := range bases {
		if ctx.Err() != nil {
			break
		}
		address, err := DistributionURL(base, artifact.Digest)
		if err != nil {
			continue
		}
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, address, nil)
		if err != nil {
			continue
		}
		response, err := client.Do(request)
		if err != nil {
			continue
		}
		body, readErr := io.ReadAll(io.LimitReader(response.Body, (64<<10)+1))
		response.Body.Close()
		if readErr != nil || response.StatusCode != http.StatusOK || response.Header.Get("Content-Encoding") != "" || uint64(len(body)) != uint64(artifact.Size) || ReleaseDigest(body) != artifact.Digest {
			continue
		}
		// The URL must still be authenticated after the potentially slow read.
		current := false
		for _, device := range server.Runtime.Authority.Snapshot().DeviceAuthorizations {
			for _, value := range device.DistributionURLs {
				if value == base {
					current = true
				}
			}
		}
		if !current {
			continue
		}
		return ShellInviteDelivery(base, artifact, encoded)
	}
	return "", errors.New("verified public installer unavailable")
}

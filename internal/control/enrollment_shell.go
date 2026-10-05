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
	verified := []string{}
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
		verified = append(verified, base)
	}
	// Recheck the whole set after all network reads, including roots verified
	// before another root's slow response. Availability remains target-specific.
	current := map[string]bool{}
	for _, device := range server.Runtime.Authority.Snapshot().DeviceAuthorizations {
		for _, base := range device.DistributionURLs {
			current[base] = true
		}
	}
	bases = nil
	for _, base := range verified {
		if current[base] {
			bases = append(bases, base)
		}
	}
	return ShellInviteDelivery(bases, artifact, encoded)
}

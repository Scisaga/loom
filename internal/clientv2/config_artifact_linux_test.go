//go:build linux

package clientv2

import (
	"bytes"
	"context"
	"net"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"loom/internal/wire"
)

func TestFetchLinuxDeviceConfigArtifactsUsesPinnedContentAddressedMirrors(t *testing.T) {
	body := []byte(`{"schema":1,"value":"linux-config"}`)
	contentHash, _ := wire.DeviceConfigArtifactContentHash(body)
	digest := strings.TrimPrefix(contentHash, "sha256:")
	requests := 0
	server, roots, pin := mirrorTLSTestFixture(t, http.HandlerFunc(
		func(response http.ResponseWriter, request *http.Request) {
			requests++
			if request.URL.Path != "/distribution/sha256/"+digest ||
				request.Header.Get("Authorization") != "" || request.Header.Get("Cookie") != "" {
				http.Error(response, "bad request", http.StatusBadRequest)
				return
			}
			_, _ = response.Write(body)
		}))
	t.Cleanup(server.Close)
	parsed, _ := url.Parse(server.URL)
	hash := func(value string) string { return wire.HashRaw("linux-config-fetch-test", []byte(value)) }
	mirrors := []wire.DistributionMirrorRefV1{
		{Schema: 1, EndpointID: "mirror-1", DistributionEndpointSetHash: hash("set-1"),
			ListenerGeneration: 1, BaseURL: "https://a.example.test:" + parsed.Port() + "/distribution/sha256/",
			ServerName: "a.example.test", WebPKIProfileRef: "webpki-v1",
			SPKIPins: []string{pin}, HintRank: 0},
		{Schema: 1, EndpointID: "mirror-2", DistributionEndpointSetHash: hash("set-2"),
			ListenerGeneration: 1, BaseURL: "https://b.example.test:" + parsed.Port() + "/distribution/sha256/",
			ServerName: "b.example.test", WebPKIProfileRef: "webpki-v1",
			SPKIPins: []string{pin}, HintRank: 1},
	}
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	fetcher := MirrorFetcher{RootCAs: roots, Timeout: 5 * time.Second,
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return dialer.DialContext(ctx, network, parsed.Host)
		}}
	ref := wire.DeviceConfigArtifactRefV1{
		ArtifactID: LinuxLinkIntentArtifactID, Generation: 2, Platform: "linux-server",
		MediaType: "application/vnd.loom.config+json", RenderContractID: "linux-link-intents-v1",
		SizeBytes: int64(len(body)), ContentHash: contentHash,
	}
	configs, err := FetchLinuxDeviceConfigArtifacts(context.Background(), mirrors,
		[]wire.DeviceConfigArtifactRefV1{ref}, fetcher)
	if err != nil || len(configs) != 1 || !bytes.Equal(configs[0].Config, body) || requests != 1 {
		t.Fatalf("config mirror fetch 无效: configs=%#v requests=%d err=%v", configs, requests, err)
	}
	got, err := LinuxInstalledConfigArtifact(&EnrollmentInstallationV1{Configs: configs},
		LinuxLinkIntentArtifactID)
	if err != nil || !bytes.Equal(got, body) {
		t.Fatalf("durable config projection 无效: got=%q err=%v", got, err)
	}
	wrongPlatform := ref
	wrongPlatform.Platform = "android"
	if _, err := FetchLinuxDeviceConfigArtifacts(context.Background(), mirrors,
		[]wire.DeviceConfigArtifactRefV1{wrongPlatform}, fetcher); err == nil || requests != 1 {
		t.Fatalf("非 Linux ref 未在请求前拒绝: requests=%d err=%v", requests, err)
	}
}

package linuxclient

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"loom/internal/control"
)

func TestLinuxComponentReadbacksMeasureOnlyExpectedComponents(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sing-box")
	if err := os.WriteFile(path, []byte("#!/bin/sh\nprintf 'sing-box version 1.11.4\\n'\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	view := control.DeviceView{ExpectedComponents: []control.ComponentExpectation{
		{Name: "agent", Version: "0.1.0"},
		{Name: "sing-box", Version: "1.11.4"},
	}}
	readbacks, err := linuxComponentReadbacks(view, path)
	if err != nil {
		t.Fatal(err)
	}
	if len(readbacks) != 2 || readbacks[0].Name != "agent" || readbacks[1].Name != "sing-box" ||
		readbacks[1].Version != "1.11.4" || !strings.HasPrefix(readbacks[1].Digest, "sha256:") {
		t.Fatalf("readbacks=%+v", readbacks)
	}
}

func TestLinuxLinkReadbacksUseWireGuardCountersAndExactTargetProbe(t *testing.T) {
	const peerKey = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
	now := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	path := filepath.Join(t.TempDir(), "wg")
	dump := fmt.Sprintf("wg-demo\tprivate\tpublic\t51820\toff\\nwg-demo\t%s\t(none)\t192.0.2.10:51820\t10.0.0.2/32\t%d\t120\t240\t25\\n", peerKey, now.Unix()-30)
	script := "#!/bin/sh\nprintf '" + dump + "'\n"
	if err := os.WriteFile(path, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	ping := filepath.Join(t.TempDir(), "ping")
	if err := os.WriteFile(ping, []byte("#!/bin/sh\nexit 0\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	view := control.DeviceView{LinkProbeTargets: []control.LinkProbeTarget{{LinkID: "demo-link", Peer: "demo-peer",
		Transport: "wireguard", Target: "192.0.2.10", PeerWGPublicKey: peerKey}}}
	readbacks, err := linuxLinkReadbacks(view, path, ping, "2030-01-01T00:00:00Z")
	if err != nil {
		t.Fatal(err)
	}
	if len(readbacks) != 1 || readbacks[0].Result != "available" || readbacks[0].Interface != "wg-demo" ||
		readbacks[0].RXBytes != 120 || readbacks[0].TXBytes != 240 || readbacks[0].LatencyMS < 1 || readbacks[0].Epoch == "" {
		t.Fatalf("readbacks=%+v", readbacks)
	}
}

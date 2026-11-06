package linuxclient

import (
	"crypto/rand"
	"encoding/json"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"testing"

	"loom/internal/netx"
)

// The user-approved exception generates an address only after proving the
// fixture has no interface or route to a real network. It never edits the host.
func isolatedPublicFixtureAddress(t *testing.T) netip.Addr {
	t.Helper()
	for _, kind := range []string{"user", "net"} {
		current, err := os.Stat("/proc/self/ns/" + kind)
		initial, initialErr := os.Stat("/proc/1/ns/" + kind)
		if err != nil || initialErr != nil || os.SameFile(current, initial) {
			t.Fatal("real Mixed transition requires separate user and network namespaces")
		}
	}
	interfaces, err := net.Interfaces()
	if err != nil || len(interfaces) != 1 || interfaces[0].Name != "lo" || interfaces[0].Flags&net.FlagLoopback == 0 {
		t.Fatal("real Mixed transition requires only isolated loopback")
	}
	for _, family := range []string{"-4", "-6"} {
		body, err := exec.Command("ip", "-json", family, "route", "show", "table", "all").Output()
		var routes []struct {
			Destination string `json:"dst"`
			Device      string `json:"dev"`
		}
		if err != nil || json.Unmarshal(body, &routes) != nil {
			t.Fatal("could not verify isolated routing")
		}
		for _, route := range routes {
			if route.Device != "" && route.Device != "lo" || route.Destination == "default" || route.Destination == "0.0.0.0/0" || route.Destination == "::/0" {
				t.Fatal("ordinary internet fixture requires no external or default route")
			}
		}
	}
	// The operator explicitly approved this scoped fixture. Documentation
	// addresses are deliberately refused by the real public-internet guard.
	var business netip.Addr
	for attempt := 0; attempt < 256; attempt++ {
		var raw [4]byte
		if _, err := rand.Read(raw[:]); err != nil {
			t.Fatal(err)
		}
		if candidate := netip.AddrFrom4(raw); netx.IsPublicInternetAddress(candidate) {
			business = candidate
			break
		}
	}
	if !business.IsValid() {
		t.Fatal("could not generate isolated ordinary-internet fixture")
	}
	for _, arguments := range [][]string{{"link", "set", "lo", "up"}, {"address", "add", netip.PrefixFrom(business, 32).String(), "dev", "lo"}} {
		if err := exec.Command("ip", arguments...).Run(); err != nil {
			t.Fatal(err)
		}
	}
	return business
}

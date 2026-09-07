//go:build windows

package agent

import "testing"

func TestWindowsRejectsServerObservationSources(t *testing.T) {
	for _, cfg := range []*Config{{Peers: []Peer{{Node: "demo-server", Addr: "192.0.2.1:443"}}}, {SelfReport: "127.0.0.1:1234"}} {
		if err := validateObservationPlatform(cfg); err == nil {
			t.Fatal("Windows accepted server observations")
		}
	}
	if err := validateObservationPlatform(&Config{}); err != nil {
		t.Fatal(err)
	}
}

package clientadapter

import (
	"loom/internal/clientmodel"
	"testing"
)

func TestHTTPSCalibrationUsesOnlyTCPSelectionKey(t *testing.T) {
	snapshot := clientmodel.Selection{CandidateID: "demo-default", Targets: map[string]string{"tcp://demo.example:443": "demo-tcp", "udp://demo.example:443": "demo-udp", "demo.example:443": "demo-retired"}}
	if selectedForURL(snapshot, "https://demo.example/health") != "demo-tcp" {
		t.Fatal("HTTPS calibration ignored its TCP override")
	}
	delete(snapshot.Targets, "tcp://demo.example:443")
	if selectedForURL(snapshot, "https://demo.example/health") != "demo-default" {
		t.Fatal("HTTPS calibration borrowed UDP or retired unscoped runtime priority")
	}
}

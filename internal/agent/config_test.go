package agent

import (
	"fmt"
	"testing"
	"time"
)

func TestObservationStaleDefaultAndValidation(t *testing.T) {
	if got, err := (&Config{}).ObsStale(); err != nil || got != 10*time.Minute {
		t.Fatalf("默认 observation_stale=%v err=%v", got, err)
	}
	if _, err := (&Config{ObservationStale: "not-a-duration"}).ObsStale(); err == nil {
		t.Fatal("非法 observation_stale 没有被拒绝")
	}
}

func TestObservationSourcesRequireAttestationCA(t *testing.T) {
	// Load performs the invariant check; marshal a minimal executable config so
	// the failure cannot be masked by a different missing field.
	b := []byte(`{"node":"n","api":"a","api_secret":"s","probe":"p","probe_secret":"s","self_report":"127.0.0.1:61802","declarations":[{"id":"d","selector":"s","objective":"latency","targets":["https://t/"],"tuning_period":"1m","switch_threshold":0.2,"window":"5m","min_samples":1,"stale_after":"5m","candidates":[{"tag":"c","probe_user":"u"}]}]}`)
	if _, err := Load(b); err == nil {
		t.Fatal("未配置 attestation_ca 的观测来源被接受")
	}
}

func TestSelfReportMustBeLiteralLoopback(t *testing.T) {
	base := `{"node":"n","api":"a","api_secret":"s","probe":"p","probe_secret":"s","attestation_ca":"/ca","self_report":"%s","declarations":[{"id":"d","selector":"s","objective":"latency","targets":["https://t/"],"tuning_period":"1m","switch_threshold":0.2,"window":"5m","min_samples":1,"stale_after":"5m","candidates":[{"tag":"c","probe_user":"u"}]}]}`
	for _, addr := range []string{"10.0.0.1:61802", "localhost:61802", "127.0.0.1", "example.test:61802"} {
		if _, err := Load([]byte(fmt.Sprintf(base, addr))); err == nil {
			t.Errorf("非 literal loopback self_report %q 被接受", addr)
		}
	}
	for _, addr := range []string{"127.0.0.1:61802", "[::1]:61802"} {
		if _, err := Load([]byte(fmt.Sprintf(base, addr))); err != nil {
			t.Errorf("合法 self_report %q 被拒绝:%v", addr, err)
		}
	}
}

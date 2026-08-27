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

func TestLegacyObservationSourcesWithoutCAAreDisabled(t *testing.T) {
	// A deployed pre-attestation config must remain readable during the
	// binary-before-config upgrade bridge, but none of its unsigned observations
	// may survive into selector input.
	b := []byte(`{"node":"n","api":"a","api_secret":"s","probe":"p","probe_secret":"s","self_report":"127.0.0.1:61802","declarations":[{"id":"d","selector":"s","objective":"latency","targets":["https://t/"],"tuning_period":"1m","switch_threshold":0.2,"window":"5m","min_samples":1,"stale_after":"5m","candidates":[{"tag":"c","probe_user":"u"}]}]}`)
	cfg, err := Load(b)
	if err != nil {
		t.Fatalf("旧配置阻断了二进制先行升级:%v", err)
	}
	if len(cfg.Peers) != 0 || cfg.SelfReport != "" || cfg.PeerPeriod != "" || cfg.ObservationDisabledReason == "" {
		t.Fatalf("旧配置的未验签观测源没有 fail closed:%+v", cfg)
	}

	phaseB := []byte(`{"node":"n","attestation_min_version":5,"self_report":"127.0.0.1:61802"}`)
	if _, err := Load(phaseB); err == nil {
		t.Fatal("phase-B 配置缺少 attestation_ca 仍被迁移兼容吞掉")
	}
	newPhaseA := []byte(`{"schema":1,"node":"n","self_report":"127.0.0.1:61802"}`)
	if _, err := Load(newPhaseA); err == nil {
		t.Fatal("新 schema 的 phase-A 配置缺少 attestation_ca 仍被 legacy bridge 吞掉")
	}
}

func TestAgentConfigSchemaIsExplicitAndBounded(t *testing.T) {
	if _, err := Load([]byte(`{"schema":2,"node":"n"}`)); err == nil {
		t.Fatal("未来 agent config schema 被当前 reader 静默接受")
	}
	if cfg, err := Load([]byte(`{"schema":1,"node":"n"}`)); err != nil || cfg.Schema != ConfigSchema {
		t.Fatalf("当前 agent config schema 无法加载:cfg=%+v err=%v", cfg, err)
	}
}

func TestAttestationUpgradeGateRejectsUnknownVersion(t *testing.T) {
	if _, err := Load([]byte(`{"node":"n","attestation_min_version":4}`)); err == nil {
		t.Fatal("未知 attestation_min_version 被 Agent 接受")
	}
	if cfg, err := Load([]byte(`{"node":"n","attestation_min_version":5}`)); err != nil || cfg.AttestationMinVersion != 5 {
		t.Fatalf("phase-B attestation 门禁无法加载:cfg=%+v err=%v", cfg, err)
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

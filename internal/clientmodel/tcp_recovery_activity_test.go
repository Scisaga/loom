package clientmodel

import (
	"testing"
	"time"
)

func TestTCPRecoveryUnknownOrdinaryResultRestartsActivityWithoutConfirmingHealth(t *testing.T) {
	at, routes, resources, current, memory, _ := recoveryFixture()
	for _, seconds := range []int64{1, 30} {
		for i := range resources {
			resources[i].ObservedAt = at.Add(time.Duration(seconds) * time.Second).UnixMilli()
		}
		_, next, err := ChooseWithNativeStability(routes, nil, nil, resources, nil, Preference{Schema: 3, PolicyID: "demo-policy"}, current, memory, "demo-local", at.Add(time.Duration(seconds)*time.Second), seconds*1000, DefaultPerformanceRule)
		if err != nil {
			t.Fatal(err)
		}
		memory = next
	}
	jobs, err := TCPRecoveryMeasurements(routes, current, memory, nil, "demo-local", at.Add(30*time.Second), DefaultPerformanceRule, 10*time.Minute)
	if err != nil || len(jobs) != 0 {
		t.Fatal("idle target created traffic without recent ordinary use", jobs, err)
	}
	unknown := nativeSample(routes[1].ID, "demo-c.example:443", "unknown", at.Add(31*time.Second), 0)
	version, confirmations := memory.Version, memory.Decisions["tcp://demo-c.example:443"].Confirmations
	got, next, err := ChooseWithNativeStability(routes, nil, []Observation{unknown}, resources, nil, Preference{Schema: 3, PolicyID: "demo-policy"}, current, memory, "demo-local", at.Add(31*time.Second), 31000, DefaultPerformanceRule)
	if err != nil || selectedTarget(got, "tcp://demo-c.example:443") != routes[1].ID || next.Version != version || next.Decisions["tcp://demo-c.example:443"].Confirmations != confirmations {
		t.Fatal("an unknown ordinary result became health or a performance vote", got, next, err)
	}
	jobs, err = TCPRecoveryMeasurements(routes, current, next, []Observation{unknown}, "demo-local", at.Add(31*time.Second), DefaultPerformanceRule, 10*time.Minute)
	if err != nil || len(jobs) != 1 {
		t.Fatal("real unknown attempt did not restore recent-use evidence", jobs, err)
	}
	if state, err := ObservationState([]Observation{unknown}, routes[1].ID, "access", "demo-local", []string{"https://demo-c.example/health"}, at.Add(31*time.Second)); err != nil || state != "unknown" {
		t.Fatal("unknown TCP activity became HTTPS evidence", state, err)
	}
}

package clientmodel

import (
	"testing"
	"time"

	"loom/internal/control"
)

func recoveryFixture() (time.Time, []RouteCandidate, []control.Observation, Selection, SelectionMemory, []Observation) {
	at, routes, resources, _ := routingEvidenceFixture()
	for i := range resources {
		resources[i].ValidUntil = at.Add(10 * time.Minute).UnixMilli()
	}
	current := Selection{Scope: "access", PolicyID: "demo-policy", Revision: "demo-revision", CandidateID: routes[0].ID, Targets: map[string]string{"tcp://demo-c.example:443": routes[1].ID}}
	memory := SelectionMemory{PolicyID: "demo-policy", NetworkGeneration: "demo-local", Decisions: map[string]SelectionDecision{
		"": {Current: routes[0].ID, Qualified: true}, "tcp://demo-c.example:443": {Current: routes[1].ID, Qualified: true},
	}, NativeBinding: &NativeBinding{Revision: current.Revision, NetworkGeneration: "demo-local", ExecutionSpec: "demo-spec"}}
	native := []Observation{nativeSample(routes[1].ID, "demo-c.example:443", "available", at, 10)}
	return at, routes, resources, current, memory, native
}

func TestTCPRecoveryProducesARealJobWhileCurrentPathKeepsSucceeding(t *testing.T) {
	for _, sameExit := range []bool{false, true} {
		at, routes, resources, current, memory, native := recoveryFixture()
		if sameExit {
			routes[1].FinalExit, routes[1].Chain = routes[0].FinalExit, append([]string{}, routes[0].Chain...)
		}
		choose := func(seconds int64) Selection {
			t.Helper()
			// Current B keeps producing fresh successful real connections.
			native[0] = nativeSample(routes[1].ID, "demo-c.example:443", "available", at.Add(time.Duration(seconds)*time.Second), 0)
			got, next, err := ChooseWithNativeStability(routes, nil, native, resources, nil, Preference{Schema: 3, PolicyID: "demo-policy"}, current, memory, "demo-local", at.Add(time.Duration(seconds)*time.Second), seconds*1000, DefaultPerformanceRule)
			if err != nil {
				t.Fatal(err)
			}
			memory = next
			return got
		}
		if got := choose(1); got.Targets["tcp://demo-c.example:443"] != routes[1].ID {
			t.Fatal("unknown backup was applied without confirmation", got)
		}
		for i := range resources {
			resources[i].ObservedAt = at.Add(30 * time.Second).UnixMilli()
		}
		if got := choose(30); got.Targets["tcp://demo-c.example:443"] != routes[1].ID {
			t.Fatal("unknown backup bypassed its TCP gate", got)
		}
		jobs, err := TCPRecoveryMeasurements(routes, current, memory, native, "demo-local", at.Add(30*time.Second), DefaultPerformanceRule, 10*time.Minute)
		if err != nil || len(jobs) != 1 || jobs[0].CandidateID != routes[0].ID || jobs[0].Target != "tcp://demo-c.example:443" {
			t.Fatal("a successful current path blocked the recovery producer", jobs, err, memory)
		}
		// Feed back exactly that planned TCP result. One successful calibration
		// gates the existing segment proof; it is not a second RTT vote series.
		result := nativeSample(jobs[0].CandidateID, "demo-c.example:443", "available", at.Add(31*time.Second), 0)
		result.Action = "tcp_calibration"
		native = append(native, result)
		if got := choose(31); selectedTarget(got, jobs[0].Target) != routes[0].ID {
			t.Fatal("successful planned calibration did not release the stable improvement", got, memory)
		}
	}
}

func TestTCPRecoveryKeepsExpiredTargetPendingButCalibrationCannotRenewActivity(t *testing.T) {
	at, routes, resources, current, memory, native := recoveryFixture()
	native[0].ValidUntil = at.Add(30 * time.Second).Format(time.RFC3339Nano)
	for _, seconds := range []int64{60, 90} {
		for i := range resources {
			resources[i].ObservedAt = at.Add(time.Duration(seconds) * time.Second).UnixMilli()
		}
		got, next, err := ChooseWithNativeStability(routes, nil, native, resources, nil, Preference{Schema: 3, PolicyID: "demo-policy"}, current, memory, "demo-local", at.Add(time.Duration(seconds)*time.Second), seconds*1000, DefaultPerformanceRule)
		if err != nil || got.Targets["tcp://demo-c.example:443"] != routes[1].ID {
			t.Fatal("expiry restored a route without proof", got, err)
		}
		memory = next
	}
	jobs, err := TCPRecoveryMeasurements(routes, current, memory, native, "demo-local", at.Add(90*time.Second), DefaultPerformanceRule, 10*time.Minute)
	if err != nil || len(jobs) != 1 {
		t.Fatal("expired target repeatedly cleared a valid transport pending", jobs, err, memory)
	}
	calibration := nativeSample(routes[0].ID, "demo-c.example:443", "unknown", at.Add(599*time.Second), 0)
	calibration.Action = "tcp_calibration"
	native = append(native, calibration)
	jobs, err = TCPRecoveryMeasurements(routes, current, memory, native, "demo-local", at.Add(601*time.Second), DefaultPerformanceRule, 10*time.Minute)
	if err != nil || len(jobs) != 0 {
		t.Fatal("calibration renewed the ordinary activity lease", jobs, err)
	}
}

func TestTCPRecoveryReusesSharedHTTPSWithoutWashingActualFailures(t *testing.T) {
	for _, outcome := range []string{"available", "unavailable", "local-tcp-failure", "partial"} {
		at, routes, resources, current, memory, native := recoveryFixture()
		_, _, _, egress := routingEvidenceFixture()
		result := outcome
		if outcome == "local-tcp-failure" {
			result = "available"
			failure := nativeSample(routes[0].ID, "demo-c.example:443", "unavailable", at, 0)
			failure.ValidUntil = at.Add(2 * time.Minute).Format(time.RFC3339Nano)
			native = append(native, failure)
		}
		url := "https://demo-c.example/health"
		targets := []string{url}
		if outcome == "partial" {
			result = "unavailable"
			targets = append(targets, "https://demo-c.example/other")
		}
		shared := []control.DeviceLinkObservation{egress(routes[0].FinalExit, url, result, 0)}
		var selected Selection
		for _, seconds := range []int64{1, 30} {
			if seconds == 30 {
				for i := range resources {
					resources[i].ObservedAt = at.Add(30 * time.Second).UnixMilli()
				}
			}
			got, next, err := ChooseWithNativeStability(routes, nil, native, resources, shared, Preference{Schema: 3, PolicyID: "demo-policy"}, current, memory, "demo-local", at.Add(time.Duration(seconds)*time.Second), seconds*1000, DefaultPerformanceRule, targets...)
			if err != nil {
				t.Fatal(err)
			}
			selected, memory = got, next
		}
		jobs, err := TCPRecoveryMeasurements(routes, current, memory, native, "demo-local", at.Add(30*time.Second), DefaultPerformanceRule, 10*time.Minute)
		wantJobs := 0
		if outcome == "partial" {
			wantJobs = 1
		}
		if err != nil || len(jobs) != wantJobs {
			t.Fatal("existing related HTTPS evidence caused duplicate access calibration", outcome, jobs, err)
		}
		want := routes[1].ID
		if outcome == "available" {
			want = routes[0].ID
		}
		if selectedTarget(selected, "tcp://demo-c.example:443") != want {
			t.Fatal("shared evidence lost its scope or cleared a current TCP failure", outcome, selected)
		}
	}
}

func TestTCPRecoveryRejectsStaleBindingsFixedExitLANAndWithdrawal(t *testing.T) {
	for _, scenario := range []string{"network", "policy", "revision", "restart", "withdrawn", "fixed", "LAN", "UDP"} {
		at, routes, resources, current, memory, native := recoveryFixture()
		for _, seconds := range []int64{1, 30} {
			for i := range resources {
				resources[i].ObservedAt = at.Add(time.Duration(seconds) * time.Second).UnixMilli()
			}
			_, next, err := ChooseWithNativeStability(routes, nil, native, resources, nil, Preference{Schema: 3, PolicyID: "demo-policy"}, current, memory, "demo-local", at.Add(time.Duration(seconds)*time.Second), seconds*1000, DefaultPerformanceRule)
			if err != nil {
				t.Fatal(err)
			}
			memory = next
		}
		switch scenario {
		case "network":
			memory.NativeBinding.NetworkGeneration = "demo-before-switch"
		case "policy":
			current.PolicyID = "demo-other-policy"
		case "revision":
			current.Revision = "demo-new-revision"
		case "restart":
			memory.NativeBinding = nil
		case "withdrawn":
			routes = routes[1:]
		case "fixed":
			for i := range routes {
				routes[i].FixedExit = true
			}
		case "LAN":
			current.Scope = "local_network:demo-lan"
		case "UDP":
			memory.Decisions["udp://demo-c.example:443"] = memory.Decisions["tcp://demo-c.example:443"]
			delete(memory.Decisions, "tcp://demo-c.example:443")
		}
		jobs, err := TCPRecoveryMeasurements(routes, current, memory, native, "demo-local", at.Add(30*time.Second), DefaultPerformanceRule, 10*time.Minute)
		if err != nil || len(jobs) != 0 {
			t.Fatal("stale or out-of-scope proposal produced calibration", scenario, jobs, err)
		}
	}
}

func TestTCPRecoveryFailureUnknownAndCoolingDoNotChangeTheCurrentPath(t *testing.T) {
	for _, result := range []string{"unavailable", "unknown", "cancelled"} {
		at, routes, resources, current, memory, native := recoveryFixture()
		for _, seconds := range []int64{1, 10} {
			for i := range resources {
				resources[i].ObservedAt = at.Add(time.Duration(seconds) * time.Second).UnixMilli()
			}
			got, next, err := ChooseWithNativeStability(routes, nil, native, resources, nil, Preference{Schema: 3, PolicyID: "demo-policy"}, current, memory, "demo-local", at.Add(time.Duration(seconds)*time.Second), seconds*1000, DefaultPerformanceRule)
			if err != nil || selectedTarget(got, "tcp://demo-c.example:443") != routes[1].ID {
				t.Fatal("cooldown did not preserve current path", got, err)
			}
			memory = next
		}
		jobs, err := TCPRecoveryMeasurements(routes, current, memory, native, "demo-local", at.Add(10*time.Second), DefaultPerformanceRule, 10*time.Minute)
		if err != nil || len(jobs) != 1 {
			t.Fatal("performance cooldown stopped measurement", jobs, err)
		}
		if result != "cancelled" {
			value := nativeSample(routes[0].ID, "demo-c.example:443", result, at.Add(20*time.Second), 0)
			value.Action = "tcp_calibration"
			native = append(native, value)
		}
		got, _, err := ChooseWithNativeStability(routes, nil, native, resources, nil, Preference{Schema: 3, PolicyID: "demo-policy"}, current, memory, "demo-local", at.Add(31*time.Second), 31000, DefaultPerformanceRule)
		if err != nil || selectedTarget(got, "tcp://demo-c.example:443") != routes[1].ID {
			t.Fatal("non-success was treated as recovery", result, got, err)
		}
	}
}

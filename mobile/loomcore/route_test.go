package loomcore

import (
	"encoding/json"
	"strings"
	"testing"
)

func androidRouteFixture(t *testing.T) ([]byte, []byte) {
	t.Helper()
	singBox := `{
  "inbounds":[{"type":"mixed","tag":"probe-in","listen":"127.0.0.1","listen_port":61801,"users":[
    {"username":"probe-a-direct","password":"${secret:probe/android-a}"},
    {"username":"probe-a-edge","password":"${secret:probe/android-a}"},
    {"username":"probe-b-direct","password":"${secret:probe/android-a}"},
    {"username":"probe-b-edge","password":"${secret:probe/android-a}"}
  ]}],
  "outbounds":[
    {"type":"selector","tag":"decl:auto","outbounds":["opaque-a-direct","opaque-a-via"],"default":"opaque-a-via"},
    {"type":"selector","tag":"svc:web","outbounds":["opaque-b-direct","opaque-b-via"],"default":"opaque-b-via"}
  ],
  "route":{"rules":[
    {"inbound":["probe-in"],"auth_user":["probe-a-direct"],"outbound":"opaque-a-direct"},
    {"inbound":["probe-in"],"auth_user":["probe-a-edge"],"outbound":"opaque-a-via"},
    {"inbound":["probe-in"],"auth_user":["probe-b-direct"],"outbound":"opaque-b-direct"},
    {"inbound":["probe-in"],"auth_user":["probe-b-edge"],"outbound":"opaque-b-via"}
  ]},
  "experimental":{"clash_api":{"external_controller":"127.0.0.1:61800","secret":"${secret:api/android-a}"}}
}`
	plan := `{
  "schema":1,"node":"android-a","api":"127.0.0.1:61800","api_secret":"${secret:api/android-a}",
  "probe":"127.0.0.1:61801","probe_secret":"${secret:probe/android-a}","declarations":[],
  "selectors":[
    {"selector":"decl:auto","default":"opaque-a-via","candidates":[
      {"tag":"opaque-a-direct","probe_user":"probe-a-direct"},
      {"tag":"opaque-a-via","chain":["relay-a","edge-z"],"probe_user":"probe-a-edge"}
    ]},
    {"selector":"svc:web","default":"opaque-b-via","candidates":[
      {"tag":"opaque-b-direct","probe_user":"probe-b-direct"},
      {"tag":"opaque-b-via","chain":["edge-z"],"probe_user":"probe-b-edge"}
    ]}
  ]
}`
	bundle := hydrationBundle(t, map[string]string{
		"sing-box/config.json": singBox,
		"agent/config.json":    plan,
	})
	prepared, err := PrepareAndroidRuntime(bundle, []byte("api/android-a=api-secret\nprobe/android-a=probe-secret\n"))
	if err != nil {
		t.Fatal(err)
	}
	var runtime preparedAndroidRuntime
	if err := json.Unmarshal(prepared, &runtime); err != nil {
		t.Fatal(err)
	}
	if runtime.Schema != 1 || runtime.RoutePlan == "" || strings.Contains(runtime.RoutePlan, "${secret:") {
		t.Fatalf("prepared runtime=%+v", runtime)
	}
	return []byte(runtime.RoutePlan), prepared
}

func TestPrepareAndroidRuntimeAndEvaluateThreeModes(t *testing.T) {
	plan, _ := androidRouteFixture(t)
	auto, err := EvaluateAndroidRoute(plan, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	var got androidRouteApplication
	if err := json.Unmarshal(auto, &got); err != nil {
		t.Fatal(err)
	}
	if got.Mode != androidRouteModeAuto || got.Blocked || !got.DirectAvailable ||
		len(got.Exits) != 1 || got.Exits[0] != "edge-z" || len(got.Selectors) != 2 ||
		got.Selectors[0].Candidate != "opaque-a-via" || got.Selectors[1].Candidate != "opaque-b-via" {
		t.Fatalf("auto application=%+v", got)
	}

	direct, err := EvaluateAndroidRoute(plan, []byte(`{"schema":1,"mode":"direct"}`), nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(direct, &got); err != nil {
		t.Fatal(err)
	}
	if got.Blocked || got.Selectors[0].Candidate != "opaque-a-direct" || got.Selectors[1].Candidate != "opaque-b-direct" {
		t.Fatalf("direct application=%+v", got)
	}

	fixed, err := EvaluateAndroidRoute(plan, []byte(`{"schema":1,"mode":"fixed_exit","exit":"edge-z"}`), nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(fixed, &got); err != nil {
		t.Fatal(err)
	}
	if got.Blocked || got.Exit != "edge-z" || got.Selectors[0].Candidate != "opaque-a-via" ||
		got.Selectors[1].Candidate != "opaque-b-via" {
		t.Fatalf("fixed application=%+v", got)
	}
}

func TestEvaluateAndroidRoutePreservesRemovedExitAsBlocked(t *testing.T) {
	plan, _ := androidRouteFixture(t)
	body, err := EvaluateAndroidRoute(plan, []byte(`{"schema":1,"mode":"fixed_exit","exit":"removed-edge"}`), nil)
	if err != nil {
		t.Fatal(err)
	}
	var got androidRouteApplication
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatal(err)
	}
	if !got.Blocked || got.Exit != "removed-edge" || got.Mode != androidRouteModeFixed || len(got.Selectors) != 0 {
		t.Fatalf("blocked application=%+v", got)
	}
}

func TestEvaluateAndroidRouteRestoresOnlySameScopeSelections(t *testing.T) {
	plan, _ := androidRouteFixture(t)
	initial, err := EvaluateAndroidRoute(plan, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	var view androidRouteApplication
	if err := json.Unmarshal(initial, &view); err != nil {
		t.Fatal(err)
	}
	saved, err := marshalCanonical(&androidSavedSelections{
		Schema: 1, PlanScope: view.PlanScope,
		Selections: []androidSavedSelection{{Selector: "decl:auto", Candidate: "opaque-a-direct"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	restored, err := EvaluateAndroidRoute(plan, nil, saved)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(restored, &view); err != nil {
		t.Fatal(err)
	}
	if view.Selectors[0].Candidate != "opaque-a-direct" {
		t.Fatalf("same-scope selection was not restored: %+v", view)
	}
	saved = []byte(`{"schema":1,"plan_scope":"different","selections":[{"selector":"decl:auto","candidate":"opaque-a-direct"}]}`)
	restored, err = EvaluateAndroidRoute(plan, nil, saved)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(restored, &view); err != nil {
		t.Fatal(err)
	}
	if view.Selectors[0].Candidate != "opaque-a-via" {
		t.Fatalf("stale-scope selection was admitted: %+v", view)
	}
}

func TestPrepareAndroidRuntimeRejectsSelectorPlanDrift(t *testing.T) {
	singBox := `{"inbounds":[],"outbounds":[{"type":"selector","tag":"decl:auto","outbounds":["a"],"default":"a"}],"route":{"rules":[]},"experimental":{"clash_api":{"external_controller":"127.0.0.1:61800","secret":"${secret:api/android-a}"}}}`
	plan := `{"schema":1,"node":"android-a","api":"127.0.0.1:61800","api_secret":"${secret:api/android-a}","probe":"127.0.0.1:61801","probe_secret":"${secret:probe/android-a}","declarations":[],"selectors":[{"selector":"decl:auto","default":"different","candidates":[{"tag":"a","probe_user":"probe-a"}]}]}`
	bundle := hydrationBundle(t, map[string]string{"sing-box/config.json": singBox, "agent/config.json": plan})
	if _, err := PrepareAndroidRuntime(bundle, []byte("api/android-a=api\nprobe/android-a=probe\n")); err == nil ||
		!strings.Contains(err.Error(), "differs from sing-box") {
		t.Fatalf("drifted selector plan error=%v", err)
	}
}

func TestAndroidRoutePlanMustBelongToBundleOwner(t *testing.T) {
	plan := []byte(`{"schema":1,"node":"android-a","api":"127.0.0.1:61800","api_secret":"api","probe":"127.0.0.1:61801","probe_secret":"probe","declarations":[],"selectors":[]}`)
	if err := validateAndroidRoutePlan([]byte(`{}`), plan, "android-b"); err == nil ||
		!strings.Contains(err.Error(), "identity") {
		t.Fatalf("owner mismatch error=%v", err)
	}
}

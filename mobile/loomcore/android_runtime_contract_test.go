package loomcore

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

	"loom/internal/wire"
)

type androidV2RuntimeFixtureSecret struct {
	id    string
	value []byte
}

func androidV2RuntimeBundleFixture(t *testing.T, owner string) []byte {
	t.Helper()
	singBox, err := os.ReadFile("../../testdata/android/v2-single-host-sing-box.json")
	if err != nil {
		t.Fatal(err)
	}
	routePlan, err := os.ReadFile("../../testdata/android/v2-single-host-route-plan.json")
	if err != nil {
		t.Fatal(err)
	}
	rewrite := func(body []byte) string {
		return strings.ReplaceAll(string(body), "android-v2", owner)
	}
	bundle, err := wire.MarshalCanonical(bundleWire{Owner: owner, Files: map[string]string{
		"agent/config.json":    rewrite(routePlan),
		"sing-box/config.json": rewrite(singBox),
	}})
	if err != nil {
		t.Fatal(err)
	}
	return bundle
}

func androidV2RuntimeFixtureSecrets(owner string) []androidV2RuntimeFixtureSecret {
	return []androidV2RuntimeFixtureSecret{
		{id: "api/" + owner, value: []byte("synthetic-api-secret")},
		{id: "probe/" + owner, value: []byte("synthetic-probe-secret")},
		{id: "wg/" + owner, value: []byte("AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=")},
	}
}

func androidV2RuntimeFixtureSecretEnv(owner string) []byte {
	var builder strings.Builder
	for _, secret := range androidV2RuntimeFixtureSecrets(owner) {
		builder.WriteString(secret.id)
		builder.WriteByte('=')
		builder.Write(secret.value)
		builder.WriteByte('\n')
	}
	return []byte(builder.String())
}

func TestAndroidV2RuntimeContractRequiresSingleHostDataPlane(t *testing.T) {
	bundle := androidV2RuntimeBundleFixture(t, "android-v2")
	preparedJSON, err := PrepareAndroidRuntime(bundle, androidV2RuntimeFixtureSecretEnv("android-v2"))
	if err != nil {
		t.Fatal(err)
	}
	var prepared preparedAndroidRuntime
	if err := decodeStrictJSON(preparedJSON, maxBundleBytes, &prepared); err != nil {
		t.Fatal(err)
	}
	if prepared.RoutePlan == "" {
		t.Fatal("synthetic v2 runtime fixture 缺 route plan")
	}
	if err := validateAndroidV2RuntimeHost([]byte(prepared.SingBoxConfig)); err != nil {
		t.Fatal(err)
	}

	var baseline map[string]any
	if err := json.Unmarshal([]byte(prepared.SingBoxConfig), &baseline); err != nil {
		t.Fatal(err)
	}
	mutated := func(change func(map[string]any)) []byte {
		body, _ := json.Marshal(baseline)
		var clone map[string]any
		if err := json.Unmarshal(body, &clone); err != nil {
			t.Fatal(err)
		}
		change(clone)
		body, err := json.Marshal(clone)
		if err != nil {
			t.Fatal(err)
		}
		return body
	}
	tests := []struct {
		name   string
		change func(map[string]any)
	}{
		{name: "missing userspace WireGuard", change: func(document map[string]any) {
			delete(document, "endpoints")
		}},
		{name: "system WireGuard", change: func(document map[string]any) {
			document["endpoints"].([]any)[0].(map[string]any)["system"] = true
		}},
		{name: "single stack TUN", change: func(document map[string]any) {
			document["inbounds"].([]any)[0].(map[string]any)["address"] = []any{"172.19.0.1/30"}
		}},
		{name: "missing signed TUN MTU", change: func(document map[string]any) {
			document["inbounds"].([]any)[0].(map[string]any)["mtu"] = float64(0)
		}},
		{name: "missing FQDN recovery", change: func(document map[string]any) {
			document["dns"].(map[string]any)["reverse_mapping"] = false
		}},
		{name: "overlay bypasses WireGuard", change: func(document map[string]any) {
			document["route"].(map[string]any)["rules"].([]any)[0].(map[string]any)["outbound"] = "route-direct"
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := validateAndroidV2RuntimeHost(mutated(test.change)); err == nil {
				t.Fatal("invalid Android v2 runtime contract accepted")
			}
		})
	}

	overlap := mutated(func(document map[string]any) {
		endpoints := document["endpoints"].([]any)
		body, _ := json.Marshal(endpoints[0])
		var next map[string]any
		if err := json.Unmarshal(body, &next); err != nil {
			t.Fatal(err)
		}
		next["tag"] = "control-wg-g2"
		next["address"] = []any{"10.31.0.11/32", "fdaa::11/128"}
		document["endpoints"] = append(endpoints, next)
	})
	if err := validateAndroidV2RuntimeHost(overlap); err != nil {
		t.Fatalf("WG generation overlap 被拒绝: %v", err)
	}
}

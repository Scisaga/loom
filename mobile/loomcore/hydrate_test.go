package loomcore

import (
	"bytes"
	"strings"
	"testing"
)

func hydrationBundle(t *testing.T, files map[string]string) []byte {
	t.Helper()
	body, err := marshalCanonical(&bundleWire{Owner: "android-a", Files: files})
	if err != nil {
		t.Fatal(err)
	}
	return body
}

func TestHydrateSingBoxConfigRequiresExactSafeSecretSet(t *testing.T) {
	bundle := hydrationBundle(t, map[string]string{
		"sing-box/config.json": `{"outbounds":[{"password":"${secret:cred/android-a}","token":"${secret:api/android-a}"}]}`,
	})
	got, err := HydrateSingBoxConfig(bundle, []byte("# bootstrap\ncred/android-a=password\napi/android-a=token\n"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(got, []byte(`"password":"password"`)) || !bytes.Contains(got, []byte(`"token":"token"`)) ||
		bytes.Contains(got, []byte("${secret:")) {
		t.Fatalf("hydrated=%s", got)
	}

	for _, test := range []struct {
		name    string
		config  string
		secrets string
		want    string
	}{
		{"missing", `{"password":"${secret:cred/android-a}"}`, "api/android-a=token\n", "missing refs"},
		{"unused", `{"password":"${secret:cred/android-a}"}`, "cred/android-a=password\napi/android-a=token\n", "unused refs"},
		{"duplicate env", `{"password":"${secret:cred/android-a}"}`, "cred/android-a=one\ncred/android-a=two\n", "duplicate"},
		{"nested ref", `{"password":"${secret:cred/${secret:other}}"}`, "other=value\n", "dangerous"},
		{"unterminated ref", `{"password":"${secret:cred/android-a"}`, "cred/android-a=value\n", "dangerous"},
		{"JSON injection", `{"password":"${secret:cred/android-a}","route":{}}`, "cred/android-a=x\",\"route\":{},\"other\":\"y\n", "duplicate JSON"},
	} {
		t.Run(test.name, func(t *testing.T) {
			input := hydrationBundle(t, map[string]string{"sing-box/config.json": test.config})
			_, err := HydrateSingBoxConfig(input, []byte(test.secrets))
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error=%v want=%q", err, test.want)
			}
		})
	}
}

func TestHydrateSingBoxConfigRejectsUnexpectedBundleFiles(t *testing.T) {
	bundle := hydrationBundle(t, map[string]string{
		"sing-box/config.json": `{"password":"${secret:cred/android-a}"}`,
		"systemd/loom.service": "unsafe",
	})
	if _, err := HydrateSingBoxConfig(bundle, []byte("cred/android-a=password\n")); err == nil {
		t.Fatal("extra lifecycle file was accepted")
	}
}

func TestHydrateSingBoxConfigAcceptsSignedMobilePlanAndChecksUnion(t *testing.T) {
	bundle := hydrationBundle(t, map[string]string{
		"sing-box/config.json": `{"experimental":{"clash_api":{"secret":"${secret:api/android-a}"}}}`,
		"agent/config.json":    `{"api_secret":"${secret:api/android-a}","probe_secret":"${secret:probe/android-a}"}`,
	})
	got, err := HydrateSingBoxConfig(bundle, []byte("api/android-a=api-secret\nprobe/android-a=probe-secret\n"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(got, []byte("api-secret")) {
		t.Fatalf("hydrated sing-box=%s", got)
	}
	if _, err := HydrateSingBoxConfig(bundle, []byte("api/android-a=api-secret\n")); err == nil ||
		!strings.Contains(err.Error(), "missing refs") {
		t.Fatalf("missing plan-only secret error=%v", err)
	}
}

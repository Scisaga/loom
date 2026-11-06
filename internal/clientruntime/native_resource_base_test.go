package clientruntime

import (
	"bytes"
	"reflect"
	"testing"

	"loom/internal/clientadapter"
)

func TestWindowsNativeResourceBaseKeepsCertifiedTemplateAndCapture(t *testing.T) {
	view := windowsViewFixture(t, "hysteria2", "wireguard")
	for _, profile := range []WindowsRuntimeProfile{WindowsInstalledProfile, WindowsPortableTUNProfile, WindowsPortableMixedProfile} {
		full, err := DeriveWindowsRuntimeConfig(view, profile, "demo-api", clientadapter.WebsiteAccess{}, new([]string{}))
		if err != nil {
			t.Fatal(err)
		}
		original := full.Bytes()
		native, err := full.NativeResourceBase()
		if err != nil || native.profile != profile || native.validate() != nil {
			t.Fatal("native base changed the typed capture boundary", err)
		}
		if !bytes.Equal(full.Bytes(), original) {
			t.Fatal("native preparation mutated the full certified resource template")
		}
		a, b := runtimeDocument(t, original), runtimeDocument(t, native.Bytes())
		for _, field := range []string{"inbounds", "route", "dns", "experimental"} {
			if !reflect.DeepEqual(a[field], b[field]) {
				t.Fatal("native base changed capture, DNS or API identity", field)
			}
		}
		for _, raw := range b["outbounds"].([]any) {
			outbound := raw.(map[string]any)
			if outbound["type"] == "hysteria2" || outbound["type"] == "direct" && outbound["detour"] == "wg-shared" && outbound["execution"] != nil {
				t.Fatal("native startup eagerly constructed a sender resource")
			}
		}
		fullPermissions, err := clientadapter.RuntimePermissionProjections(string(original))
		if err != nil {
			t.Fatal(err)
		}
		basePermissions, err := clientadapter.RuntimePermissionProjections(string(native.Bytes()))
		if err != nil || !reflect.DeepEqual(fullPermissions, basePermissions) {
			t.Fatal("stripping sender constructors changed accepted permission", err)
		}
		native.Clear()
		if full.validate() != nil {
			t.Fatal("clearing temporary native bytes cleared the full template")
		}
		full.Clear()
		if _, err := full.NativeResourceBase(); err == nil {
			t.Fatal("cleared projection was accepted at the native process boundary")
		}
	}
}

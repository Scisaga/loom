package clientruntime

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestInstalledRuntimeUsesIndependentProfileCA(t *testing.T) {
	source, agentPlan := pathPlanFixture(t)
	original := append([]byte(nil), source...)
	paths := []string{
		WindowsInstalledCAPath,
		`C:\ProgramData\Loom\profiles\00112233445566778899aabbccddeeff\tls\ca.crt`,
		`C:\ProgramData\Loom\profiles\ffeeddccbbaa99887766554433221100\tls\ca.crt`,
	}
	for _, path := range paths {
		derived, err := DeriveWindowsRuntimeConfig(source, WindowsInstalledProfile, path)
		if err != nil {
			t.Fatalf("derive managed profile CA: %v", err)
		}
		var config singBoxConfig
		if err := json.Unmarshal(derived, &config); err != nil {
			t.Fatal(err)
		}
		certificates := 0
		for _, outbound := range config.Outbounds {
			if outbound.TLS != nil {
				certificates++
				if outbound.TLS.CertificatePath != path {
					t.Fatalf("runtime inherited another profile CA: %q", outbound.TLS.CertificatePath)
				}
			}
		}
		if certificates == 0 {
			t.Fatal("fixture did not exercise TLS candidates")
		}
		if _, err := BuildWindowsSelectorPlan(derived, agentPlan, WindowsInstalledProfile, path); err != nil {
			t.Fatalf("profile CA prevented shared Agent validation: %v", err)
		}
		other := paths[1]
		if path == other {
			other = paths[2]
		}
		if err := ValidateWindowsRuntimeConfig(derived, WindowsInstalledProfile, other); err == nil {
			t.Fatal("runtime accepted another profile's CA")
		}
	}
	if !bytes.Equal(source, original) {
		t.Fatal("derivation mutated signed source")
	}
	var signed singBoxConfig
	if err := json.Unmarshal(source, &signed); err != nil {
		t.Fatal(err)
	}
	for index := range signed.Outbounds {
		if signed.Outbounds[index].TLS != nil {
			signed.Outbounds[index].TLS.CertificatePath = paths[1]
		}
	}
	changed, err := json.Marshal(signed)
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateWindowsSingBox(changed); err == nil {
		t.Fatal("local profile CA path was accepted as signed source policy")
	}
}

func TestInstalledRuntimeRejectsUnmanagedProfileCA(t *testing.T) {
	source, _ := pathPlanFixture(t)
	prefix := `C:\ProgramData\Loom\profiles\`
	suffix := `\tls\ca.crt`
	id := "00112233445566778899aabbccddeeff"
	for _, path := range []string{
		"", `C:\other\tls\ca.crt`, `C:\ProgramData\Loom\tls\..\tls\ca.crt`,
		prefix + "legacy" + suffix, prefix + "LEGACY" + suffix,
		prefix + strings.ToUpper(id) + suffix, prefix + id[:31] + suffix,
		prefix + id + "0" + suffix, prefix + strings.Repeat("z", 32) + suffix,
		prefix + id + `\..` + suffix, prefix + `..\` + id + suffix,
		prefix + id + `\extra` + suffix, prefix + id + suffix + ":stream",
		prefix + id + suffix + " ", prefix + id + suffix + "\x00",
		strings.ReplaceAll(prefix+id+suffix, `\`, "/"),
		`\\host\share\profiles\` + id + suffix,
		`\\?\` + prefix + id + suffix,
	} {
		if _, err := DeriveWindowsRuntimeConfig(source, WindowsInstalledProfile, path); err == nil {
			t.Errorf("unsafe Installed CA path accepted: %q", path)
		}
	}
}

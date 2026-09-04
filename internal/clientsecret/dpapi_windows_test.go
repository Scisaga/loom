//go:build windows

package clientsecret

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestMachineProtectorNativeRoundTrip(t *testing.T) {
	protector := MachineProtector{}
	plaintext := []byte("loom-native-dpapi-round-trip")
	ciphertext, err := protector.Protect(VaultPurpose, plaintext)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(ciphertext)
	if bytes.Contains(ciphertext, plaintext) {
		t.Fatal("DPAPI ciphertext contains the plaintext")
	}
	roundTrip, err := protector.Unprotect(VaultPurpose, ciphertext)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(roundTrip)
	if !bytes.Equal(roundTrip, plaintext) {
		t.Fatal("DPAPI plaintext did not round trip")
	}
	if _, err := protector.Unprotect("candidate-config-v1", ciphertext); err == nil {
		t.Fatal("DPAPI ciphertext was accepted for a different purpose")
	}

	tampered := append([]byte(nil), ciphertext...)
	tampered[len(tampered)/2] ^= 0x80
	defer clear(tampered)
	if _, err := protector.Unprotect(VaultPurpose, tampered); err == nil {
		t.Fatal("tampered DPAPI ciphertext was accepted")
	}
}

func TestUserProtectorNativeRoundTripAndScopeSeparation(t *testing.T) {
	user := UserProtector{}
	machine := MachineProtector{}
	plaintext := []byte("loom-native-user-dpapi-round-trip")
	ciphertext, err := user.Protect(VaultPurpose, plaintext)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(ciphertext)
	if bytes.Contains(ciphertext, plaintext) {
		t.Fatal("user DPAPI ciphertext contains the plaintext")
	}
	roundTrip, err := user.Unprotect(VaultPurpose, ciphertext)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(roundTrip)
	if !bytes.Equal(roundTrip, plaintext) {
		t.Fatal("user DPAPI plaintext did not round trip")
	}
	if _, err := machine.Unprotect(VaultPurpose, ciphertext); err == nil {
		t.Fatal("user-scope ciphertext was accepted by the machine-scope protector")
	}

	machineCiphertext, err := machine.Protect(VaultPurpose, plaintext)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(machineCiphertext)
	if _, err := user.Unprotect(VaultPurpose, machineCiphertext); err == nil {
		t.Fatal("machine-scope ciphertext was accepted by the user-scope protector")
	}
}

func TestMachineProtectorCrossAccountFixture(t *testing.T) {
	mode := os.Getenv("LOOM_DPAPI_CROSS_ACCOUNT_MODE")
	if mode == "" {
		t.Skip("set LOOM_DPAPI_CROSS_ACCOUNT_MODE for the native cross-account probe")
	}
	path := os.Getenv("LOOM_DPAPI_CROSS_ACCOUNT_PATH")
	if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path {
		t.Fatal("LOOM_DPAPI_CROSS_ACCOUNT_PATH must be absolute and clean")
	}
	protector := MachineProtector{}
	want := map[string]string{
		"vault:cred/cross-account": "cross-account-password",
		"api/cross-account":        "cross-account-api",
	}
	switch mode {
	case "write":
		if err := WriteVault(path, want, protector); err != nil {
			t.Fatal(err)
		}
	case "read":
		got, err := ReadVault(path, protector)
		if err != nil {
			t.Fatal(err)
		}
		defer clear(got)
		if len(got) != len(want) {
			t.Fatalf("cross-account vault length = %d, want %d", len(got), len(want))
		}
		for ref, value := range want {
			if got[ref] != value {
				t.Fatalf("cross-account vault value for %q did not round trip", ref)
			}
		}
	default:
		t.Fatalf("unsupported cross-account fixture mode %q", mode)
	}
}

func TestMachineProtectorNativeVaultFile(t *testing.T) {
	protector := MachineProtector{}
	path := filepath.Join(t.TempDir(), "vault.json.dpapi")
	want := map[string]string{
		"vault:cred/win-native": "native-password-value",
		"api/win-native":        "native-api-value",
	}
	if err := WriteVault(path, want, protector); err != nil {
		t.Fatal(err)
	}
	onDisk, err := readRegular(path, maxCiphertext*2)
	if err != nil {
		t.Fatal(err)
	}
	for _, value := range want {
		if bytes.Contains(onDisk, []byte(value)) {
			t.Fatal("DPAPI vault persisted a plaintext value")
		}
	}
	got, err := ReadVault(path, protector)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(got)
	if len(got) != len(want) {
		t.Fatalf("vault length = %d, want %d", len(got), len(want))
	}
	for ref, value := range want {
		if got[ref] != value {
			t.Fatalf("vault value for %q did not round trip", ref)
		}
	}
}

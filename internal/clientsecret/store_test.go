package clientsecret

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

type testProtector struct{}

func (testProtector) Protect(purpose string, plaintext []byte) ([]byte, error) {
	out := append([]byte(purpose+"\x00"), plaintext...)
	for index := len(purpose) + 1; index < len(out); index++ {
		out[index] ^= 0xa5
	}
	return out, nil
}

func (testProtector) Unprotect(purpose string, ciphertext []byte) ([]byte, error) {
	prefix := []byte(purpose + "\x00")
	if !bytes.HasPrefix(ciphertext, prefix) {
		return nil, errors.New("purpose mismatch")
	}
	out := append([]byte(nil), ciphertext[len(prefix):]...)
	for index := range out {
		out[index] ^= 0xa5
	}
	return out, nil
}

func TestParseEnvIsStrict(t *testing.T) {
	got, err := ParseEnv("# bootstrap\nvault:cred/win01 = alpha\nprobe/win01=beta\n")
	if err != nil || !reflect.DeepEqual(got, map[string]string{
		"vault:cred/win01": "alpha", "probe/win01": "beta",
	}) {
		t.Fatalf("ParseEnv = %#v, %v", got, err)
	}
	for _, body := range []string{
		"", "missing-separator", "ref=", "ref=a\nref=b\n", "bad ref=value\n", "bad}=value\n",
	} {
		if _, err := ParseEnv(body); err == nil {
			t.Fatalf("invalid secret bootstrap accepted: %q", body)
		}
	}
}

func TestVaultRoundTripDoesNotStorePlaintext(t *testing.T) {
	path := filepath.Join(t.TempDir(), "secrets", "vault.json")
	want := map[string]string{"vault:cred/win01": "do-not-leak", "api/win01": "api-secret"}
	if err := WriteVault(path, want, testProtector{}); err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(body, []byte("do-not-leak")) || bytes.Contains(body, []byte("api-secret")) {
		t.Fatalf("vault persisted plaintext: %s", body)
	}
	got, err := ReadVault(path, testProtector{})
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("ReadVault = %#v, %v", got, err)
	}
}

func TestProtectedEnvelopeRejectsPurposeSwapAndTampering(t *testing.T) {
	path := filepath.Join(t.TempDir(), "protected.json")
	if err := WriteProtected(path, "candidate-config-v1", []byte("secret config"), testProtector{}); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadProtected(path, VaultPurpose, testProtector{}); err == nil || !strings.Contains(err.Error(), "purpose") {
		t.Fatalf("purpose swap result = %v", err)
	}
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	body = bytes.Replace(body, []byte(`"ciphertext": "`), []byte(`"ciphertext": "A`), 1)
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadProtected(path, "candidate-config-v1", testProtector{}); err == nil {
		t.Fatal("tampered protected envelope was accepted")
	}
}

func TestInvalidVaultDoesNotOverwriteExistingCiphertext(t *testing.T) {
	path := filepath.Join(t.TempDir(), "vault.json")
	if err := WriteVault(path, map[string]string{"ref": "value"}, testProtector{}); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(path)
	if err := WriteVault(path, map[string]string{"bad ref": "value"}, testProtector{}); err == nil {
		t.Fatal("invalid vault was written")
	}
	after, _ := os.ReadFile(path)
	if !bytes.Equal(before, after) {
		t.Fatal("invalid write changed existing vault")
	}
}

func TestStrictVaultDecoderRejectsDuplicateAndUnknownFields(t *testing.T) {
	path := filepath.Join(t.TempDir(), "vault.json")
	for _, plaintext := range []string{
		`{"schema":1,"schema":1,"secrets":{"ref":"value"}}`,
		`{"schema":1,"secrets":{"ref":"value"},"unknown":true}`,
		`{"schema":1,"secrets":{"ref":"first","ref":"second"}}`,
	} {
		if err := WriteProtected(path, VaultPurpose, []byte(plaintext), testProtector{}); err != nil {
			t.Fatal(err)
		}
		if _, err := ReadVault(path, testProtector{}); err == nil {
			t.Fatalf("ambiguous vault accepted: %s", plaintext)
		}
	}
}

func TestProtectedJSONBudgetCoversMaximumJoinResponse(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ready.json.dpapi")
	want := struct {
		Body string `json:"body"`
	}{Body: strings.Repeat("r", 4<<20)}
	if err := WriteJSONProtected(path, "network-join-ready-v1", &want, testProtector{}); err != nil {
		t.Fatal(err)
	}
	var got struct {
		Body string `json:"body"`
	}
	if err := ReadJSONProtected(path, "network-join-ready-v1", &got, testProtector{}); err != nil {
		t.Fatal(err)
	}
	if got.Body != want.Body {
		t.Fatal("maximum join response journal changed during protected round trip")
	}
}

func TestReadRegularRejectsLinksAndOversizedFiles(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "protected.json")
	if err := os.WriteFile(target, []byte("bounded"), 0o600); err != nil {
		t.Fatal(err)
	}
	body, err := readRegular(target, int64(len("bounded")))
	if err != nil || string(body) != "bounded" {
		t.Fatalf("read bounded regular file = %q, %v", body, err)
	}
	if _, err := readRegular(target, int64(len("bounded")-1)); err == nil {
		t.Fatal("oversized protected file was accepted")
	}

	link := filepath.Join(dir, "linked.json")
	if err := os.Symlink(target, link); err == nil {
		if _, err := readRegular(link, int64(len("bounded"))); err == nil {
			t.Fatal("linked protected file was accepted")
		}
	}
}

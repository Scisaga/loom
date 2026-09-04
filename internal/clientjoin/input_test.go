package clientjoin

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"image"
	"image/png"
	"os"
	"path/filepath"
	"strings"
	"testing"

	qrcodeencoder "github.com/skip2/go-qrcode"
)

func TestReadEquivalentJoinInputs(t *testing.T) {
	raw, token := testJoinURI(t)
	dir := t.TempDir()
	textPath := filepath.Join(dir, "device.loom-invite")
	if err := os.WriteFile(textPath, []byte(raw+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	pngBody, err := qrcodeencoder.Encode(raw, qrcodeencoder.Medium, 320)
	if err != nil {
		t.Fatal(err)
	}
	imagePath := filepath.Join(dir, "device join.png")
	if err := os.WriteFile(imagePath, pngBody, 0o600); err != nil {
		t.Fatal(err)
	}
	clipboardImage, err := png.Decode(bytes.NewReader(pngBody))
	if err != nil {
		t.Fatal(err)
	}

	inputs := []struct {
		name   string
		source string
		stdin  string
	}{
		{name: "pasted URI", stdin: raw + "\n"},
		{name: "URI", source: raw},
		{name: "join file", source: textPath},
		{name: "quoted QR image", source: `"` + imagePath + `"`},
	}
	for _, input := range inputs {
		t.Run(input.name, func(t *testing.T) {
			invite, err := Read(input.source, strings.NewReader(input.stdin))
			if err != nil {
				t.Fatal(err)
			}
			if invite.Token != token || invite.Endpoint != "https://control.example/api/client/enroll" {
				t.Fatalf("invite=%+v", invite)
			}
		})
	}
	invite, err := ReadImage(clipboardImage)
	if err != nil {
		t.Fatal(err)
	}
	if invite.Token != token || invite.Endpoint != "https://control.example/api/client/enroll" {
		t.Fatalf("clipboard invite=%+v", invite)
	}
}

func TestReadRejectsUnrelatedOrLinkedArtifactsWithoutLeakingInput(t *testing.T) {
	dir := t.TempDir()
	badURI := "loom://not-a-join#this-value-must-not-appear"
	if _, err := Read("", strings.NewReader(badURI)); err == nil || strings.Contains(err.Error(), badURI) {
		t.Fatalf("bad URI error=%v", err)
	}
	otherQR, err := qrcodeencoder.Encode("https://example.com/not-loom", qrcodeencoder.Medium, 256)
	if err != nil {
		t.Fatal(err)
	}
	otherPath := filepath.Join(dir, "other.png")
	if err := os.WriteFile(otherPath, otherQR, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Read(otherPath, nil); err == nil || strings.Contains(err.Error(), "not-loom") {
		t.Fatalf("unrelated QR error=%v", err)
	}
	linkPath := filepath.Join(dir, "linked.png")
	if err := os.Symlink(otherPath, linkPath); err == nil {
		if _, err := Read(linkPath, nil); err == nil {
			t.Fatal("symlinked QR was accepted")
		}
	}
}

func TestReadBoundsStdin(t *testing.T) {
	if _, err := Read("", bytes.NewReader(bytes.Repeat([]byte{'x'}, maxJoinInputBytes+1))); err == nil {
		t.Fatal("oversized join input was accepted")
	}
}

func TestReadRejectsOversizedPNGDimensions(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "too-wide.png")
	var body bytes.Buffer
	if err := png.Encode(&body, image.NewGray(image.Rect(0, 0, maxQRImageSide+1, 1))); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, body.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Read(path, nil); err == nil {
		t.Fatal("oversized PNG dimensions were accepted")
	}
	if _, err := ReadImage(image.NewGray(image.Rect(0, 0, maxQRImageSide+1, 1))); err == nil {
		t.Fatal("oversized clipboard image was accepted")
	}
}

func testJoinURI(t *testing.T) (string, string) {
	t.Helper()
	token := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x42}, 32))
	body, err := json.Marshal(struct {
		Schema    int    `json:"schema"`
		Endpoint  string `json:"endpoint"`
		Token     string `json:"token"`
		ExpiresAt string `json:"expires_at"`
	}{Schema: 1, Endpoint: "https://control.example/api/client/enroll", Token: token, ExpiresAt: "2030-01-01T00:00:00Z"})
	if err != nil {
		t.Fatal(err)
	}
	return "loom://enroll#" + base64.RawURLEncoding.EncodeToString(body), token
}

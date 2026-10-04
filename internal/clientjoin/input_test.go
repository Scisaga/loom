package clientjoin

import (
	"bytes"
	"compress/zlib"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"image"
	"image/png"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	qrcodeencoder "github.com/skip2/go-qrcode"

	"loom/internal/control"
)

func TestReadEquivalentJoinInputs(t *testing.T) {
	raw, transactionID := testJoinURI(t)
	dir := t.TempDir()
	textPath := filepath.Join(dir, "device.loom-invite")
	if err := os.WriteFile(textPath, []byte(raw+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	pngBody, err := qrcodeencoder.Encode(raw, qrcodeencoder.Medium, -5)
	if err != nil {
		t.Fatalf("complete schema3 invite: %d bytes; QR medium: %v", len(raw), err)
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
			if invite.Material.Payload.(control.Invite).ID != transactionID {
				t.Fatalf("invite=%+v", invite)
			}
		})
	}
	invite, err := ReadImage(clipboardImage)
	if err != nil {
		t.Fatal(err)
	}
	if invite.Material.Payload.(control.Invite).ID != transactionID {
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
	public, private, _ := ed25519.GenerateKey(rand.Reader)
	member := control.Member{ControlID: "demo-control", NodeID: "demo-node", PublicKey: base64.RawURLEncoding.EncodeToString(public)}
	otherPublic, _, _ := ed25519.GenerateKey(rand.Reader)
	other := control.Member{ControlID: "demo-control-b", NodeID: "demo-node-b", PublicKey: base64.RawURLEncoding.EncodeToString(otherPublic)}
	config := control.ControlConfig{Schema: 3, NetworkID: "demo-network", Operation: "genesis", Members: []control.Member{member, other}, SealedKeys: []control.ControlSealedKey{}}
	adminPublic, adminPrivate, _ := ed25519.GenerateKey(rand.Reader)
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "demo-admin"}, NotBefore: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), NotAfter: time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, adminPublic, adminPrivate)
	if err != nil {
		t.Fatal(err)
	}
	keyID, _ := control.KeyID(member.PublicKey)
	genesis, err := control.SignMaterial(control.Material{Schema: 3, NetworkID: "demo-network", IssuerControlID: member.ControlID, IssuerKeyID: keyID, Operation: "genesis", Payload: control.Genesis{ControlConfig: config, NetworkIntent: control.EmptyNetworkIntent(), AdminCertificates: []control.AdminCertificate{{ID: "demo-admin", CertificateDER: base64.RawURLEncoding.EncodeToString(der)}}}}, private)
	if err != nil {
		t.Fatal(err)
	}
	anchor, _ := control.MaterialID(genesis)
	configID, _ := control.ConfigID(config)
	endpoint := control.EndpointGeneration{ID: "demo-entry", Generation: 1, OwnerControlID: member.ControlID, Host: "192.0.2.1", Port: 443, ServerName: "demo.example", SPKISHA256: "sha256:" + strings.Repeat("1", 64), CertificateDigest: "sha256:" + strings.Repeat("2", 64), Modes: []string{"bootstrap", "device"}, State: "serving"}
	invitation := control.Invite{ID: "demo-transaction", GenesisDigest: anchor, IssuerControlID: member.ControlID, DeviceID: "demo-access", Name: "Demo access", Responsibilities: []string{"access"}, PolicyIDs: []string{}, Medium: "qr", Endpoint: endpoint, ExpiresAt: 1893456000000}
	material, err := control.SignMaterial(control.Material{Schema: 3, NetworkID: "demo-network", IssuerControlID: member.ControlID, IssuerKeyID: keyID, ControlConfigID: configID, Sequence: 1, PreviousMaterialID: control.EmptyMaterialChainID(), Dependencies: []string{}, RequestID: "demo-issue", TargetKind: "invite", TargetID: invitation.ID, Operation: "invite.issue", Payload: invitation}, private)
	if err != nil {
		t.Fatal(err)
	}
	invite := control.BootstrapInvite{Schema: 3, NetworkID: "demo-network", GenesisDigest: anchor, ControlProof: control.ControlProof{Genesis: genesis, Successors: []control.ControlCertificate{}}, Material: material}
	raw, err := control.EncodeInvite(invite)
	if err != nil {
		t.Fatal(err)
	}
	return raw, invitation.ID
}

func TestInviteCompressedDeliveryRejectsAlternateOrTrailingStreams(t *testing.T) {
	raw, _ := testJoinURI(t)
	invite, err := control.DecodeInvite(raw)
	if err != nil {
		t.Fatal(err)
	}
	body, err := control.CanonicalEncode(invite)
	if err != nil {
		t.Fatal(err)
	}
	compressed, _ := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(raw, "loom://enroll#"))
	var alternate bytes.Buffer
	w, _ := zlib.NewWriterLevel(&alternate, zlib.BestSpeed)
	_, _ = w.Write(body)
	_ = w.Close()
	var bomb bytes.Buffer
	w = zlib.NewWriter(&bomb)
	_, _ = w.Write(bytes.Repeat([]byte{'x'}, (8<<20)+1))
	_ = w.Close()
	for _, bad := range [][]byte{body, append(append([]byte{}, compressed...), 0), append(append([]byte{}, compressed...), compressed...), alternate.Bytes(), bomb.Bytes()} {
		if _, err := control.DecodeInvite("loom://enroll#" + base64.RawURLEncoding.EncodeToString(bad)); err == nil {
			t.Fatal("alternate, trailing, concatenated or oversized delivery accepted")
		}
	}
	for _, bad := range []string{" " + raw, raw + " ", "\t" + raw} {
		if _, err := Read(bad, nil); err == nil {
			t.Fatal("padded invitation URI accepted")
		}
	}
	oldURI := "loom://enroll#" + base64.RawURLEncoding.EncodeToString(body)
	if _, err := qrcodeencoder.Encode(oldURI, qrcodeencoder.Low, 1024); err == nil {
		t.Fatal("fixture no longer demonstrates the full-proof QR capacity boundary")
	}
	if _, err := qrcodeencoder.Encode(raw, qrcodeencoder.Medium, -5); err != nil {
		t.Fatalf("compressed complete two-member proof and admin leaf do not fit: %v", err)
	}
	t.Logf("demo complete proof: members=2 admin_leaf_DER=%d C=%d original_URI=%d zlib=%d compressed_URI=%d", len(mustDemoAdminDER(t, invite)), len(body), len(oldURI), len(compressed), len(raw))
}
func mustDemoAdminDER(t *testing.T, invite control.BootstrapInvite) []byte {
	t.Helper()
	body, err := base64.RawURLEncoding.DecodeString(invite.ControlProof.Genesis.Payload.(control.Genesis).AdminCertificates[0].CertificateDER)
	if err != nil {
		t.Fatal(err)
	}
	return body
}

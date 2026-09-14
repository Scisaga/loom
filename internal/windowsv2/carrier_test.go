package windowsv2

import (
	"bytes"
	"image/png"
	"os"
	"path/filepath"
	"testing"

	qrcodeencoder "github.com/skip2/go-qrcode"

	"loom/internal/clientv2"
	"loom/internal/wire"
)

func TestWindowsEnrollmentCarrierKeepsInviteAndResumeDistinct(t *testing.T) {
	invite := wire.InviteBootstrapDescriptorV2{Schema: 2, ClusterID: "cluster-demo"}
	inviteBody, err := wire.MarshalCanonical(invite)
	if err != nil {
		t.Fatal(err)
	}
	carrier, err := DecodeEnrollmentCarrierText(string(inviteBody))
	if err != nil || carrier.Invite == nil || carrier.Resume != nil ||
		!wire.EqualCanonical(*carrier.Invite, invite) {
		t.Fatalf("invite carrier=%+v err=%v", carrier, err)
	}
	resume := wire.EnrollmentResumeDescriptorV1{Schema: 1, ClusterID: "cluster-demo"}
	resumeBody, err := wire.MarshalCanonical(resume)
	if err != nil {
		t.Fatal(err)
	}
	carrier, err = DecodeEnrollmentCarrierText(string(resumeBody))
	if err != nil || carrier.Resume == nil || carrier.Invite != nil ||
		!wire.EqualCanonical(*carrier.Resume, resume) {
		t.Fatalf("resume carrier=%+v err=%v", carrier, err)
	}
	if _, err := DecodeEnrollmentCarrierText(string(inviteBody) + "\n"); err == nil {
		t.Fatal("接受了带尾随空白的 exact carrier")
	}
}

func TestWindowsEnrollmentCarrierReadsURIFileQRAndRejectsSymlink(t *testing.T) {
	descriptor := wire.InviteBootstrapDescriptorV2{Schema: 2, ClusterID: "cluster-demo"}
	uri, err := clientv2.EncodeInviteURI(&descriptor)
	if err != nil {
		t.Fatal(err)
	}
	if carrier, err := ReadEnrollmentCarrier(uri); err != nil || carrier.Invite == nil {
		t.Fatalf("URI carrier=%+v err=%v", carrier, err)
	}
	directory := t.TempDir()
	body, _ := wire.MarshalCanonical(descriptor)
	path := filepath.Join(directory, "device.loom-invite")
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}
	if carrier, err := ReadEnrollmentCarrier(path); err != nil || carrier.Invite == nil {
		t.Fatalf("file carrier=%+v err=%v", carrier, err)
	}
	linked := filepath.Join(directory, "linked.loom-invite")
	if err := os.Symlink(path, linked); err == nil {
		if _, err := ReadEnrollmentCarrier(linked); err == nil {
			t.Fatal("接受了 symlink carrier")
		}
	}
	pngBody, err := qrcodeencoder.Encode(uri, qrcodeencoder.Medium, 1024)
	if err != nil {
		t.Fatal(err)
	}
	imageValue, err := png.Decode(bytes.NewReader(pngBody))
	if err != nil {
		t.Fatal(err)
	}
	decodedText, decodeErr := decodeWindowsQRImage(imageValue)
	if decodeErr != nil || decodedText != uri {
		t.Fatalf("QR text length=%d want=%d err=%v", len(decodedText), len(uri), decodeErr)
	}
	if carrier, err := ReadEnrollmentCarrierImage(imageValue); err != nil || carrier.Invite == nil {
		t.Fatalf("QR carrier=%+v err=%v", carrier, err)
	}
}

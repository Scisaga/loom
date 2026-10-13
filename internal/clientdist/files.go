package clientdist

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// Published holds the exact captured archive descriptor and bounded metadata.
// Close must follow every successful verification, including metadata-only use.
type Published struct {
	Manifest                       Manifest
	SHA256                         string
	Size                           int64
	Archive                        *os.File
	Checksum, Signature, PublicKey []byte
	capture                        *packageInput
}

func (v Published) Close() error {
	if v.capture == nil {
		return nil
	}
	return v.capture.close()
}

func VerifyFiles(archivePath, publicKeyPath string) (Published, error) {
	return VerifyFilesAt(context.Background(), archivePath, publicKeyPath, "")
}

func VerifyFilesAt(ctx context.Context, archivePath, publicKeyPath, workRoot string) (Published, error) {
	return VerifyFilesWithPathsAt(ctx, archivePath, archivePath+".sha256", archivePath+".sig", publicKeyPath, workRoot)
}

func VerifyFilesWithPathsAt(ctx context.Context, archivePath, checksumPath, signaturePath, publicKeyPath, workRoot string) (result Published, resultErr error) {
	var zero Published
	var capture *packageInput
	defer func() {
		if resultErr != nil && capture != nil {
			resultErr = errors.Join(resultErr, capture.close())
			result = zero
		}
	}()
	if workRoot == "" {
		absolute, err := filepath.Abs(archivePath)
		if err != nil {
			return zero, err
		}
		workRoot = filepath.Dir(absolute)
	}
	checksum, err := readRegularBounded(checksumPath, 4<<10)
	if err != nil {
		return zero, err
	}
	signature, err := readRegularBounded(signaturePath, 16<<10)
	if err != nil {
		return zero, err
	}
	publicBody, err := readRegularBounded(publicKeyPath, 4<<10)
	if err != nil {
		return zero, err
	}
	public, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(publicBody)))
	if err != nil {
		public, err = base64.RawStdEncoding.DecodeString(strings.TrimSpace(string(publicBody)))
	}
	if err != nil || len(public) != ed25519.PublicKeySize {
		return zero, errors.New("independent Linux installation public key is invalid")
	}
	entry, err := os.Lstat(archivePath)
	if err != nil || !entry.Mode().IsRegular() || entry.Size() <= 0 || entry.Size() > maxArchiveBytes || !packageFileLinks(entry) {
		return zero, errors.New("archive is not a bounded ordinary file")
	}
	source, err := os.Open(archivePath)
	if err != nil {
		return zero, err
	}
	defer func() { resultErr = errors.Join(resultErr, source.Close()) }()
	input := &packageFileInput{path: archivePath, size: entry.Size(), file: source, entry: entry}
	if err := input.stable(); err != nil {
		return zero, err
	}
	capture, err = newPackageCapture(workRoot)
	if err != nil {
		return zero, err
	}
	if err := capturePackageMember(ctx, capture, "archive", input.size, io.NewSectionReader(source, 0, input.size), make([]byte, packageCopyBuffer)); err != nil {
		return zero, err
	}
	if err := input.stable(); err != nil {
		return zero, err
	}
	archive := capture.files["archive"]
	archive.digest, err = hashPackageInput(ctx, archive, make([]byte, packageCopyBuffer))
	if err != nil {
		return zero, err
	}
	verified, err := VerifyArchiveFile(ctx, archive.file, ed25519.PublicKey(public), capture.root)
	if err != nil {
		return zero, err
	}
	defer func() { resultErr = errors.Join(resultErr, verified.Close()) }()
	name := "loom-client-linux-" + verified.Manifest.Arch + ".tar.gz"
	if filepath.Base(archivePath) != name {
		return zero, errors.New("Linux archive filename differs from architecture")
	}
	if !strings.HasSuffix(string(checksum), "\n") || string(checksum) != fmt.Sprintf("%s  %s\n", archive.digest, name) {
		return zero, errors.New("Linux archive checksum differs or is not canonical")
	}
	if string(signature) != string(verified.Signature) {
		return zero, errors.New("detached and embedded manifest signatures differ")
	}
	return Published{Manifest: verified.Manifest, SHA256: archive.digest, Size: archive.size, Archive: archive.file, Checksum: checksum, Signature: signature, PublicKey: publicBody, capture: capture}, nil
}

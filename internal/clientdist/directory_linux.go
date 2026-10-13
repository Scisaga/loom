package clientdist

import (
	"context"
	"crypto/ed25519"
	"errors"
	"path/filepath"
)

// VerifyDirectory captures input before inspecting it; installation consumes
// the same fixed files rather than reopening untrusted input paths.
func VerifyDirectory(directory string, public ed25519.PublicKey) (VerifiedDirectory, error) {
	return VerifyDirectoryAt(context.Background(), directory, public, "")
}

func VerifyDirectoryAt(ctx context.Context, directory string, public ed25519.PublicKey, workRoot string) (VerifiedDirectory, error) {
	if workRoot == "" {
		absolute, err := filepath.Abs(directory)
		if err != nil {
			return VerifiedDirectory{}, err
		}
		workRoot = filepath.Dir(absolute)
	}
	input, err := capturePackageDirectory(ctx, directory, workRoot)
	if err != nil {
		return VerifiedDirectory{}, err
	}
	value, err := verifyPackageInput(ctx, input, public)
	if err != nil {
		return VerifiedDirectory{}, errors.Join(err, input.close())
	}
	return value, nil
}

// This only observes a root-protected accepted directory. It neither captures
// payloads nor reconstructs an archive, and it does not install any new value.
func VerifyInstalledDirectory(ctx context.Context, directory string, public ed25519.PublicKey) (VerifiedDirectory, error) {
	if err := checkDirectory(directory, 0755, false); err != nil {
		return VerifiedDirectory{}, err
	}
	input, err := openPackageDirectory(ctx, directory, true)
	if err != nil {
		return VerifiedDirectory{}, err
	}
	value, err := verifyPackageInput(ctx, input, public)
	if err != nil {
		return VerifiedDirectory{}, errors.Join(err, input.close())
	}
	return value, nil
}

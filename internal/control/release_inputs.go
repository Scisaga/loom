package control

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"io"
	"os"
	"strings"
)

// ReadReleasePublicKey reads the independently installed public trust input.
// Package or catalog contents never supply this trust root.
func ReadReleasePublicKey(path string) (ed25519.PublicKey, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0o022 != 0 || info.Size() > 4096 {
		return nil, errors.New("release public key input is not protected")
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil || !os.SameFile(info, opened) {
		return nil, errors.New("release public key input changed while opening")
	}
	body, err := io.ReadAll(io.LimitReader(f, 4097))
	if err != nil || len(body) > 4096 {
		return nil, errors.New("release public key input exceeds its boundary")
	}
	key, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(body)))
	if err != nil || len(key) != ed25519.PublicKeySize {
		return nil, errors.New("release public key input is invalid")
	}
	return ed25519.PublicKey(key), nil
}

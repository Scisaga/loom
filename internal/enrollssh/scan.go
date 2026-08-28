package enrollssh

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// HostKey is the public result presented to an operator for confirmation.
// PublicKey is the base64 OpenSSH wire blob, never private material.
type HostKey struct {
	Algorithm   string
	PublicKey   string
	Fingerprint string
}

// Scanner obtains only an Ed25519 host key. Timeout is both an overall context
// deadline and the basis of ssh-keyscan's own connection timeout.
type Scanner struct {
	Runner      Runner
	Timeout     time.Duration
	OutputLimit int
}

// Scan runs ssh-keyscan directly and computes the OpenSSH SHA256 fingerprint
// locally. Multiple returned addresses are accepted only when they present the
// identical key.
func (s Scanner) Scan(ctx context.Context, connection Connection) (HostKey, error) {
	if err := connection.Validate(); err != nil {
		return HostKey{}, err
	}
	timeoutDuration, err := timeout(s.Timeout, defaultScanTimeout)
	if err != nil {
		return HostKey{}, fmt.Errorf("invalid scan timeout: %w", err)
	}
	limit, err := outputLimit(s.OutputLimit)
	if err != nil {
		return HostKey{}, fmt.Errorf("invalid scan output limit: %w", err)
	}
	seconds := int((timeoutDuration + time.Second - 1) / time.Second)
	if seconds < 1 {
		seconds = 1
	}
	if seconds > 60 {
		seconds = 60
	}
	scanCtx, cancel := context.WithTimeout(ctx, timeoutDuration)
	defer cancel()
	invocation := Invocation{
		Program: "ssh-keyscan",
		Args: []string{
			"-T", strconv.Itoa(seconds),
			"-p", strconv.Itoa(connection.Port),
			"-t", "ed25519",
			connection.Host,
		},
		StdoutLimit: limit,
		StderrLimit: limit,
	}
	result, runErr := runnerOrDefault(s.Runner).Run(scanCtx, invocation)
	if err := commandError("scan SSH Ed25519 host key", scanCtx, result, runErr); err != nil {
		return HostKey{}, err
	}
	hostKey, err := parseKeyscan(result.Stdout)
	if err != nil {
		return HostKey{}, fmt.Errorf("invalid ssh-keyscan output: %w", err)
	}
	return hostKey, nil
}

func parseKeyscan(output []byte) (HostKey, error) {
	var found HostKey
	for _, raw := range strings.Split(string(output), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 3 {
			return HostKey{}, errors.New("host-key line does not contain host, algorithm, and key")
		}
		if fields[1] != "ssh-ed25519" {
			continue
		}
		key, err := hostKeyForBlob(fields[2])
		if err != nil {
			return HostKey{}, err
		}
		if found.Algorithm == "" {
			found = key
			continue
		}
		if !sameHostKey(found, key) {
			return HostKey{}, errors.New("target returned more than one Ed25519 host key")
		}
	}
	if found.Algorithm == "" {
		return HostKey{}, errors.New("no Ed25519 host key was returned")
	}
	return found, nil
}

func hostKeyForBlob(encoded string) (HostKey, error) {
	blob, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return HostKey{}, errors.New("Ed25519 host key is not valid base64")
	}
	if err := validateEd25519Blob(blob); err != nil {
		return HostKey{}, err
	}
	sum := sha256.Sum256(blob)
	return HostKey{
		Algorithm:   "ssh-ed25519",
		PublicKey:   encoded,
		Fingerprint: "SHA256:" + base64.RawStdEncoding.EncodeToString(sum[:]),
	}, nil
}

func validateEd25519Blob(blob []byte) error {
	algorithm, rest, ok := wireString(blob)
	if !ok || string(algorithm) != "ssh-ed25519" {
		return errors.New("host key is not an OpenSSH Ed25519 key blob")
	}
	public, rest, ok := wireString(rest)
	if !ok || len(public) != 32 || len(rest) != 0 {
		return errors.New("OpenSSH Ed25519 host key has an invalid payload")
	}
	return nil
}

func wireString(input []byte) ([]byte, []byte, bool) {
	if len(input) < 4 {
		return nil, nil, false
	}
	n := int(binary.BigEndian.Uint32(input[:4]))
	if n < 0 || n > len(input)-4 {
		return nil, nil, false
	}
	return input[4 : 4+n], input[4+n:], true
}

func validateHostKey(key HostKey) error {
	if key.Algorithm != "ssh-ed25519" {
		return errors.New("confirmed host key algorithm must be ssh-ed25519")
	}
	recomputed, err := hostKeyForBlob(key.PublicKey)
	if err != nil {
		return err
	}
	if subtle.ConstantTimeCompare([]byte(recomputed.Fingerprint), []byte(key.Fingerprint)) != 1 {
		return errors.New("confirmed host key fingerprint does not match its public key")
	}
	return nil
}

func sameHostKey(a, b HostKey) bool {
	return a.Algorithm == b.Algorithm &&
		subtle.ConstantTimeCompare([]byte(a.PublicKey), []byte(b.PublicKey)) == 1 &&
		subtle.ConstantTimeCompare([]byte(a.Fingerprint), []byte(b.Fingerprint)) == 1
}

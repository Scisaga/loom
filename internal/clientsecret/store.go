// Package clientsecret stores Windows-client secret material behind a small,
// testable protection boundary. The production protector is DPAPI machine
// scope; tests use an in-memory substitute and never weaken the Windows build.
package clientsecret

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"unicode"
)

const (
	EnvelopeSchema = 1
	VaultSchema    = 1
	VaultPurpose   = "secrets-v1"
	// Secret maps stay within 1 MiB. Generic protected JSON also carries the
	// validated ready response, whose wire protocol is bounded at 4 MiB; keep a
	// small serialization margin so a legal response can always be journaled.
	maxSecretPlaintext    = 1 << 20
	maxProtectedPlaintext = 5 << 20
	maxCiphertext         = 6 << 20
)

// Protector binds ciphertext to a purpose. Implementations must reject a blob
// protected for another purpose so secrets and hydrated configs cannot be
// swapped even when both are valid protected byte strings.
type Protector interface {
	Protect(purpose string, plaintext []byte) ([]byte, error)
	Unprotect(purpose string, ciphertext []byte) ([]byte, error)
}

type sealedEnvelope struct {
	Schema     int    `json:"schema"`
	Purpose    string `json:"purpose"`
	Ciphertext string `json:"ciphertext"`
}

type vaultPayload struct {
	Schema  int               `json:"schema"`
	Secrets map[string]string `json:"secrets"`
}

// ParseEnv converts the ready-bootstrap ref=value representation without
// persisting its plaintext. Empty values, duplicate refs, and multiline values
// are rejected at the secret boundary.
func ParseEnv(body string) (map[string]string, error) {
	if len(body) == 0 || len(body) > maxSecretPlaintext {
		return nil, errors.New("secret bootstrap must be between 1 byte and 1 MiB")
	}
	out := map[string]string{}
	scanner := bufio.NewScanner(strings.NewReader(body))
	scanner.Buffer(make([]byte, 4096), maxSecretPlaintext)
	for lineNumber := 1; scanner.Scan(); lineNumber++ {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		ref, value, ok := strings.Cut(line, "=")
		ref, value = strings.TrimSpace(ref), strings.TrimSpace(value)
		if !ok || !validRef(ref) || value == "" || len(value) > 64<<10 ||
			strings.ContainsAny(value, "\r\n") {
			return nil, fmt.Errorf("invalid secret bootstrap line %d", lineNumber)
		}
		if _, duplicate := out[ref]; duplicate {
			return nil, fmt.Errorf("duplicate secret ref on line %d", lineNumber)
		}
		out[ref] = value
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scan secret bootstrap: %w", err)
	}
	if len(out) == 0 {
		return nil, errors.New("secret bootstrap contains no entries")
	}
	return out, nil
}

func WriteVault(path string, secrets map[string]string, protector Protector) error {
	if err := validateSecrets(secrets); err != nil {
		return err
	}
	body, err := json.Marshal(&vaultPayload{Schema: VaultSchema, Secrets: secrets})
	if err != nil {
		return err
	}
	defer clear(body)
	return WriteProtected(path, VaultPurpose, body, protector)
}

func ReadVault(path string, protector Protector) (map[string]string, error) {
	body, err := ReadProtected(path, VaultPurpose, protector)
	if err != nil {
		return nil, err
	}
	defer clear(body)
	var payload vaultPayload
	if err := decodeStrict(body, maxSecretPlaintext, &payload); err != nil {
		return nil, fmt.Errorf("decode protected secret vault: %w", err)
	}
	if payload.Schema != VaultSchema {
		return nil, fmt.Errorf("unsupported secret vault schema %d", payload.Schema)
	}
	if err := validateSecrets(payload.Secrets); err != nil {
		return nil, err
	}
	out := make(map[string]string, len(payload.Secrets))
	for ref, value := range payload.Secrets {
		out[ref] = value
	}
	return out, nil
}

func WriteJSONProtected(path, purpose string, value any, protector Protector) error {
	body, err := json.Marshal(value)
	if err != nil {
		return err
	}
	defer clear(body)
	return WriteProtected(path, purpose, body, protector)
}

func ReadJSONProtected(path, purpose string, target any, protector Protector) error {
	body, err := ReadProtected(path, purpose, protector)
	if err != nil {
		return err
	}
	defer clear(body)
	return decodeStrict(body, maxProtectedPlaintext, target)
}

func WriteProtected(path, purpose string, plaintext []byte, protector Protector) error {
	if protector == nil {
		return errors.New("secret protector is nil")
	}
	if err := validateProtectedPath(path); err != nil {
		return err
	}
	if err := validatePurpose(purpose); err != nil {
		return err
	}
	if len(plaintext) == 0 || len(plaintext) > maxProtectedPlaintext {
		return errors.New("protected plaintext must be between 1 byte and 5 MiB")
	}
	ciphertext, err := protector.Protect(purpose, plaintext)
	if err != nil {
		return fmt.Errorf("protect %s: %w", purpose, err)
	}
	defer clear(ciphertext)
	if len(ciphertext) == 0 || len(ciphertext) > maxCiphertext {
		return errors.New("protector returned invalid ciphertext size")
	}
	envelope := sealedEnvelope{
		Schema: EnvelopeSchema, Purpose: purpose,
		Ciphertext: base64.StdEncoding.EncodeToString(ciphertext),
	}
	body, err := json.MarshalIndent(&envelope, "", "  ")
	if err != nil {
		return err
	}
	return writeAtomic(path, append(body, '\n'))
}

func ReadProtected(path, purpose string, protector Protector) ([]byte, error) {
	if protector == nil {
		return nil, errors.New("secret protector is nil")
	}
	if err := validateProtectedPath(path); err != nil {
		return nil, err
	}
	if err := validatePurpose(purpose); err != nil {
		return nil, err
	}
	body, err := readRegular(path, maxCiphertext*2)
	if err != nil {
		return nil, err
	}
	var envelope sealedEnvelope
	if err := decodeStrict(body, maxCiphertext*2, &envelope); err != nil {
		return nil, fmt.Errorf("decode protected envelope: %w", err)
	}
	if envelope.Schema != EnvelopeSchema || envelope.Purpose != purpose {
		return nil, errors.New("protected envelope schema or purpose mismatch")
	}
	ciphertext, err := base64.StdEncoding.Strict().DecodeString(envelope.Ciphertext)
	if err != nil || base64.StdEncoding.EncodeToString(ciphertext) != envelope.Ciphertext ||
		len(ciphertext) == 0 || len(ciphertext) > maxCiphertext {
		return nil, errors.New("protected envelope has invalid canonical ciphertext")
	}
	defer clear(ciphertext)
	plaintext, err := protector.Unprotect(purpose, ciphertext)
	if err != nil {
		return nil, fmt.Errorf("unprotect %s: %w", purpose, err)
	}
	if len(plaintext) == 0 || len(plaintext) > maxProtectedPlaintext {
		clear(plaintext)
		return nil, errors.New("protector returned invalid plaintext size")
	}
	return plaintext, nil
}

func validateSecrets(secrets map[string]string) error {
	if len(secrets) == 0 || len(secrets) > 4096 {
		return errors.New("secret vault must contain between 1 and 4096 entries")
	}
	total := 0
	for ref, value := range secrets {
		if !validRef(ref) || value == "" || len(value) > 64<<10 || strings.ContainsAny(value, "\r\n") {
			return fmt.Errorf("invalid secret entry %q", ref)
		}
		total += len(ref) + len(value)
		if total > maxSecretPlaintext {
			return errors.New("secret vault exceeds 1 MiB")
		}
	}
	return nil
}

func validRef(ref string) bool {
	return ref != "" && len(ref) <= 256 && !strings.ContainsAny(ref, "}=") &&
		strings.IndexFunc(ref, unicode.IsSpace) < 0 && strings.IndexFunc(ref, unicode.IsControl) < 0
}

func validatePurpose(purpose string) error {
	if purpose == "" || len(purpose) > 64 {
		return errors.New("protection purpose must be 1-64 bytes")
	}
	for _, character := range []byte(purpose) {
		if (character < 'a' || character > 'z') && (character < '0' || character > '9') && character != '-' {
			return fmt.Errorf("invalid protection purpose %q", purpose)
		}
	}
	return nil
}

func decodeStrict(body []byte, maximum int, target any) error {
	if len(body) == 0 || len(body) > maximum {
		return errors.New("JSON body has invalid size")
	}
	if err := rejectDuplicateJSONKeys(body); err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return errors.New("JSON body has trailing content")
	}
	return nil
}

func rejectDuplicateJSONKeys(body []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.UseNumber()
	if err := walkJSONValue(decoder); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return errors.New("JSON body has trailing content")
	}
	return nil
}

func walkJSONValue(decoder *json.Decoder) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delimiter {
	case '{':
		seen := map[string]bool{}
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return err
			}
			key, ok := keyToken.(string)
			if !ok {
				return errors.New("JSON object key is not a string")
			}
			if seen[key] {
				return fmt.Errorf("duplicate JSON field %q", key)
			}
			seen[key] = true
			if err := walkJSONValue(decoder); err != nil {
				return err
			}
		}
		_, err = decoder.Token()
		return err
	case '[':
		for decoder.More() {
			if err := walkJSONValue(decoder); err != nil {
				return err
			}
		}
		_, err = decoder.Token()
		return err
	default:
		return errors.New("unexpected JSON delimiter")
	}
}

func readRegular(path string, maximum int64) ([]byte, error) {
	before, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !before.Mode().IsRegular() || before.Mode()&os.ModeSymlink != 0 ||
		before.Size() < 0 || before.Size() > maximum {
		return nil, fmt.Errorf("%s is not a bounded regular file", path)
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	after, err := file.Stat()
	if err != nil || !after.Mode().IsRegular() || !os.SameFile(before, after) ||
		after.Size() != before.Size() || after.Size() < 0 || after.Size() > maximum {
		return nil, fmt.Errorf("%s changed while opening", path)
	}
	body, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil {
		clear(body)
		return nil, err
	}
	if int64(len(body)) != after.Size() || int64(len(body)) > maximum {
		clear(body)
		return nil, fmt.Errorf("%s changed while reading", path)
	}
	return body, nil
}

func writeAtomic(path string, body []byte) (retErr error) {
	if err := validateProtectedPath(path); err != nil {
		return err
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	file, err := os.CreateTemp(dir, "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	temporary := file.Name()
	defer func() {
		_ = file.Close()
		if retErr != nil {
			_ = os.Remove(temporary)
		}
	}()
	if err := file.Chmod(0o600); err != nil {
		return err
	}
	if _, err := file.Write(body); err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	if err := replaceFile(temporary, path); err != nil {
		return err
	}
	return syncDirectory(dir)
}

func validateProtectedPath(path string) error {
	if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return fmt.Errorf("protected path must be absolute and clean: %q", path)
	}
	return nil
}

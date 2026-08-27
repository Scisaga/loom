// Package releasefloor persists the newest signed-current generation accepted by
// a node.  The record is deliberately small: it is a monotonic floor, not a
// second copy of the release manifest.
package releasefloor

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

const (
	CurrentSchema = 1
	// Path is the node-local monotonic floor used by the production pull unit.
	// Tests and recovery tooling may override it explicitly.
	Path = "/var/lib/loom/release-floor.json"
)

var (
	// ErrStaleGeneration means a signed current is older than the persisted
	// floor and must not be replayed.
	ErrStaleGeneration = errors.New("signed current generation is below the persisted floor")
	// ErrGenerationConflict means two different payloads claim the same
	// generation.  Accepting either one would make the generation ambiguous.
	ErrGenerationConflict = errors.New("signed current generation has a different payload")
)

// Record is the durable anti-replay floor for signed current.
type Record struct {
	Schema           int    `json:"schema"`
	Generation       uint64 `json:"generation"`
	PayloadSHA256    string `json:"payload_sha256"`
	SelectedSnapshot string `json:"selected_snapshot"`
}

// Read loads and strictly validates a floor record.  A missing file means that
// the node has not accepted a signed current yet and is returned as nil.
func Read(path string) (*Record, error) {
	body, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read release floor %s: %w", path, err)
	}

	if err := rejectDuplicateTopLevelKeys(body); err != nil {
		return nil, fmt.Errorf("decode release floor %s: %w", path, err)
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	var rec Record
	if err := dec.Decode(&rec); err != nil {
		return nil, fmt.Errorf("decode release floor %s: %w", path, err)
	}
	// Decode once more instead of relying on Decoder.More: More only applies to
	// arrays and objects.  Whitespace is fine; any second value or junk is not.
	var trailing any
	if err := dec.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			err = errors.New("additional JSON value")
		}
		return nil, fmt.Errorf("decode release floor %s: trailing content: %w", path, err)
	}
	if err := validate(rec); err != nil {
		return nil, fmt.Errorf("validate release floor %s: %w", path, err)
	}
	return &rec, nil
}

// Check decides whether an incoming generation and payload may advance this
// floor.  Equal generation plus equal digest is an idempotent retry; equal
// generation with different bytes is equivocation and is rejected.
func (r *Record) Check(incomingGeneration uint64, incomingDigest string) error {
	if incomingGeneration == 0 {
		return errors.New("incoming generation must be greater than zero")
	}
	if !validLowerHex(incomingDigest, 64) {
		return fmt.Errorf("invalid incoming payload_sha256 %q", incomingDigest)
	}
	if r == nil {
		return nil
	}
	if err := validate(*r); err != nil {
		return fmt.Errorf("invalid current release floor: %w", err)
	}
	switch {
	case incomingGeneration < r.Generation:
		return fmt.Errorf("%w: incoming=%d floor=%d", ErrStaleGeneration, incomingGeneration, r.Generation)
	case incomingGeneration == r.Generation && incomingDigest != r.PayloadSHA256:
		return fmt.Errorf("%w: generation=%d", ErrGenerationConflict, incomingGeneration)
	default:
		return nil
	}
}

// Advance durably replaces path with next after re-reading and checking the
// current floor.  Callers must serialize concurrent Advance calls with their
// release transaction lock; the defensive read here is still required so a
// stale caller cannot overwrite a newer floor after acquiring that lock.
func Advance(path string, next Record) error {
	if err := validate(next); err != nil {
		return fmt.Errorf("validate next release floor: %w", err)
	}
	current, err := Read(path)
	if err != nil {
		return err
	}
	if err := current.Check(next.Generation, next.PayloadSHA256); err != nil {
		return err
	}
	if current != nil && current.Generation == next.Generation && current.PayloadSHA256 == next.PayloadSHA256 {
		if current.SelectedSnapshot != next.SelectedSnapshot {
			return fmt.Errorf("generation %d and payload %s already select snapshot %s, not %s",
				next.Generation, short(next.PayloadSHA256), current.SelectedSnapshot, next.SelectedSnapshot)
		}
		return nil
	}

	body, err := json.MarshalIndent(&next, "", "  ")
	if err != nil {
		return fmt.Errorf("encode next release floor: %w", err)
	}
	return writeAtomic(path, append(body, '\n'))
}

func validate(rec Record) error {
	if rec.Schema != CurrentSchema {
		return fmt.Errorf("schema must be %d, got %d", CurrentSchema, rec.Schema)
	}
	if rec.Generation == 0 {
		return errors.New("generation must be greater than zero")
	}
	if !validLowerHex(rec.PayloadSHA256, 64) {
		return fmt.Errorf("payload_sha256 must be exactly 64 lowercase hex characters, got %q", rec.PayloadSHA256)
	}
	if !validLowerHex(rec.SelectedSnapshot, 12) {
		return fmt.Errorf("selected_snapshot must be exactly 12 lowercase hex characters, got %q", rec.SelectedSnapshot)
	}
	return nil
}

// rejectDuplicateTopLevelKeys closes encoding/json's "last key wins"
// ambiguity at the persisted anti-replay boundary. Record contains no nested
// objects, so walking the one object is sufficient and keeps this package
// independent from the wire-protocol decoder.
func rejectDuplicateTopLevelKeys(body []byte) error {
	dec := json.NewDecoder(bytes.NewReader(body))
	tok, err := dec.Token()
	if err != nil {
		return err
	}
	if tok != json.Delim('{') {
		return errors.New("release floor must be a JSON object")
	}
	seen := map[string]struct{}{}
	for dec.More() {
		keyToken, err := dec.Token()
		if err != nil {
			return err
		}
		key, ok := keyToken.(string)
		if !ok {
			return errors.New("release floor key is not a string")
		}
		if _, duplicate := seen[key]; duplicate {
			return fmt.Errorf("duplicate field %q", key)
		}
		seen[key] = struct{}{}
		var value any
		if err := dec.Decode(&value); err != nil {
			return err
		}
	}
	end, err := dec.Token()
	if err != nil {
		return err
	}
	if end != json.Delim('}') {
		return errors.New("release floor object did not terminate")
	}
	return nil
}

func validLowerHex(s string, size int) bool {
	if len(s) != size {
		return false
	}
	for i := range len(s) {
		if (s[i] < '0' || s[i] > '9') && (s[i] < 'a' || s[i] > 'f') {
			return false
		}
	}
	return true
}

func short(s string) string {
	if len(s) <= 12 {
		return s
	}
	return s[:12]
}

func writeAtomic(path string, body []byte) (retErr error) {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("create release floor directory %s: %w", dir, err)
	}
	f, err := os.CreateTemp(dir, "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return fmt.Errorf("create temporary release floor in %s: %w", dir, err)
	}
	tmp := f.Name()
	defer func() {
		_ = f.Close()
		if retErr != nil {
			_ = os.Remove(tmp)
		}
	}()
	if err := f.Chmod(0o600); err != nil {
		return fmt.Errorf("set temporary release floor permissions: %w", err)
	}
	if _, err := f.Write(body); err != nil {
		return fmt.Errorf("write temporary release floor: %w", err)
	}
	if err := f.Sync(); err != nil {
		return fmt.Errorf("sync temporary release floor: %w", err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("close temporary release floor: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("install release floor %s: %w", path, err)
	}
	parent, err := os.Open(dir)
	if err != nil {
		return fmt.Errorf("open release floor directory %s: %w", dir, err)
	}
	if err := parent.Sync(); err != nil {
		_ = parent.Close()
		return fmt.Errorf("sync release floor directory %s: %w", dir, err)
	}
	if err := parent.Close(); err != nil {
		return fmt.Errorf("close release floor directory %s: %w", dir, err)
	}
	return nil
}

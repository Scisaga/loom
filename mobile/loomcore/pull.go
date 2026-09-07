package loomcore

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"path"
	"sort"
	"strings"
	"time"
)

const currentSignatureDomain = "loom-current-v1\x00"

type deploymentAssignment struct {
	Node     string `json:"node"`
	Snapshot string `json:"snapshot"`
}

type deploymentCurrent struct {
	Schema      int                    `json:"schema"`
	Generation  uint64                 `json:"generation"`
	Snapshot    string                 `json:"snapshot"`
	Assignments []deploymentAssignment `json:"assignments,omitempty"`
	PublishedAt string                 `json:"published_at"`
	Signature   string                 `json:"signature"`
}

type deploymentCurrentPayload struct {
	Schema      int                    `json:"schema"`
	Generation  uint64                 `json:"generation"`
	Snapshot    string                 `json:"snapshot"`
	Assignments []deploymentAssignment `json:"assignments,omitempty"`
	PublishedAt string                 `json:"published_at"`
}

type releaseFloor struct {
	Schema           int    `json:"schema"`
	Generation       uint64 `json:"generation"`
	PayloadSHA256    string `json:"payload_sha256"`
	SelectedSnapshot string `json:"selected_snapshot"`
}

type currentVerification struct {
	Schema           int          `json:"schema"`
	Generation       uint64       `json:"generation"`
	PayloadSHA256    string       `json:"payload_sha256"`
	SelectedSnapshot string       `json:"selected_snapshot"`
	NextFloor        releaseFloor `json:"next_floor"`
}

type currentCandidatesWire struct {
	Schema     int                    `json:"schema"`
	Candidates []currentCandidateWire `json:"candidates"`
}

type currentCandidateWire struct {
	ID          string `json:"id"`
	CurrentJSON string `json:"current_json"`
}

type selectedCurrent struct {
	Schema           int          `json:"schema"`
	CurrentJSON      string       `json:"current_json"`
	Generation       uint64       `json:"generation"`
	PayloadSHA256    string       `json:"payload_sha256"`
	SelectedSnapshot string       `json:"selected_snapshot"`
	NextFloor        releaseFloor `json:"next_floor"`
}

type manifestWire struct {
	ID                string             `json:"id"`
	CreatedAt         string             `json:"created_at"`
	Author            string             `json:"author,omitempty"`
	SSOTHash          string             `json:"ssot_hash"`
	Binaries          []binaryRefWire    `json:"binaries,omitempty"`
	Decommissioned    []string           `json:"decommissioned,omitempty"`
	Bundles           []bundleRefWire    `json:"bundles"`
	Components        []componentRefWire `json:"components,omitempty"`
	SecretGenerations []secretRefWire    `json:"secret_generations,omitempty"`
	Skipped           []skipWire         `json:"skipped,omitempty"`
}

type bundleRefWire struct {
	Owner string `json:"owner"`
	Hash  string `json:"hash"`
}

type binaryRefWire struct {
	OS     string `json:"os"`
	Arch   string `json:"arch"`
	SHA256 string `json:"sha256"`
	Size   int    `json:"size"`
}

type componentRefWire struct {
	Node      string `json:"node"`
	SingBox   string `json:"sing_box,omitempty"`
	WireGuard string `json:"wireguard,omitempty"`
	Tailscale string `json:"tailscale,omitempty"`
	Agent     string `json:"agent,omitempty"`
}

type secretRefWire struct {
	Node       string `json:"node"`
	Generation int    `json:"generation"`
	PublicKey  string `json:"public_key,omitempty"`
}

type skipWire struct {
	Where  string `json:"where"`
	Reason string `json:"reason"`
}

type bundleWire struct {
	Owner string            `json:"owner"`
	Files map[string]string `json:"files"`
}

type componentVersions struct {
	SingBox   string `json:"sing_box,omitempty"`
	WireGuard string `json:"wireguard,omitempty"`
	Tailscale string `json:"tailscale,omitempty"`
	Agent     string `json:"agent,omitempty"`
}

type pullVerification struct {
	Schema          int               `json:"schema"`
	Generation      uint64            `json:"generation"`
	PayloadSHA256   string            `json:"payload_sha256"`
	Snapshot        string            `json:"snapshot"`
	BundleSHA256    string            `json:"bundle_sha256"`
	CanonicalBundle string            `json:"canonical_bundle"`
	Components      componentVersions `json:"components"`
	NextFloor       releaseFloor      `json:"next_floor"`
}

// VerifyCurrent authenticates and selects one signed current.json without any
// network or file access. The Android host must durably save next_floor before
// fetching immutable snapshot payload, so withholding a newer payload cannot
// reopen an older generation. expectedCurrentJSON is used only when no floor
// exists; a clean generation-1 install may omit it.
func VerifyCurrent(currentJSON, pinnedPlatformKey []byte, nodeID string, expectedCurrentJSON, floorJSON []byte) ([]byte, error) {
	verification, err := verifyCurrent(currentJSON, pinnedPlatformKey, nodeID, expectedCurrentJSON, floorJSON)
	if err != nil {
		return nil, err
	}
	return marshalCanonical(&verification)
}

// SelectVerifiedCurrents validates independently fetched mirror candidates,
// chooses the highest authenticated generation, and rejects equivocation by
// otherwise-valid mirrors at that generation. candidatesJSON has this strict
// shape: {"schema":1,"candidates":[{"id":"opaque-local-id",
// "current_json":"{...exact fetched bytes...}"}]}. The returned current_json
// preserves the winning bytes exactly; no source identifier is returned.
func SelectVerifiedCurrents(candidatesJSON, pinnedPlatformKey []byte, nodeID string,
	expectedCurrentJSON, floorJSON []byte) ([]byte, error) {
	if len(pinnedPlatformKey) != ed25519.PublicKeySize {
		return nil, errors.New("pinned platform public key has invalid length")
	}
	if !validNodeID(nodeID) {
		return nil, errors.New("invalid node_id")
	}
	var input currentCandidatesWire
	if err := decodeStrictJSON(candidatesJSON, 16*maxCurrentBytes, &input); err != nil ||
		input.Schema != 1 || len(input.Candidates) == 0 || len(input.Candidates) > 16 {
		return nil, errors.New("current mirror candidate set is invalid")
	}
	floor, err := decodeReleaseFloor(floorJSON)
	if err != nil {
		return nil, err
	}
	type validCandidate struct {
		body     []byte
		current  *deploymentCurrent
		digest   string
		selected string
	}
	valid := make([]validCandidate, 0, len(input.Candidates))
	seenIDs := map[string]bool{}
	for _, candidate := range input.Candidates {
		if candidate.ID == "" || len(candidate.ID) > 128 || strings.IndexFunc(candidate.ID, func(r rune) bool { return r < 0x20 || r == 0x7f }) >= 0 || seenIDs[candidate.ID] {
			return nil, errors.New("current mirror candidate id is invalid or duplicate")
		}
		seenIDs[candidate.ID] = true
		body := []byte(candidate.CurrentJSON)
		current, candidateErr := decodeAndVerifyCurrent(body, ed25519.PublicKey(pinnedPlatformKey))
		if candidateErr != nil {
			continue
		}
		selected, candidateErr := current.selectSnapshot(nodeID)
		if candidateErr != nil {
			continue
		}
		digest, candidateErr := current.payloadSHA256()
		if candidateErr != nil || checkReleaseFloor(floor, current.Generation, digest, selected) != nil {
			continue
		}
		valid = append(valid, validCandidate{body: body, current: current, digest: digest, selected: selected})
	}
	if len(valid) == 0 {
		return nil, fmt.Errorf("all %d distribution mirrors rejected current.json", len(input.Candidates))
	}
	winner := valid[0]
	for _, candidate := range valid[1:] {
		if candidate.current.Generation > winner.current.Generation {
			winner = candidate
		}
	}
	for _, candidate := range valid {
		if candidate.current.Generation == winner.current.Generation &&
			(candidate.digest != winner.digest || candidate.selected != winner.selected) {
			return nil, fmt.Errorf("signed mirror fork at generation %d", winner.current.Generation)
		}
	}
	if floor == nil {
		switch {
		case len(expectedCurrentJSON) > 0:
			expected, err := decodeAndVerifyCurrent(expectedCurrentJSON, ed25519.PublicKey(pinnedPlatformKey))
			if err != nil {
				return nil, fmt.Errorf("expected-current is not a valid trust anchor: %w", err)
			}
			if _, err := expected.selectSnapshot(nodeID); err != nil {
				return nil, fmt.Errorf("expected-current does not bind this device: %w", err)
			}
			if !bytes.Equal(winner.body, expectedCurrentJSON) {
				return nil, errors.New("highest valid current.json differs from expected-current trust anchor")
			}
		case winner.current.Generation != 1:
			return nil, fmt.Errorf("no release floor: first observed signed generation is %d, expected-current is required", winner.current.Generation)
		}
	}
	nextFloor := releaseFloor{
		Schema: 1, Generation: winner.current.Generation, PayloadSHA256: winner.digest,
		SelectedSnapshot: winner.selected,
	}
	return marshalCanonical(&selectedCurrent{
		Schema: 1, CurrentJSON: string(winner.body), Generation: winner.current.Generation,
		PayloadSHA256: winner.digest, SelectedSnapshot: winner.selected, NextFloor: nextFloor,
	})
}

func verifyCurrent(currentJSON, pinnedPlatformKey []byte, nodeID string, expectedCurrentJSON, floorJSON []byte) (currentVerification, error) {
	var out currentVerification
	if len(pinnedPlatformKey) != ed25519.PublicKeySize {
		return out, errors.New("pinned platform public key has invalid length")
	}
	if !validNodeID(nodeID) {
		return out, errors.New("invalid node_id")
	}
	current, err := decodeAndVerifyCurrent(currentJSON, ed25519.PublicKey(pinnedPlatformKey))
	if err != nil {
		return out, fmt.Errorf("verify signed current: %w", err)
	}
	selected, err := current.selectSnapshot(nodeID)
	if err != nil {
		return out, fmt.Errorf("signed current does not bind this device: %w", err)
	}
	digest, err := current.payloadSHA256()
	if err != nil {
		return out, err
	}
	floor, err := decodeReleaseFloor(floorJSON)
	if err != nil {
		return out, err
	}
	if err := checkReleaseFloor(floor, current.Generation, digest, selected); err != nil {
		return out, err
	}
	if floor == nil {
		switch {
		case len(expectedCurrentJSON) > 0:
			expected, err := decodeAndVerifyCurrent(expectedCurrentJSON, ed25519.PublicKey(pinnedPlatformKey))
			if err != nil {
				return out, fmt.Errorf("expected-current is not a valid trust anchor: %w", err)
			}
			if _, err := expected.selectSnapshot(nodeID); err != nil {
				return out, fmt.Errorf("expected-current does not bind this device: %w", err)
			}
			if !bytes.Equal(currentJSON, expectedCurrentJSON) {
				return out, errors.New("current.json differs from expected-current trust anchor")
			}
		case current.Generation != 1:
			return out, fmt.Errorf("no release floor: first observed signed generation is %d, expected-current is required", current.Generation)
		}
	}
	next := releaseFloor{
		Schema: 1, Generation: current.Generation, PayloadSHA256: digest, SelectedSnapshot: selected,
	}
	out = currentVerification{
		Schema: 1, Generation: current.Generation, PayloadSHA256: digest,
		SelectedSnapshot: selected, NextFloor: next,
	}
	return out, nil
}

// VerifyPull replays the complete portable trust chain over already-fetched
// bytes: signed current, anti-rollback floor, snapshot signature, manifest
// device binding, bundle owner/path safety, and the signed bundle hash. It
// returns a standalone canonical bundle string and the next durable floor.
func VerifyPull(currentJSON, snapshotJSON, snapshotSignature, bundleJSON, pinnedPlatformKey []byte,
	nodeID string, expectedCurrentJSON, floorJSON []byte) ([]byte, error) {
	current, err := verifyCurrent(currentJSON, pinnedPlatformKey, nodeID, expectedCurrentJSON, floorJSON)
	if err != nil {
		return nil, err
	}
	return verifyAuthenticatedPayload(current, snapshotJSON, snapshotSignature, bundleJSON, pinnedPlatformKey, nodeID)
}

// VerifyCachedPull replays a previously committed package after restart. A
// durable floor newer than that package is allowed: this is the expected state
// when a newer authenticated current was latched but its payload was withheld.
// An equal floor must match exactly and an older/missing floor is rejected.
// Android must keep the cached package/coordinates in authenticated app state;
// this function proves the remote signing chain, not local slot ownership.
func VerifyCachedPull(currentJSON, snapshotJSON, snapshotSignature, bundleJSON, pinnedPlatformKey []byte,
	nodeID string, floorJSON []byte) ([]byte, error) {
	if len(pinnedPlatformKey) != ed25519.PublicKeySize {
		return nil, errors.New("pinned platform public key has invalid length")
	}
	if !validNodeID(nodeID) {
		return nil, errors.New("invalid node_id")
	}
	current, err := decodeAndVerifyCurrent(currentJSON, ed25519.PublicKey(pinnedPlatformKey))
	if err != nil {
		return nil, fmt.Errorf("verify cached signed current: %w", err)
	}
	selected, err := current.selectSnapshot(nodeID)
	if err != nil {
		return nil, fmt.Errorf("cached signed current does not bind this device: %w", err)
	}
	digest, err := current.payloadSHA256()
	if err != nil {
		return nil, err
	}
	floor, err := decodeReleaseFloor(floorJSON)
	if err != nil {
		return nil, err
	}
	if floor == nil || floor.Generation < current.Generation ||
		(floor.Generation == current.Generation &&
			(floor.PayloadSHA256 != digest || floor.SelectedSnapshot != selected)) {
		return nil, errors.New("cached package is not covered by the durable release floor")
	}
	verification := currentVerification{
		Schema: 1, Generation: current.Generation, PayloadSHA256: digest,
		SelectedSnapshot: selected, NextFloor: *floor,
	}
	return verifyAuthenticatedPayload(verification, snapshotJSON, snapshotSignature, bundleJSON, pinnedPlatformKey, nodeID)
}

func verifyAuthenticatedPayload(current currentVerification, snapshotJSON, snapshotSignature, bundleJSON,
	pinnedPlatformKey []byte, nodeID string) ([]byte, error) {
	if len(snapshotJSON) == 0 || len(snapshotJSON) > maxManifestBytes {
		return nil, errors.New("snapshot manifest size is invalid")
	}
	if len(snapshotSignature) != ed25519.SignatureSize ||
		!ed25519.Verify(ed25519.PublicKey(pinnedPlatformKey), snapshotJSON, snapshotSignature) {
		return nil, errors.New("snapshot signature is missing, malformed, or invalid")
	}
	var manifest manifestWire
	if err := decodeStrictJSON(snapshotJSON, maxManifestBytes, &manifest); err != nil {
		return nil, fmt.Errorf("snapshot manifest JSON: %w", err)
	}
	wantedBundleHash, components, err := validateManifest(&manifest, current.SelectedSnapshot, nodeID)
	if err != nil {
		return nil, fmt.Errorf("snapshot manifest binding: %w", err)
	}
	var bundle bundleWire
	if err := decodeStrictJSON(bundleJSON, maxBundleBytes, &bundle); err != nil {
		return nil, fmt.Errorf("bundle JSON: %w", err)
	}
	if err := validateBundle(bundle, nodeID); err != nil {
		return nil, fmt.Errorf("bundle binding: %w", err)
	}
	bundleDigest := bundleHash(bundle.Files)
	if bundleDigest != wantedBundleHash {
		return nil, errors.New("bundle content does not match signed manifest")
	}
	canonicalBundle, err := marshalCanonical(&bundle)
	if err != nil {
		return nil, err
	}
	return marshalCanonical(&pullVerification{
		Schema: 1, Generation: current.Generation, PayloadSHA256: current.PayloadSHA256,
		Snapshot: current.SelectedSnapshot, BundleSHA256: bundleDigest,
		CanonicalBundle: string(canonicalBundle), Components: components, NextFloor: current.NextFloor,
	})
}

func decodeAndVerifyCurrent(body []byte, platformKey ed25519.PublicKey) (*deploymentCurrent, error) {
	var current deploymentCurrent
	if err := decodeStrictJSON(body, maxCurrentBytes, &current); err != nil {
		return nil, fmt.Errorf("current.json invalid: %w", err)
	}
	current.Assignments = sortedAssignments(current.Assignments)
	if err := current.validate(true); err != nil {
		return nil, fmt.Errorf("current.json invalid: %w", err)
	}
	signature, err := decodeCurrentSignature(current.Signature)
	if err != nil {
		return nil, err
	}
	message, err := current.signingBytes()
	if err != nil {
		return nil, err
	}
	if !ed25519.Verify(platformKey, message, signature) {
		return nil, errors.New("current.json signature verification failed")
	}
	return &current, nil
}

func (current *deploymentCurrent) validate(requireSignature bool) error {
	if current == nil || current.Schema != 1 {
		return errors.New("unsupported current schema")
	}
	if current.Generation == 0 {
		return errors.New("generation must be greater than zero")
	}
	if !validLowerHex(current.Snapshot, 12) {
		return errors.New("snapshot must be 12 lowercase hexadecimal characters")
	}
	seen := map[string]bool{}
	for _, assignment := range current.Assignments {
		if !validNodeID(assignment.Node) || !validLowerHex(assignment.Snapshot, 12) || seen[assignment.Node] {
			return errors.New("current.json contains an invalid or duplicate assignment")
		}
		seen[assignment.Node] = true
	}
	if current.PublishedAt == "" {
		return errors.New("published_at is empty")
	}
	if _, err := time.Parse(time.RFC3339Nano, current.PublishedAt); err != nil {
		return errors.New("published_at is not RFC3339")
	}
	if requireSignature {
		if _, err := decodeCurrentSignature(current.Signature); err != nil {
			return err
		}
	}
	return nil
}

func (current *deploymentCurrent) signingBytes() ([]byte, error) {
	payload := deploymentCurrentPayload{
		Schema: current.Schema, Generation: current.Generation, Snapshot: current.Snapshot,
		Assignments: sortedAssignments(current.Assignments), PublishedAt: current.PublishedAt,
	}
	body, err := json.Marshal(&payload)
	if err != nil {
		return nil, err
	}
	return append([]byte(currentSignatureDomain), body...), nil
}

func (current *deploymentCurrent) payloadSHA256() (string, error) {
	message, err := current.signingBytes()
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(message)
	return hex.EncodeToString(digest[:]), nil
}

func (current *deploymentCurrent) selectSnapshot(nodeID string) (string, error) {
	if !validNodeID(nodeID) {
		return "", errors.New("node id is invalid")
	}
	if err := current.validate(false); err != nil {
		return "", err
	}
	if len(current.Assignments) == 0 {
		return current.Snapshot, nil
	}
	for _, assignment := range current.Assignments {
		if assignment.Node == nodeID {
			return assignment.Snapshot, nil
		}
	}
	return "", errors.New("signed current has no assignment for this device")
}

func decodeCurrentSignature(encoded string) ([]byte, error) {
	if encoded == "" {
		return nil, errors.New("current.json has no signature")
	}
	signature, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil || len(signature) != ed25519.SignatureSize || base64.StdEncoding.EncodeToString(signature) != encoded {
		return nil, errors.New("current.json signature is not canonical base64 Ed25519")
	}
	return signature, nil
}

func sortedAssignments(assignments []deploymentAssignment) []deploymentAssignment {
	if len(assignments) == 0 {
		return nil
	}
	out := append([]deploymentAssignment(nil), assignments...)
	sort.Slice(out, func(i, j int) bool {
		if out[i].Node != out[j].Node {
			return out[i].Node < out[j].Node
		}
		return out[i].Snapshot < out[j].Snapshot
	})
	return out
}

func decodeReleaseFloor(body []byte) (*releaseFloor, error) {
	if len(body) == 0 {
		return nil, nil
	}
	var floor releaseFloor
	if err := decodeStrictJSON(body, 64<<10, &floor); err != nil {
		return nil, fmt.Errorf("release floor is invalid: %w", err)
	}
	if err := validateReleaseFloor(floor); err != nil {
		return nil, fmt.Errorf("release floor is invalid: %w", err)
	}
	return &floor, nil
}

func validateReleaseFloor(floor releaseFloor) error {
	if floor.Schema != 1 || floor.Generation == 0 || !validLowerHex(floor.PayloadSHA256, 64) ||
		!validLowerHex(floor.SelectedSnapshot, 12) {
		return errors.New("invalid schema or release coordinates")
	}
	return nil
}

func checkReleaseFloor(floor *releaseFloor, generation uint64, digest, selected string) error {
	if generation == 0 || !validLowerHex(digest, 64) || !validLowerHex(selected, 12) {
		return errors.New("incoming release coordinates are invalid")
	}
	if floor == nil {
		return nil
	}
	switch {
	case generation < floor.Generation:
		return errors.New("signed current generation is below the persisted floor")
	case generation == floor.Generation && digest != floor.PayloadSHA256:
		return errors.New("signed current generation has a different payload")
	case generation == floor.Generation && selected != floor.SelectedSnapshot:
		return errors.New("signed current generation selects a different snapshot")
	default:
		return nil
	}
}

func validateManifest(manifest *manifestWire, selected, nodeID string) (string, componentVersions, error) {
	var components componentVersions
	if manifest == nil || manifest.ID != selected {
		return "", components, errors.New("manifest id does not match signed current")
	}
	for _, decommissioned := range manifest.Decommissioned {
		if decommissioned == nodeID {
			return "", components, errors.New("signed manifest decommissions this device")
		}
	}
	seenOwners := map[string]bool{}
	wantedHash := ""
	for _, bundle := range manifest.Bundles {
		if seenOwners[bundle.Owner] {
			return "", components, errors.New("manifest contains a duplicate bundle owner")
		}
		seenOwners[bundle.Owner] = true
		if !validLowerHex(bundle.Hash, 64) {
			return "", components, errors.New("manifest contains an invalid bundle hash")
		}
		if bundle.Owner == nodeID {
			wantedHash = bundle.Hash
		}
	}
	if wantedHash == "" {
		return "", components, errors.New("manifest has no bundle for this device")
	}
	var err error
	components, err = componentVersionsForNode(manifest, nodeID)
	if err != nil {
		return "", componentVersions{}, err
	}
	return wantedHash, components, nil
}

func componentVersionsForNode(manifest *manifestWire, nodeID string) (componentVersions, error) {
	var result componentVersions
	found := false
	seen := map[string]bool{}
	for _, component := range manifest.Components {
		if component.Node == "" || len(component.Node) > 128 || seen[component.Node] {
			return componentVersions{}, errors.New("manifest contains an invalid or duplicate component node")
		}
		seen[component.Node] = true
		for _, version := range []string{component.SingBox, component.WireGuard, component.Tailscale, component.Agent} {
			if len(version) > 64 || strings.ContainsAny(version, "\x00\r\n") {
				return componentVersions{}, errors.New("manifest contains an invalid component version")
			}
		}
		if component.Node == nodeID {
			found = true
			result = componentVersions{
				SingBox: component.SingBox, WireGuard: component.WireGuard,
				Tailscale: component.Tailscale, Agent: component.Agent,
			}
		}
	}
	if len(manifest.Components) > 0 && !found {
		return componentVersions{}, errors.New("manifest has no component versions for this device")
	}
	return result, nil
}

func validateBundle(bundle bundleWire, nodeID string) error {
	if bundle.Owner != nodeID {
		return errors.New("bundle owner does not match this device")
	}
	if len(bundle.Files) == 0 || len(bundle.Files) > maxBundleFiles {
		return fmt.Errorf("bundle must contain between 1 and %d files", maxBundleFiles)
	}
	total := 0
	for name, content := range bundle.Files {
		if name == "" || strings.Contains(name, "\\") || strings.HasPrefix(name, "/") ||
			path.Clean(name) != name || name == "." || strings.HasPrefix(name, "../") {
			return errors.New("bundle contains an unsafe path")
		}
		total += len(name) + len(content)
		if total > maxBundleBytes {
			return errors.New("bundle file content exceeds size limit")
		}
	}
	return nil
}

func bundleHash(files map[string]string) string {
	names := make([]string, 0, len(files))
	for name := range files {
		names = append(names, name)
	}
	sort.Strings(names)
	hash := sha256.New()
	for _, name := range names {
		content := files[name]
		_, _ = fmt.Fprintf(hash, "%s\x00%d\x00%s\x00", name, len(content), content)
	}
	return hex.EncodeToString(hash.Sum(nil))
}

func marshalCanonical(value any) ([]byte, error) {
	body, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(body, '\n'), nil
}

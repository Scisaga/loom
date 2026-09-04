package clientupdate

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path"
	"sort"
	"strings"
	"sync"

	"loom/internal/publish"
	"loom/internal/releasefloor"
)

const (
	maxCurrentBody  = 1 << 20
	maxManifestBody = 4 << 20
	maxSignature    = 1 << 10
	maxBundleBody   = 16 << 20
	maxBundleFiles  = 64
)

// Updater is safe for concurrent callers in one client Service. The service is
// the only process permitted to mutate StateRoot; future UI calls must go
// through that same instance rather than opening a second writer.
type Updater struct {
	Client              *http.Client
	Config              Config
	PublicKey           ed25519.PublicKey
	StateRoot           string
	ExpectedCurrentPath string

	mu sync.Mutex
}

type Result struct {
	Snapshot   string
	Generation uint64
	BundleHash string
	Changed    bool
	Warnings   []string
}

type releaseDecision struct {
	current      *publish.DeploymentCurrent
	digest       string
	snapshot     string
	body         []byte
	contentBases []string
}

type verifiedPayload struct {
	currentBody  []byte
	manifestBody []byte
	signature    []byte
	bundleBody   []byte
	bundleHash   string
}

// manifestWire is the existing snapshot JSON contract without any renderer
// dependency. Keeping the complete field set makes unknown future schema fail
// closed while allowing the Windows client to stay independent of render and
// its control-plane dependency graph.
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

func (u *Updater) PullOnce(ctx context.Context) (Result, error) {
	u.mu.Lock()
	defer u.mu.Unlock()

	if u.Client == nil {
		return Result{}, errors.New("update HTTP client is nil")
	}
	if err := u.Config.Validate(); err != nil {
		return Result{}, fmt.Errorf("invalid update config: %w", err)
	}
	if len(u.PublicKey) != ed25519.PublicKeySize {
		return Result{}, errors.New("pinned platform public key has invalid length")
	}
	if err := requireAbsoluteClean(u.StateRoot); err != nil {
		return Result{}, fmt.Errorf("invalid update state root: %w", err)
	}
	if u.ExpectedCurrentPath != "" {
		if err := requireAbsoluteClean(u.ExpectedCurrentPath); err != nil {
			return Result{}, fmt.Errorf("invalid expected-current path: %w", err)
		}
	}

	floorPath := statePath(u.StateRoot, "release-floor.json")
	floor, err := releasefloor.Read(floorPath)
	if err != nil {
		return Result{}, err
	}
	expected, err := u.readExpectedCurrent(floor)
	if err != nil {
		return Result{}, err
	}
	decision, warnings, err := u.selectCurrent(ctx, floor, expected)
	if err != nil {
		return Result{}, err
	}

	// Latch the authenticated mutable decision before asking any mirror for
	// immutable payload. A mirror withholding payload cannot thereby reopen an
	// older, still-downloadable generation.
	if err := releasefloor.Advance(floorPath, releasefloor.Record{
		Schema: releasefloor.CurrentSchema, Generation: decision.current.Generation,
		PayloadSHA256: decision.digest, SelectedSnapshot: decision.snapshot,
	}); err != nil {
		return Result{}, fmt.Errorf("persist authenticated release floor: %w", err)
	}

	payload, err := u.fetchPayload(ctx, decision)
	if err != nil {
		return Result{}, err
	}
	changed, err := commitVerified(u.StateRoot, VerifiedVersion{
		Generation: decision.current.Generation, PayloadSHA256: decision.digest,
		Snapshot: decision.snapshot, BundleSHA256: payload.bundleHash,
	}, payload)
	if err != nil {
		return Result{}, fmt.Errorf("commit verified client bundle: %w", err)
	}
	return Result{
		Snapshot: decision.snapshot, Generation: decision.current.Generation,
		BundleHash: payload.bundleHash, Changed: changed, Warnings: warnings,
	}, nil
}

func (u *Updater) readExpectedCurrent(floor *releasefloor.Record) ([]byte, error) {
	if floor != nil || u.ExpectedCurrentPath == "" {
		return nil, nil
	}
	body, err := readLimitedFile(u.ExpectedCurrentPath, maxCurrentBody)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read expected-current trust anchor: %w", err)
	}
	current, err := publish.DecodeDeploymentCurrent(body)
	if err != nil {
		return nil, fmt.Errorf("expected-current is not a strict signed envelope: %w", err)
	}
	if err := current.Verify(u.PublicKey); err != nil {
		return nil, fmt.Errorf("verify expected-current trust anchor: %w", err)
	}
	if _, err := current.Select(u.Config.NodeID); err != nil {
		return nil, fmt.Errorf("expected-current does not bind this device: %w", err)
	}
	return body, nil
}

type mirrorCurrent struct {
	base     string
	body     []byte
	current  *publish.DeploymentCurrent
	digest   string
	snapshot string
	err      error
}

func (u *Updater) selectCurrent(ctx context.Context, floor *releasefloor.Record, expected []byte) (*releaseDecision, []string, error) {
	bases := u.Config.Mirrors()
	results := make([]mirrorCurrent, len(bases))
	var group sync.WaitGroup
	for index, base := range bases {
		group.Add(1)
		go func(index int, base string) {
			defer group.Done()
			result := mirrorCurrent{base: base}
			body, err := getBytes(ctx, u.Client, base+"/current.json", maxCurrentBody)
			if err != nil {
				result.err = err
				results[index] = result
				return
			}
			current, err := publish.DecodeDeploymentCurrent(body)
			if err == nil {
				err = current.Verify(u.PublicKey)
			}
			var selected, digest string
			if err == nil {
				selected, err = current.Select(u.Config.NodeID)
			}
			if err == nil {
				digest, err = current.PayloadSHA256()
			}
			if err == nil {
				err = checkFloor(floor, current.Generation, digest, selected)
			}
			result.body, result.current, result.digest, result.snapshot, result.err = body, current, digest, selected, err
			results[index] = result
		}(index, base)
	}
	group.Wait()

	var valid []mirrorCurrent
	var warnings []string
	for _, result := range results {
		if result.err != nil {
			warnings = append(warnings, fmt.Sprintf("%s/current.json: %v", result.base, result.err))
			continue
		}
		valid = append(valid, result)
	}
	if len(valid) == 0 {
		return nil, warnings, fmt.Errorf("all %d distribution mirrors rejected current.json", len(results))
	}

	winner := valid[0]
	for _, candidate := range valid[1:] {
		if candidate.current.Generation > winner.current.Generation {
			winner = candidate
		}
	}
	for _, candidate := range valid {
		if candidate.current.Generation == winner.current.Generation &&
			(candidate.digest != winner.digest || candidate.snapshot != winner.snapshot) {
			return nil, warnings, fmt.Errorf("signed mirror fork at generation %d between %s and %s",
				winner.current.Generation, winner.base, candidate.base)
		}
	}
	if len(expected) > 0 && !bytes.Equal(winner.body, expected) {
		return nil, warnings, errors.New("highest valid current.json differs from expected-current trust anchor")
	}
	if floor == nil && len(expected) == 0 && winner.current.Generation != 1 {
		return nil, warnings, fmt.Errorf("no release floor: first observed signed generation is %d, expected-current is required", winner.current.Generation)
	}

	decision := &releaseDecision{
		current: winner.current, digest: winner.digest, snapshot: winner.snapshot, body: winner.body,
	}
	seen := map[string]bool{}
	for _, result := range results {
		if result.err == nil && result.current.Generation == winner.current.Generation &&
			result.digest == winner.digest && result.snapshot == winner.snapshot {
			decision.contentBases = append(decision.contentBases, result.base)
			seen[result.base] = true
		}
	}
	for _, base := range bases {
		if !seen[base] {
			decision.contentBases = append(decision.contentBases, base)
		}
	}
	return decision, warnings, nil
}

func checkFloor(floor *releasefloor.Record, generation uint64, digest, selected string) error {
	if err := floor.Check(generation, digest); err != nil {
		return err
	}
	if floor != nil && generation == floor.Generation && selected != floor.SelectedSnapshot {
		return fmt.Errorf("generation %d already selects snapshot %s, not %s", generation, floor.SelectedSnapshot, selected)
	}
	return nil
}

func (u *Updater) fetchPayload(ctx context.Context, decision *releaseDecision) (verifiedPayload, error) {
	var failures []string
	for _, base := range decision.contentBases {
		root := base + "/" + decision.snapshot
		manifestBody, err := getBytes(ctx, u.Client, root+"/snapshot.json", maxManifestBody)
		if err != nil {
			failures = append(failures, fmt.Sprintf("%s manifest: %v", base, err))
			continue
		}
		signature, err := getBytes(ctx, u.Client, root+"/snapshot.sig", maxSignature)
		if err != nil {
			failures = append(failures, fmt.Sprintf("%s signature: %v", base, err))
			continue
		}
		if len(signature) != ed25519.SignatureSize || !ed25519.Verify(u.PublicKey, manifestBody, signature) {
			failures = append(failures, fmt.Sprintf("%s manifest signature is missing, malformed, or invalid", base))
			continue
		}
		var manifest manifestWire
		if err := decodeStrict(manifestBody, maxManifestBody, &manifest); err != nil {
			failures = append(failures, fmt.Sprintf("%s manifest JSON: %v", base, err))
			continue
		}
		want, err := validateManifest(&manifest, decision.snapshot, u.Config.NodeID)
		if err != nil {
			failures = append(failures, fmt.Sprintf("%s manifest binding: %v", base, err))
			continue
		}
		bundleBody, err := getBytes(ctx, u.Client, root+"/nodes/"+u.Config.NodeID+".json", maxBundleBody)
		if err != nil {
			failures = append(failures, fmt.Sprintf("%s bundle: %v", base, err))
			continue
		}
		var bundle bundleWire
		if err := decodeStrict(bundleBody, maxBundleBody, &bundle); err != nil {
			failures = append(failures, fmt.Sprintf("%s bundle JSON: %v", base, err))
			continue
		}
		if err := validateBundle(bundle, u.Config.NodeID); err != nil {
			failures = append(failures, fmt.Sprintf("%s bundle binding: %v", base, err))
			continue
		}
		hash := bundleHash(bundle.Files)
		if hash != want {
			failures = append(failures, fmt.Sprintf("%s bundle hash %s does not match manifest %s", base, short(hash), short(want)))
			continue
		}
		canonicalBundle, err := json.MarshalIndent(&bundle, "", "  ")
		if err != nil {
			return verifiedPayload{}, err
		}
		return verifiedPayload{
			currentBody: decision.body, manifestBody: manifestBody, signature: signature,
			bundleBody: append(canonicalBundle, '\n'), bundleHash: hash,
		}, nil
	}
	return verifiedPayload{}, fmt.Errorf("all mirrors rejected snapshot payload: %s", strings.Join(failures, "; "))
}

func validateManifest(manifest *manifestWire, selected, node string) (string, error) {
	if manifest == nil || manifest.ID != selected {
		return "", fmt.Errorf("manifest id is %q, want %q", manifest.ID, selected)
	}
	for _, id := range manifest.Decommissioned {
		if id == node {
			return "", errors.New("signed manifest decommissions this device")
		}
	}
	seen := map[string]bool{}
	want := ""
	for _, ref := range manifest.Bundles {
		if seen[ref.Owner] {
			return "", fmt.Errorf("duplicate bundle owner %q", ref.Owner)
		}
		seen[ref.Owner] = true
		if !validLowerHex(ref.Hash, 64) {
			return "", fmt.Errorf("bundle %q has invalid hash", ref.Owner)
		}
		if ref.Owner == node {
			want = ref.Hash
		}
	}
	if want == "" {
		return "", fmt.Errorf("manifest has no bundle for node %q", node)
	}
	if _, err := componentVersionsForNode(manifest, node); err != nil {
		return "", err
	}
	return want, nil
}

func componentVersionsForNode(manifest *manifestWire, node string) (ComponentVersions, error) {
	var result ComponentVersions
	found := false
	seen := make(map[string]bool, len(manifest.Components))
	for _, component := range manifest.Components {
		if component.Node == "" || len(component.Node) > 128 {
			return ComponentVersions{}, errors.New("manifest contains a component entry with an invalid node")
		}
		if seen[component.Node] {
			return ComponentVersions{}, fmt.Errorf("duplicate component node %q", component.Node)
		}
		seen[component.Node] = true
		for name, version := range map[string]string{
			"sing-box": component.SingBox, "WireGuard": component.WireGuard,
			"Tailscale": component.Tailscale, "Agent": component.Agent,
		} {
			if len(version) > 64 || strings.ContainsAny(version, "\x00\r\n") {
				return ComponentVersions{}, fmt.Errorf("component %s version for %q is invalid", name, component.Node)
			}
		}
		if component.Node == node {
			found = true
			result = ComponentVersions{SingBox: component.SingBox, WireGuard: component.WireGuard,
				Tailscale: component.Tailscale, Agent: component.Agent}
		}
	}
	if len(manifest.Components) > 0 && !found {
		return ComponentVersions{}, fmt.Errorf("manifest has no component versions for node %q", node)
	}
	return result, nil
}

func validateBundle(bundle bundleWire, node string) error {
	if bundle.Owner != node {
		return fmt.Errorf("bundle owner is %q, want %q", bundle.Owner, node)
	}
	if len(bundle.Files) == 0 || len(bundle.Files) > maxBundleFiles {
		return fmt.Errorf("bundle must contain between 1 and %d files", maxBundleFiles)
	}
	total := 0
	for name, content := range bundle.Files {
		if name == "" || strings.Contains(name, "\\") || strings.HasPrefix(name, "/") ||
			path.Clean(name) != name || name == "." || strings.HasPrefix(name, "../") {
			return fmt.Errorf("unsafe bundle path %q", name)
		}
		total += len(name) + len(content)
		if total > maxBundleBody {
			return errors.New("bundle file content exceeds size limit")
		}
	}
	return nil
}

func bundleHash(files map[string]string) string {
	paths := make([]string, 0, len(files))
	for name := range files {
		paths = append(paths, name)
	}
	sort.Strings(paths)
	hash := sha256.New()
	for _, name := range paths {
		content := files[name]
		fmt.Fprintf(hash, "%s\x00%d\x00%s\x00", name, len(content), content)
	}
	return fmt.Sprintf("%x", hash.Sum(nil))
}

func getBytes(ctx context.Context, client *http.Client, rawURL string, maximum int64) ([]byte, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}
	request.Header.Set("Accept", "application/json, application/octet-stream")
	response, err := client.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", response.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, maximum+1))
	if err != nil {
		return nil, err
	}
	if int64(len(body)) > maximum {
		return nil, fmt.Errorf("response exceeds %d bytes", maximum)
	}
	return body, nil
}

func validLowerHex(value string, length int) bool {
	if len(value) != length {
		return false
	}
	for _, character := range []byte(value) {
		if (character < '0' || character > '9') && (character < 'a' || character > 'f') {
			return false
		}
	}
	return true
}

func short(value string) string {
	if len(value) <= 12 {
		return value
	}
	return value[:12]
}

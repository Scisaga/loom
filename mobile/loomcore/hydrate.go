package loomcore

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"unicode"
)

const maxSecretPlaintext = 1 << 20

// HydrateSingBoxConfig extracts the Android sing-box config from an already
// verified canonical bundle and substitutes the union of secret references in
// the permitted Android files. Stage-2 bundles may contain only sing-box;
// stage-3 additionally carries agent/config.json as a data-only mobile routing
// plan. Any other file remains a hard failure.
func HydrateSingBoxConfig(verifiedBundleJSON, secretsEnv []byte) ([]byte, error) {
	files, _, err := hydrateAndroidFiles(verifiedBundleJSON, secretsEnv)
	if err != nil {
		return nil, err
	}
	return files["sing-box/config.json"], nil
}

type preparedAndroidRuntime struct {
	Schema        int    `json:"schema"`
	SingBoxConfig string `json:"sing_box_config"`
	RoutePlan     string `json:"route_plan,omitempty"`
}

// PrepareAndroidRuntime hydrates both permitted Android runtime files and
// verifies that the data-only route plan exactly describes the selectors and
// probe paths in sing-box. The returned JSON is an in-memory handoff; callers
// must never persist or display route_plan because it contains loopback API
// credentials already protected by the enrollment vault.
func PrepareAndroidRuntime(verifiedBundleJSON, secretsEnv []byte) ([]byte, error) {
	files, owner, err := hydrateAndroidFiles(verifiedBundleJSON, secretsEnv)
	if err != nil {
		return nil, err
	}
	plan := files["agent/config.json"]
	if len(plan) > 0 {
		if err := validateAndroidRoutePlan(files["sing-box/config.json"], plan, owner); err != nil {
			return nil, fmt.Errorf("Android route plan: %w", err)
		}
	}
	return marshalCanonical(&preparedAndroidRuntime{
		Schema: 1, SingBoxConfig: string(files["sing-box/config.json"]), RoutePlan: string(plan),
	})
}

func hydrateAndroidFiles(verifiedBundleJSON, secretsEnv []byte) (map[string][]byte, string, error) {
	var bundle bundleWire
	if err := decodeStrictJSON(verifiedBundleJSON, maxBundleBytes, &bundle); err != nil {
		return nil, "", fmt.Errorf("verified bundle JSON: %w", err)
	}
	if !validNodeID(bundle.Owner) {
		return nil, "", errors.New("verified bundle owner is invalid")
	}
	if err := validateBundle(bundle, bundle.Owner); err != nil {
		return nil, "", err
	}
	if len(bundle.Files) < 1 || len(bundle.Files) > 2 {
		return nil, "", errors.New("Android bundle must contain sing-box/config.json and optional agent/config.json")
	}
	_, ok := bundle.Files["sing-box/config.json"]
	if !ok {
		return nil, "", errors.New("Android bundle does not contain sing-box/config.json")
	}
	for path := range bundle.Files {
		if path != "sing-box/config.json" && path != "agent/config.json" {
			return nil, "", fmt.Errorf("Android bundle contains unsupported file %s", path)
		}
	}
	secrets, err := parseSecretsEnv(string(secretsEnv))
	if err != nil {
		return nil, "", fmt.Errorf("secret bootstrap: %w", err)
	}
	used := map[string]bool{}
	missingSet := map[string]bool{}
	hydratedFiles := make(map[string][]byte, len(bundle.Files))
	paths := make([]string, 0, len(bundle.Files))
	for path := range bundle.Files {
		paths = append(paths, path)
	}
	sort.Strings(paths)
	for _, path := range paths {
		hydrated, fileUsed, missing, err := hydrateStrict(bundle.Files[path], secrets)
		if err != nil {
			return nil, "", fmt.Errorf("hydrate %s: %w", path, err)
		}
		for ref := range fileUsed {
			used[ref] = true
		}
		for _, ref := range missing {
			missingSet[ref] = true
		}
		if strings.Contains(hydrated, "${secret:") {
			continue
		}
		var document map[string]json.RawMessage
		if err := decodeStrictJSON([]byte(hydrated), maxBundleBytes, &document); err != nil {
			return nil, "", fmt.Errorf("hydrated %s is invalid JSON: %w", path, err)
		}
		if document == nil {
			return nil, "", fmt.Errorf("hydrated %s must be a JSON object", path)
		}
		hydratedFiles[path] = []byte(hydrated)
	}
	if len(missingSet) > 0 {
		missing := make([]string, 0, len(missingSet))
		for ref := range missingSet {
			missing = append(missing, ref)
		}
		sort.Strings(missing)
		return nil, "", fmt.Errorf("protected secret vault is missing refs: %s", strings.Join(missing, ", "))
	}
	unused := make([]string, 0)
	for ref := range secrets {
		if !used[ref] {
			unused = append(unused, ref)
		}
	}
	sort.Strings(unused)
	if len(unused) > 0 {
		return nil, "", fmt.Errorf("protected secret vault contains unused refs: %s", strings.Join(unused, ", "))
	}
	return hydratedFiles, bundle.Owner, nil
}

func parseSecretsEnv(body string) (map[string]string, error) {
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
		if !ok || !validSecretRef(ref) || value == "" || len(value) > 64<<10 || strings.ContainsAny(value, "\r\n") {
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
	if len(out) == 0 || len(out) > 4096 {
		return nil, errors.New("secret bootstrap contains an invalid number of entries")
	}
	return out, nil
}

func validSecretRef(ref string) bool {
	if ref == "" || len(ref) > 256 || strings.ContainsAny(ref, "{}=$") ||
		strings.IndexFunc(ref, unicode.IsSpace) >= 0 || strings.IndexFunc(ref, unicode.IsControl) >= 0 {
		return false
	}
	for i := 0; i < len(ref); i++ {
		character := ref[i]
		if (character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') ||
			(character >= '0' && character <= '9') || strings.ContainsRune("._:/@+-", rune(character)) {
			continue
		}
		return false
	}
	return true
}

func hydrateStrict(content string, secrets map[string]string) (string, map[string]bool, []string, error) {
	const prefix = "${secret:"
	used := map[string]bool{}
	missingSet := map[string]bool{}
	var output strings.Builder
	remaining := content
	for {
		start := strings.Index(remaining, prefix)
		if start < 0 {
			output.WriteString(remaining)
			break
		}
		output.WriteString(remaining[:start])
		referenceStart := start + len(prefix)
		endOffset := strings.IndexByte(remaining[referenceStart:], '}')
		if endOffset < 0 {
			return "", nil, nil, errors.New("sing-box config contains an unterminated secret reference")
		}
		end := referenceStart + endOffset
		ref := remaining[referenceStart:end]
		if !validSecretRef(ref) {
			return "", nil, nil, errors.New("sing-box config contains a dangerous secret reference")
		}
		value, ok := secrets[ref]
		if !ok {
			missingSet[ref] = true
			output.WriteString(remaining[start : end+1])
		} else {
			used[ref] = true
			output.WriteString(value)
		}
		remaining = remaining[end+1:]
	}
	missing := make([]string, 0, len(missingSet))
	for ref := range missingSet {
		missing = append(missing, ref)
	}
	sort.Strings(missing)
	return output.String(), used, missing, nil
}

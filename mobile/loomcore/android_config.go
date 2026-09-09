package loomcore

import (
	"encoding/json"
	"errors"
	"fmt"
	"path"
	"strings"
)

const (
	androidDefaultCAPath = "tls/ca.crt"
	androidCAPathPrefix  = "tls/ca-"
	androidCAPathSuffix  = ".crt"
)

// RelocateAndroidCA gives one hydrated candidate an immutable,
// content-addressed CA slot before libbox preflight. candidatePath must be
// exactly tls/ca-<64 lowercase hex>.crt or an absolute clean path ending in
// libbox/tls/ca-<64 lowercase hex>.crt. libbox checks certificate files against
// the process filesystem rather than SetupOptions.WorkingPath, so Android uses
// the latter form in production. Every certificate_path anywhere in the JSON
// must exist as a string and still equal the renderer-owned tls/ca.crt default;
// all are replaced in one pure transformation. Any other path, duplicate JSON
// key, missing certificate_path, or non-object root fails.
func RelocateAndroidCA(config []byte, candidatePath string) ([]byte, error) {
	if !validAndroidCAPath(candidatePath) {
		return nil, errors.New("Android CA candidate path must be a content-addressed libbox/tls slot")
	}
	var document map[string]json.RawMessage
	if err := decodeStrictJSON(config, maxBundleBytes, &document); err != nil || document == nil {
		return nil, errors.New("Android config must be one strict JSON object")
	}
	relocated, replaced, err := relocateCertificatePaths(document, candidatePath)
	if err != nil {
		return nil, err
	}
	if replaced == 0 {
		return nil, errors.New("Android config contains no certificate_path")
	}
	body, err := json.Marshal(relocated)
	if err != nil {
		return nil, fmt.Errorf("encode relocated Android config: %w", err)
	}
	return body, nil
}

func validAndroidCAPath(value string) bool {
	name := value
	if strings.HasPrefix(value, "/") {
		if path.Clean(value) != value {
			return false
		}
		directory := path.Dir(value)
		if path.Base(directory) != "tls" || path.Base(path.Dir(directory)) != "libbox" {
			return false
		}
		name = "tls/" + path.Base(value)
	}
	if !strings.HasPrefix(name, androidCAPathPrefix) || !strings.HasSuffix(name, androidCAPathSuffix) {
		return false
	}
	digest := strings.TrimSuffix(strings.TrimPrefix(name, androidCAPathPrefix), androidCAPathSuffix)
	return validLowerHex(digest, 64)
}

func relocateCertificatePaths(value map[string]json.RawMessage, relativePath string) (map[string]json.RawMessage, int, error) {
	out := make(map[string]json.RawMessage, len(value))
	total := 0
	for key, child := range value {
		if key == "certificate_path" {
			var pathValue string
			if err := json.Unmarshal(child, &pathValue); err != nil || pathValue != androidDefaultCAPath {
				return nil, 0, errors.New("Android certificate_path is not the renderer-owned tls/ca.crt default")
			}
			encoded, _ := json.Marshal(relativePath)
			out[key] = encoded
			total++
			continue
		}
		relocated, count, err := relocateJSONValue(child, relativePath)
		if err != nil {
			return nil, 0, err
		}
		out[key] = relocated
		total += count
	}
	return out, total, nil
}

func relocateJSONValue(value json.RawMessage, relativePath string) (json.RawMessage, int, error) {
	trimmed := strings.TrimSpace(string(value))
	if trimmed == "" {
		return nil, 0, errors.New("Android config contains an empty JSON value")
	}
	switch trimmed[0] {
	case '{':
		var object map[string]json.RawMessage
		if err := json.Unmarshal(value, &object); err != nil {
			return nil, 0, err
		}
		relocated, count, err := relocateCertificatePaths(object, relativePath)
		if err != nil {
			return nil, 0, err
		}
		body, err := json.Marshal(relocated)
		return body, count, err
	case '[':
		var array []json.RawMessage
		if err := json.Unmarshal(value, &array); err != nil {
			return nil, 0, err
		}
		total := 0
		for index := range array {
			relocated, count, err := relocateJSONValue(array[index], relativePath)
			if err != nil {
				return nil, 0, err
			}
			array[index] = relocated
			total += count
		}
		body, err := json.Marshal(array)
		return body, total, err
	default:
		return append(json.RawMessage(nil), value...), 0, nil
	}
}

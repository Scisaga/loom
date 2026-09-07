package loomcore

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

const (
	androidDefaultCAPath = "tls/ca.crt"
	androidCAPathPrefix  = "tls/ca-"
	androidCAPathSuffix  = ".crt"
)

// RelocateAndroidCA gives one hydrated candidate an immutable,
// content-addressed CA slot before libbox preflight. relativePath must be
// exactly tls/ca-<64 lowercase hex>.crt. Every certificate_path anywhere in
// the JSON must exist as a string and still equal the renderer-owned
// tls/ca.crt default; all are replaced in one pure transformation. Any other
// path, duplicate JSON key, missing certificate_path, or non-object root fails.
func RelocateAndroidCA(config []byte, relativePath string) ([]byte, error) {
	if !validAndroidCAPath(relativePath) {
		return nil, errors.New("Android CA candidate path must be tls/ca-<64 lowercase hex>.crt")
	}
	var document map[string]json.RawMessage
	if err := decodeStrictJSON(config, maxBundleBytes, &document); err != nil || document == nil {
		return nil, errors.New("Android config must be one strict JSON object")
	}
	relocated, replaced, err := relocateCertificatePaths(document, relativePath)
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
	if !strings.HasPrefix(value, androidCAPathPrefix) || !strings.HasSuffix(value, androidCAPathSuffix) {
		return false
	}
	digest := strings.TrimSuffix(strings.TrimPrefix(value, androidCAPathPrefix), androidCAPathSuffix)
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

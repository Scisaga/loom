// Package clientupdate implements the platform-neutral, read-only half of a
// managed client's configuration update transaction. It authenticates release
// coordinates and immutable bundles; platform hosts remain responsible for
// secret hydration, preflight, activation, and rollback.
package clientupdate

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"net/url"
	"path/filepath"
	"strings"
	"time"

	"loom/internal/model"
)

const (
	ConfigSchema        = 1
	defaultPullInterval = 45 * time.Second
	maxControlFile      = 64 << 10
)

// Config contains only non-secret pull coordinates installed by enrollment.
// The pinned platform key remains a separate trust-root file.
type Config struct {
	Schema              int      `json:"schema"`
	NodeID              string   `json:"node_id"`
	DistributionURLs    []string `json:"distribution_urls"`
	DNS                 []string `json:"dns,omitempty"`
	PullIntervalSeconds int      `json:"pull_interval_seconds,omitempty"`
}

func ReadConfig(path string) (Config, error) {
	body, err := readLimitedFile(path, maxControlFile)
	if err != nil {
		return Config{}, err
	}
	var config Config
	if err := decodeStrict(body, maxControlFile, &config); err != nil {
		return Config{}, fmt.Errorf("decode client update config %s: %w", path, err)
	}
	if err := config.Validate(); err != nil {
		return Config{}, fmt.Errorf("validate client update config %s: %w", path, err)
	}
	return config, nil
}

func (c Config) Validate() error {
	if c.Schema != ConfigSchema {
		return fmt.Errorf("schema must be %d, got %d", ConfigSchema, c.Schema)
	}
	if !model.ValidNodeID(c.NodeID) {
		return fmt.Errorf("invalid node_id %q", c.NodeID)
	}
	if len(c.DistributionURLs) == 0 || len(c.DistributionURLs) > 8 {
		return errors.New("distribution_urls must contain between 1 and 8 mirrors")
	}
	seen := map[string]bool{}
	for _, raw := range c.DistributionURLs {
		normalized, err := normalizeMirror(raw)
		if err != nil {
			return err
		}
		if seen[normalized] {
			return fmt.Errorf("duplicate distribution mirror %q", raw)
		}
		seen[normalized] = true
	}
	if len(c.DNS) > 4 {
		return errors.New("dns must contain at most 4 literal addresses")
	}
	for _, raw := range c.DNS {
		if address, err := netip.ParseAddr(raw); err != nil || !address.IsValid() || address.IsUnspecified() {
			return fmt.Errorf("dns entry must be a non-unspecified literal IP address, got %q", raw)
		}
	}
	if c.PullIntervalSeconds != 0 && (c.PullIntervalSeconds < 15 || c.PullIntervalSeconds > 86400) {
		return errors.New("pull_interval_seconds must be 15-86400 when set")
	}
	return nil
}

func (c Config) Mirrors() []string {
	out := make([]string, 0, len(c.DistributionURLs))
	for _, raw := range c.DistributionURLs {
		normalized, _ := normalizeMirror(raw)
		out = append(out, normalized)
	}
	return out
}

func (c Config) PullInterval() time.Duration {
	if c.PullIntervalSeconds == 0 {
		return defaultPullInterval
	}
	return time.Duration(c.PullIntervalSeconds) * time.Second
}

func ReadPublicKey(path string) (ed25519.PublicKey, error) {
	body, err := readLimitedFile(path, maxControlFile)
	if err != nil {
		return nil, err
	}
	if len(body) == 0 || len(body) > maxControlFile {
		return nil, errors.New("platform public key file has invalid size")
	}
	encoded := strings.TrimSpace(string(body))
	key, err := base64.StdEncoding.Strict().DecodeString(encoded)
	if err != nil || len(key) != ed25519.PublicKeySize || base64.StdEncoding.EncodeToString(key) != encoded {
		return nil, errors.New("platform public key must be one canonical base64 Ed25519 key")
	}
	return ed25519.PublicKey(key), nil
}

func normalizeMirror(raw string) (string, error) {
	parsed, err := url.ParseRequestURI(raw)
	if err != nil || parsed.Host == "" || (parsed.Scheme != "http" && parsed.Scheme != "https") ||
		parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return "", fmt.Errorf("distribution mirror must be a complete credential-free http(s) URL without query or fragment: %q", raw)
	}
	return strings.TrimRight(raw, "/"), nil
}

func requireAbsoluteClean(path string) error {
	if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return fmt.Errorf("path must be absolute and clean: %q", path)
	}
	return nil
}

func decodeStrict(body []byte, maximum int64, target any) error {
	if len(body) == 0 || int64(len(body)) > maximum {
		return fmt.Errorf("JSON size must be between 1 and %d bytes", maximum)
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
		if err == nil {
			err = errors.New("additional JSON value")
		}
		return fmt.Errorf("trailing content: %w", err)
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
		if err == nil {
			err = errors.New("additional JSON value")
		}
		return err
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
		end, err := decoder.Token()
		if err != nil || end != json.Delim('}') {
			return errors.New("JSON object did not terminate")
		}
	case '[':
		for decoder.More() {
			if err := walkJSONValue(decoder); err != nil {
				return err
			}
		}
		end, err := decoder.Token()
		if err != nil || end != json.Delim(']') {
			return errors.New("JSON array did not terminate")
		}
	default:
		return fmt.Errorf("unexpected JSON delimiter %q", delimiter)
	}
	return nil
}

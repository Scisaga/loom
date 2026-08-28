// Package enrollssh is the narrow SSH trust boundary used while enrolling a
// node. It deliberately does not decide node identity, topology, egress, or
// reachability. Its job ends after authenticating one SSH host, observing a
// small fixed set of facts, and preparing a node-local WireGuard identity.
package enrollssh

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const (
	defaultScanTimeout    = 10 * time.Second
	defaultSSHTimeout     = 30 * time.Second
	defaultConnectTimeout = 10 * time.Second
	defaultOutputLimit    = 64 << 10
	maxConfiguredOutput   = 1 << 20
)

var userPattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_.-]{0,63}$`)

// Connection contains the only operator-provided SSH connection fields. Host
// is a bare IP address or DNS name: bracketed IPv6 literals and URLs are not
// accepted. Values are passed as distinct argv entries and are never copied
// into a local or remote shell program.
type Connection struct {
	Host string
	User string
	Port int
}

// Validate applies a deliberately small grammar so a connection value can
// never be interpreted as an ssh option, config fragment, or shell text.
func (c Connection) Validate() error {
	if err := validateHost(c.Host); err != nil {
		return fmt.Errorf("invalid SSH host: %w", err)
	}
	if !userPattern.MatchString(c.User) {
		return errors.New("invalid SSH user: use 1-64 ASCII letters, digits, '_', '.', or '-' and do not start with '-' or a digit")
	}
	if c.Port < 1 || c.Port > 65535 {
		return fmt.Errorf("invalid SSH port %d: expected 1-65535", c.Port)
	}
	return nil
}

func validateHost(host string) error {
	if host == "" {
		return errors.New("host is empty")
	}
	if strings.TrimSpace(host) != host || len(host) > 253 {
		return errors.New("host has surrounding whitespace or exceeds 253 bytes")
	}
	if strings.ContainsAny(host, "\x00\r\n\t /\\@[]%") {
		return errors.New("host must be a bare IP address or DNS name")
	}
	if net.ParseIP(host) != nil {
		return nil
	}
	if strings.HasSuffix(host, ".") {
		return errors.New("a trailing DNS root dot is not accepted")
	}
	labels := strings.Split(host, ".")
	allNumeric := len(labels) == 4
	for _, label := range labels {
		if len(label) == 0 || len(label) > 63 {
			return errors.New("DNS labels must contain 1-63 bytes")
		}
		if label[0] == '-' || label[len(label)-1] == '-' {
			return errors.New("DNS labels cannot start or end with '-'")
		}
		for _, r := range label {
			if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-') {
				return errors.New("DNS names may contain only ASCII letters, digits, '.', and '-'")
			}
			if r < '0' || r > '9' {
				allNumeric = false
			}
		}
	}
	if allNumeric {
		return errors.New("malformed dotted IPv4 address")
	}
	return nil
}

func (c Connection) destination() string { return c.User + "@" + c.Host }

func (c Connection) knownHostPattern() string {
	if c.Port == 22 {
		return c.Host
	}
	return "[" + c.Host + "]:" + strconv.Itoa(c.Port)
}

func outputLimit(configured int) (int, error) {
	if configured == 0 {
		return defaultOutputLimit, nil
	}
	if configured < 1024 || configured > maxConfiguredOutput {
		return 0, fmt.Errorf("output limit must be between 1024 and %d bytes", maxConfiguredOutput)
	}
	return configured, nil
}

func timeout(configured, fallback time.Duration) (time.Duration, error) {
	if configured == 0 {
		return fallback, nil
	}
	if configured < 0 {
		return 0, errors.New("timeout cannot be negative")
	}
	return configured, nil
}

func connectTimeoutSeconds(configured time.Duration) (int, error) {
	d, err := timeout(configured, defaultConnectTimeout)
	if err != nil {
		return 0, err
	}
	seconds := int((d + time.Second - 1) / time.Second)
	if seconds < 1 || seconds > 60 {
		return 0, errors.New("SSH connect timeout must be between 1 second and 60 seconds")
	}
	return seconds, nil
}

func validateLocalPath(path, label string) error {
	if path == "" {
		return fmt.Errorf("%s path is empty", label)
	}
	if strings.TrimSpace(path) != path || strings.ContainsAny(path, "\x00\r\n") {
		return fmt.Errorf("%s path contains whitespace or control bytes", label)
	}
	if !filepath.IsAbs(path) {
		return fmt.Errorf("%s path must be absolute", label)
	}
	return nil
}

func validateWGPublicKey(s string) error {
	if len(s) != 44 || strings.ContainsAny(s, " \t\r\n") {
		return errors.New("WireGuard public key must be one base64 line")
	}
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil || len(b) != 32 {
		return errors.New("WireGuard public key is not a 32-byte base64 key")
	}
	return nil
}

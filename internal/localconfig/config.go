// Package localconfig loads the management workstation's single deployment
// configuration. The file is data, never a shell program.
package localconfig

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

const DefaultSSHConfig = ".ssh_config"

var (
	aliasPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)
	tokenPattern = regexp.MustCompile(`^[A-Za-z0-9._~+/=-]+$`)
)

type Config struct {
	GandiPATToken  string
	DeployHosts    []string
	LocalNode      string
	SSHConfig      string
	SigningKey     string
	PublishOutputs []string
}

var orderedKeys = []string{
	"GANDI_PAT_TOKEN",
	"LOOM_DEPLOY_HOSTS",
	"LOOM_LOCAL_NODE",
	"LOOM_SSH_CONFIG",
	"LOOM_SIGNING_KEY",
	"LOOM_PUBLISH_OUTPUTS",
}

func Load(path string) (Config, error) {
	var zero Config
	info, err := os.Lstat(path)
	if err != nil {
		return zero, fmt.Errorf("load deployment config: %w", err)
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
		return zero, errors.New("deployment config must be a regular file with permissions no wider than 0600")
	}
	body, err := os.ReadFile(path)
	if err != nil {
		return zero, fmt.Errorf("load deployment config: %w", err)
	}
	return Decode(body, filepath.Dir(path))
}

// Migrate rewrites the one historical six-key representation still present on
// the management workstation. It is an explicit, one-time conversion; Load
// never accepts the historical JSON list as a compatibility format.
func Migrate(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
		return errors.New("deployment config must be a regular file with permissions no wider than 0600")
	}
	body, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	lines := strings.Split(string(body), "\n")
	converted := false
	for index, line := range lines {
		const prefix = "LOOM_PUBLISH_OUTPUTS='"
		if !strings.HasPrefix(line, prefix) || !strings.HasSuffix(line, "'") {
			continue
		}
		value := strings.TrimSuffix(strings.TrimPrefix(line, prefix), "'")
		if !strings.HasPrefix(value, "[") {
			continue
		}
		var targets []string
		if err := json.Unmarshal([]byte(value), &targets); err != nil || len(targets) == 0 {
			return errors.New("legacy LOOM_PUBLISH_OUTPUTS is invalid")
		}
		lines[index] = prefix + strings.Join(targets, ",") + "'"
		converted = true
	}
	if !converted {
		if _, err := Decode(body, filepath.Dir(path)); err != nil {
			return err
		}
	}
	config, err := Decode([]byte(strings.Join(lines, "\n")), filepath.Dir(path))
	if err != nil {
		return err
	}
	canonical, err := Encode(config, filepath.Dir(path))
	if err != nil {
		return err
	}
	temporary, err := os.CreateTemp(filepath.Dir(path), ".env-migrate-*")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err = temporary.Chmod(0o600); err == nil {
		_, err = temporary.Write(canonical)
	}
	if err == nil {
		err = temporary.Sync()
	}
	closeErr := temporary.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		return err
	}
	directory, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}

func Decode(body []byte, anchor string) (Config, error) {
	var zero Config
	if len(body) == 0 || strings.ContainsRune(string(body), '\x00') {
		return zero, errors.New("deployment config is empty or contains NUL")
	}
	allowed := make(map[string]bool, len(orderedKeys))
	for _, key := range orderedKeys {
		allowed[key] = true
	}
	values := map[string]string{}
	scanner := bufio.NewScanner(strings.NewReader(string(body)))
	for line := 1; scanner.Scan(); line++ {
		raw := scanner.Text()
		if strings.TrimSpace(raw) == "" || strings.HasPrefix(strings.TrimSpace(raw), "#") {
			continue
		}
		key, value, ok := strings.Cut(raw, "=")
		if !ok || strings.TrimSpace(key) != key || !allowed[key] {
			return zero, fmt.Errorf("deployment config line %d has an unknown or malformed key", line)
		}
		if _, duplicate := values[key]; duplicate {
			return zero, fmt.Errorf("deployment config key %s is duplicated", key)
		}
		if key == "GANDI_PAT_TOKEN" {
			if value == "" || !tokenPattern.MatchString(value) {
				return zero, errors.New("GANDI_PAT_TOKEN is empty or has a non-canonical representation")
			}
		} else {
			var err error
			value, err = singleQuoted(value)
			if err != nil {
				return zero, fmt.Errorf("deployment config key %s: %w", key, err)
			}
		}
		if strings.ContainsAny(value, "\r\n\x00") || strings.Contains(value, "$(") || strings.Contains(value, "${") || strings.Contains(value, "`") {
			return zero, fmt.Errorf("deployment config key %s contains shell expansion or control data", key)
		}
		values[key] = value
	}
	if err := scanner.Err(); err != nil {
		return zero, err
	}
	for _, required := range orderedKeys {
		if _, present := values[required]; !present {
			return zero, fmt.Errorf("deployment config is missing %s", required)
		}
	}
	for _, required := range []string{"GANDI_PAT_TOKEN", "LOOM_DEPLOY_HOSTS", "LOOM_SIGNING_KEY", "LOOM_PUBLISH_OUTPUTS"} {
		if values[required] == "" {
			return zero, fmt.Errorf("deployment config is missing %s", required)
		}
	}

	hosts, err := uniqueSorted(strings.Fields(values["LOOM_DEPLOY_HOSTS"]), validAlias, "deploy host")
	if err != nil || len(hosts) == 0 {
		if err == nil {
			err = errors.New("deploy host set is empty")
		}
		return zero, err
	}
	local := values["LOOM_LOCAL_NODE"]
	if local != "" {
		if !validAlias(local) || !contains(hosts, local) {
			return zero, errors.New("LOOM_LOCAL_NODE must be one of LOOM_DEPLOY_HOSTS")
		}
	}
	ssh := values["LOOM_SSH_CONFIG"]
	if ssh == "" {
		ssh = DefaultSSHConfig
	}
	ssh, err = anchoredPath(anchor, ssh)
	if err != nil {
		return zero, fmt.Errorf("LOOM_SSH_CONFIG: %w", err)
	}
	signing, err := reference(anchor, values["LOOM_SIGNING_KEY"])
	if err != nil {
		return zero, fmt.Errorf("LOOM_SIGNING_KEY: %w", err)
	}
	outputs, err := uniqueSorted(strings.Split(values["LOOM_PUBLISH_OUTPUTS"], ","), validTarget, "publish target")
	if err != nil || len(outputs) == 0 {
		if err == nil {
			err = errors.New("publish target set is empty")
		}
		return zero, err
	}
	return Config{GandiPATToken: values["GANDI_PAT_TOKEN"], DeployHosts: hosts, LocalNode: local,
		SSHConfig: ssh, SigningKey: signing, PublishOutputs: outputs}, nil
}

func Encode(config Config, anchor string) ([]byte, error) {
	decoded, err := Decode([]byte(fmt.Sprintf("GANDI_PAT_TOKEN=%s\nLOOM_DEPLOY_HOSTS='%s'\nLOOM_LOCAL_NODE='%s'\nLOOM_SSH_CONFIG='%s'\nLOOM_SIGNING_KEY='%s'\nLOOM_PUBLISH_OUTPUTS='%s'\n",
		config.GandiPATToken, strings.Join(config.DeployHosts, " "), config.LocalNode,
		relativeTo(anchor, config.SSHConfig), relativeTo(anchor, config.SigningKey), strings.Join(config.PublishOutputs, ","))), anchor)
	if err != nil {
		return nil, err
	}
	return []byte(fmt.Sprintf("GANDI_PAT_TOKEN=%s\nLOOM_DEPLOY_HOSTS='%s'\nLOOM_LOCAL_NODE='%s'\nLOOM_SSH_CONFIG='%s'\nLOOM_SIGNING_KEY='%s'\nLOOM_PUBLISH_OUTPUTS='%s'\n",
		decoded.GandiPATToken, strings.Join(decoded.DeployHosts, " "), decoded.LocalNode,
		relativeTo(anchor, decoded.SSHConfig), relativeTo(anchor, decoded.SigningKey), strings.Join(decoded.PublishOutputs, ","))), nil
}

func singleQuoted(value string) (string, error) {
	if len(value) < 2 || value[0] != '\'' || value[len(value)-1] != '\'' || strings.Contains(value[1:len(value)-1], "'") {
		return "", errors.New("value must use one pair of single quotes")
	}
	return value[1 : len(value)-1], nil
}

func uniqueSorted(values []string, valid func(string) bool, name string) ([]string, error) {
	seen := map[string]bool{}
	result := make([]string, 0, len(values))
	for _, value := range values {
		if !valid(value) {
			return nil, fmt.Errorf("%s %q is invalid", name, value)
		}
		if seen[value] {
			return nil, fmt.Errorf("%s %q is duplicated", name, value)
		}
		seen[value] = true
		result = append(result, value)
	}
	sort.Strings(result)
	return result, nil
}

func validAlias(value string) bool { return aliasPattern.MatchString(value) }

func validTarget(value string) bool {
	if value == "" || strings.TrimSpace(value) != value {
		return false
	}
	if strings.HasPrefix(value, "ssh://") {
		rest := strings.TrimPrefix(value, "ssh://")
		alias, path, ok := strings.Cut(rest, "/")
		return ok && validAlias(alias) && path != "" && cleanAbsolute("/"+path)
	}
	return cleanAbsolute(value)
}

func anchoredPath(anchor, value string) (string, error) {
	if value == "" || strings.ContainsAny(value, "\r\n") {
		return "", errors.New("path is empty or invalid")
	}
	if !filepath.IsAbs(value) {
		value = filepath.Join(anchor, value)
	}
	return filepath.Clean(value), nil
}

func reference(anchor, value string) (string, error) {
	for _, prefix := range []string{"pkcs11:", "secret:"} {
		if strings.HasPrefix(value, prefix) && len(value) > len(prefix) {
			return value, nil
		}
	}
	return anchoredPath(anchor, value)
}

func cleanAbsolute(value string) bool {
	return filepath.IsAbs(value) && filepath.Clean(value) == value && !strings.Contains(value, "//")
}

func relativeTo(anchor, value string) string {
	if strings.HasPrefix(value, "pkcs11:") || strings.HasPrefix(value, "secret:") {
		return value
	}
	rel, err := filepath.Rel(anchor, value)
	if err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return filepath.ToSlash(rel)
	}
	return value
}

func contains(values []string, wanted string) bool {
	index := sort.SearchStrings(values, wanted)
	return index < len(values) && values[index] == wanted
}

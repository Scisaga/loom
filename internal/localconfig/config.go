// Package localconfig loads the workstation's private .env reference and its
// sole deployment YAML. Both files are data and never execute shell expressions.
package localconfig

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode"

	"gopkg.in/yaml.v3"
)

const (
	DefaultSSHConfig = ".ssh_config"
	configSchema     = 1 // Existing operator input, independent of signed schema 3 objects.
	maxConfigSize    = 1 << 20
)

var (
	aliasPattern     = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)
	tokenPattern     = regexp.MustCompile(`^[A-Za-z0-9._~+/=-]+$`)
	hostLabelPattern = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)
	purposePattern   = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,31}$`)
)

type Config struct {
	GandiPATToken  string `json:"-"`
	DeployHosts    []string
	LocalNode      string
	Nodes          []NodeNetwork
	SSHConfig      string
	SigningKey     string
	PublishOutputs []string
}

type NodeNetwork struct {
	ID             string           `json:"id" yaml:"id"`
	ManagementHost string           `json:"management_host" yaml:"management_host"`
	ManagementPort int              `json:"management_port" yaml:"management_port"`
	HostAddresses  []string         `json:"host_addresses" yaml:"host_addresses"`
	Ingress        []IngressMapping `json:"ingress" yaml:"ingress"`
}

type IngressMapping struct {
	Purpose     string    `json:"purpose" yaml:"purpose"`
	Protocol    string    `json:"protocol" yaml:"protocol"`
	PublicHost  string    `json:"public_host" yaml:"public_host"`
	PublicPorts PortRange `json:"public_ports" yaml:"public_ports"`
	HostAddress string    `json:"host_address" yaml:"host_address"`
	HostPorts   PortRange `json:"host_ports" yaml:"host_ports"`
}

type PortRange struct {
	First int `json:"first" yaml:"first"`
	Last  int `json:"last" yaml:"last"`
}

type deployFile struct {
	Schema         int           `yaml:"schema"`
	DeployHosts    []string      `yaml:"deploy_hosts"`
	LocalNode      string        `yaml:"local_node,omitempty"`
	Nodes          []NodeNetwork `yaml:"nodes"`
	SSHConfig      string        `yaml:"ssh_config"`
	SigningKey     string        `yaml:"signing_key"`
	PublishOutputs []string      `yaml:"publish_outputs"`
}

// Load follows the sole dotenv reference. It never changes either input file.
func Load(envPath string) (Config, error) {
	path, err := filepath.Abs(envPath)
	if err != nil {
		return Config{}, errors.New("invalid environment path")
	}
	body, err := readOwnerOnlyFile(path)
	if err != nil {
		return Config{}, fmt.Errorf("load local environment: %w", err)
	}
	token, deployPath, err := decodeEnv(body, filepath.Dir(path))
	if err != nil {
		return Config{}, err
	}
	body, err = readOwnerOnlyFile(deployPath)
	if err != nil {
		return Config{}, fmt.Errorf("load deployment YAML: %w", err)
	}
	config, err := DecodeDeployment(body, filepath.Dir(deployPath))
	if err != nil {
		return Config{}, err
	}
	config.GandiPATToken = token
	return config, nil
}

func decodeEnv(body []byte, anchor string) (string, string, error) {
	if len(body) == 0 || len(body) > maxConfigSize || bytes.IndexByte(body, 0) >= 0 {
		return "", "", errors.New("invalid local environment size or NUL")
	}
	values, err := decodeAssignments(body, map[string]bool{"GANDI_PAT_TOKEN": true, "LOOM_DEPLOY_CONFIG": true})
	if err != nil {
		return "", "", err
	}
	token, present := values["GANDI_PAT_TOKEN"]
	if present && (token == "" || !tokenPattern.MatchString(token)) {
		return "", "", errors.New("GANDI_PAT_TOKEN must be omitted or contain a nonempty canonical token")
	}
	ref, err := singleQuoted(values["LOOM_DEPLOY_CONFIG"])
	if err != nil {
		return "", "", errors.New("LOOM_DEPLOY_CONFIG requires a single-quoted file reference")
	}
	path, err := anchoredPath(anchor, ref)
	if err != nil {
		return "", "", errors.New("LOOM_DEPLOY_CONFIG is invalid")
	}
	canonical, err := encodeEnv(token, path, anchor)
	if err != nil || !bytes.Equal(body, canonical) {
		return "", "", errors.New("local environment is not canonical")
	}
	return token, path, nil
}

func encodeEnv(token, path, anchor string) ([]byte, error) {
	if token != "" && !tokenPattern.MatchString(token) {
		return nil, errors.New("invalid provider token")
	}
	ref := relativeTo(anchor, path)
	if ref == "" || strings.ContainsAny(ref, "'`$") || strings.ContainsFunc(ref, unicode.IsControl) {
		return nil, errors.New("invalid deployment file reference")
	}
	var body strings.Builder
	if token != "" {
		fmt.Fprintf(&body, "GANDI_PAT_TOKEN=%s\n", token)
	}
	fmt.Fprintf(&body, "LOOM_DEPLOY_CONFIG='%s'\n", ref)
	return []byte(body.String()), nil
}

// DecodeDeployment accepts only the existing canonical YAML, including all
// operator-owned ingress mappings; it has no access to the provider token.
func DecodeDeployment(body []byte, anchor string) (Config, error) {
	if len(body) == 0 || len(body) > maxConfigSize || bytes.IndexByte(body, 0) >= 0 {
		return Config{}, errors.New("invalid deployment YAML size or NUL")
	}
	var syntax yaml.Node
	decoder := yaml.NewDecoder(bytes.NewReader(body))
	if err := decoder.Decode(&syntax); err != nil {
		return Config{}, errors.New("invalid deployment YAML syntax")
	}
	if err := requireYAMLEOF(decoder); err != nil {
		return Config{}, err
	}
	if err := validateYAMLNode(&syntax); err != nil {
		return Config{}, err
	}
	var wire deployFile
	decoder = yaml.NewDecoder(bytes.NewReader(body))
	decoder.KnownFields(true)
	if err := decoder.Decode(&wire); err != nil {
		return Config{}, errors.New("deployment YAML contains unknown fields or incorrect value types")
	}
	config, err := normalizeDeployFile(wire, anchor)
	if err != nil {
		return Config{}, err
	}
	canonical, err := marshalDeployment(config, anchor)
	if err != nil || !bytes.Equal(body, canonical) {
		return Config{}, errors.New("deployment YAML is not canonical")
	}
	return config, nil
}

func EncodeDeployment(config Config, anchor string) ([]byte, error) {
	body, err := marshalDeployment(config, anchor)
	if err != nil {
		return nil, err
	}
	if _, err = DecodeDeployment(body, anchor); err != nil {
		return nil, err
	}
	return body, nil
}

func marshalDeployment(config Config, anchor string) ([]byte, error) {
	return yaml.Marshal(deployFile{Schema: configSchema, DeployHosts: config.DeployHosts, LocalNode: config.LocalNode,
		Nodes: config.Nodes, SSHConfig: relativeTo(anchor, config.SSHConfig), SigningKey: relativeTo(anchor, config.SigningKey), PublishOutputs: config.PublishOutputs})
}

func readOwnerOnlyFile(path string) ([]byte, error) {
	before, err := os.Lstat(path)
	if err != nil {
		return nil, errors.New("private input file is unavailable")
	}
	if !before.Mode().IsRegular() || before.Mode().Perm()&0077 != 0 {
		return nil, errors.New("input must be an owner-only regular file")
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, errors.New("private input file cannot be opened")
	}
	defer f.Close()
	after, err := f.Stat()
	if err != nil || !os.SameFile(before, after) || !after.Mode().IsRegular() || after.Mode().Perm()&0077 != 0 {
		return nil, errors.New("private input changed while opening")
	}
	body, err := io.ReadAll(io.LimitReader(f, maxConfigSize+1))
	if err != nil || len(body) > maxConfigSize {
		return nil, errors.New("private input is unreadable or exceeds size limit")
	}
	return body, nil
}

func decodeAssignments(body []byte, allowed map[string]bool) (map[string]string, error) {
	values := map[string]string{}
	scanner := bufio.NewScanner(bytes.NewReader(body))
	for line := 1; scanner.Scan(); line++ {
		raw := scanner.Text()
		if strings.TrimSpace(raw) == "" || strings.HasPrefix(strings.TrimSpace(raw), "#") {
			continue
		}
		key, value, ok := strings.Cut(raw, "=")
		if !ok || strings.TrimSpace(key) != key || !allowed[key] {
			return nil, fmt.Errorf("local environment line %d has an unknown or malformed key", line)
		}
		if _, duplicate := values[key]; duplicate {
			return nil, fmt.Errorf("local environment key %s is duplicated", key)
		}
		if strings.ContainsFunc(value, unicode.IsControl) || strings.Contains(value, "$(") ||
			strings.Contains(value, "${") || strings.Contains(value, "`") {
			return nil, fmt.Errorf("local environment key %s contains shell expansion or control data", key)
		}
		values[key] = value
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return values, nil
}

func normalizeDeployFile(wire deployFile, anchor string) (Config, error) {
	var zero Config
	if wire.Schema != configSchema {
		return zero, errors.New("deployment YAML must use schema 1")
	}
	hosts, err := uniqueSorted(wire.DeployHosts, validAlias, "deploy host")
	if err != nil || len(hosts) == 0 {
		if err == nil {
			err = errors.New("deploy host set is empty")
		}
		return zero, err
	}
	if wire.LocalNode != "" && (!validAlias(wire.LocalNode) || !contains(hosts, wire.LocalNode)) {
		return zero, errors.New("local_node must be one of deploy_hosts")
	}
	nodes, err := normalizeNodes(wire.Nodes)
	if err != nil {
		return zero, fmt.Errorf("nodes: %w", err)
	}
	if err := validateNodesJoin(nodes, hosts, wire.LocalNode); err != nil {
		return zero, fmt.Errorf("nodes: %w", err)
	}
	ssh := wire.SSHConfig
	if ssh == "" {
		ssh = DefaultSSHConfig
	}
	ssh, err = anchoredPath(anchor, ssh)
	if err != nil {
		return zero, fmt.Errorf("ssh_config: %w", err)
	}
	signing, err := reference(anchor, wire.SigningKey)
	if err != nil {
		return zero, fmt.Errorf("signing_key: %w", err)
	}
	outputs, err := uniqueSorted(wire.PublishOutputs, validTarget, "publish target")
	if err != nil || len(outputs) == 0 {
		if err == nil {
			err = errors.New("publish target set is empty")
		}
		return zero, err
	}
	return Config{
		DeployHosts: hosts, LocalNode: wire.LocalNode, Nodes: nodes,
		SSHConfig: ssh, SigningKey: signing, PublishOutputs: outputs,
	}, nil
}

func normalizeNodes(nodes []NodeNetwork) ([]NodeNetwork, error) {
	if len(nodes) == 0 {
		return nodes, errors.New("deployment must contain nodes")
	}
	nodes = cloneNodes(nodes)
	seenNodes := map[string]bool{}
	seenPublic := map[string]string{}
	for index := range nodes {
		node := &nodes[index]
		if !validAlias(node.ID) || seenNodes[node.ID] {
			return nodes, errors.New("node id is invalid or duplicated")
		}
		seenNodes[node.ID] = true
		if !validHost(node.ManagementHost) || node.ManagementPort < 1 || node.ManagementPort > 65535 {
			return nodes, errors.New("node has invalid management endpoint")
		}
		addresses, err := uniqueSorted(node.HostAddresses, validCanonicalIP, "host address")
		if err != nil || len(addresses) == 0 {
			if err == nil {
				err = errors.New("host address set is empty")
			}
			return nodes, fmt.Errorf("node: %w", err)
		}
		node.HostAddresses = addresses
		if node.Ingress == nil {
			return nodes, errors.New("node ingress must be an explicit array")
		}
		for mappingIndex := range node.Ingress {
			mapping := &node.Ingress[mappingIndex]
			if !purposePattern.MatchString(mapping.Purpose) || mapping.Protocol != "tcp" && mapping.Protocol != "udp" ||
				!validHost(mapping.PublicHost) || !validCanonicalIP(mapping.HostAddress) ||
				!contains(node.HostAddresses, mapping.HostAddress) || !validPortRange(mapping.PublicPorts) ||
				!validPortRange(mapping.HostPorts) || mapping.PublicPorts.Last-mapping.PublicPorts.First != mapping.HostPorts.Last-mapping.HostPorts.First {
				return nodes, fmt.Errorf("node has invalid ingress mapping %d", mappingIndex)
			}
			for port := mapping.PublicPorts.First; port <= mapping.PublicPorts.Last; port++ {
				key := mapping.Protocol + "\x00" + mapping.PublicHost + "\x00" + strconv.Itoa(port)
				if previous := seenPublic[key]; previous != "" {
					return nodes, errors.New("nodes have overlapping public ingress")
				}
				seenPublic[key] = node.ID
			}
		}
		sort.Slice(node.Ingress, func(left, right int) bool {
			a, b := node.Ingress[left], node.Ingress[right]
			ak := a.Protocol + "\x00" + a.PublicHost + "\x00" + fmt.Sprintf("%05d\x00%s", a.PublicPorts.First, a.Purpose)
			bk := b.Protocol + "\x00" + b.PublicHost + "\x00" + fmt.Sprintf("%05d\x00%s", b.PublicPorts.First, b.Purpose)
			return ak < bk
		})
	}
	sort.Slice(nodes, func(left, right int) bool { return nodes[left].ID < nodes[right].ID })
	return nodes, nil
}

func validateNodesJoin(nodes []NodeNetwork, hosts []string, local string) error {
	if len(nodes) != len(hosts) {
		return errors.New("deployment node set must exactly match deploy_hosts")
	}
	for index, host := range hosts {
		if nodes[index].ID != host {
			return errors.New("deployment node set must exactly match deploy_hosts")
		}
	}
	if local != "" {
		index := sort.Search(len(nodes), func(index int) bool { return nodes[index].ID >= local })
		host := nodes[index].ManagementHost
		if host != "localhost" {
			address, err := netip.ParseAddr(host)
			if err != nil || !address.IsLoopback() {
				return errors.New("local node management_host must be localhost or a canonical loopback address")
			}
		}
	}
	return nil
}

func validateYAMLNode(node *yaml.Node) error {
	if node == nil || node.Kind != yaml.DocumentNode || len(node.Content) != 1 {
		return errors.New("deployment config must contain exactly one YAML document")
	}
	return walkYAMLNode(node.Content[0])
}

func walkYAMLNode(node *yaml.Node) error {
	if node.Anchor != "" || node.Kind == yaml.AliasNode {
		return errors.New("deployment config does not allow YAML anchors or aliases")
	}
	switch node.Kind {
	case yaml.MappingNode:
		if node.Tag != "!!map" || len(node.Content)%2 != 0 {
			return errors.New("deployment config contains a non-standard YAML mapping")
		}
		seen := map[string]bool{}
		for index := 0; index < len(node.Content); index += 2 {
			key := node.Content[index]
			if key.Kind != yaml.ScalarNode || key.Tag != "!!str" || key.Value == "" || seen[key.Value] || key.Value == "<<" {
				return errors.New("deployment config contains an invalid or duplicate YAML key")
			}
			seen[key.Value] = true
			if err := walkYAMLNode(node.Content[index+1]); err != nil {
				return err
			}
		}
	case yaml.SequenceNode:
		if node.Tag != "!!seq" {
			return errors.New("deployment config contains a non-standard YAML sequence")
		}
		for _, child := range node.Content {
			if err := walkYAMLNode(child); err != nil {
				return err
			}
		}
	case yaml.ScalarNode:
		if node.Tag != "!!str" && node.Tag != "!!int" {
			return errors.New("deployment config only allows string and integer YAML scalars")
		}
	default:
		return errors.New("deployment config contains an unsupported YAML node")
	}
	return nil
}

func requireYAMLEOF(decoder *yaml.Decoder) error {
	var extra yaml.Node
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return errors.New("deployment config has trailing YAML content")
	}
	return nil
}

func cloneNodes(nodes []NodeNetwork) []NodeNetwork {
	cloned := make([]NodeNetwork, len(nodes))
	for index, node := range nodes {
		cloned[index] = node
		cloned[index].HostAddresses = append([]string(nil), node.HostAddresses...)
		cloned[index].Ingress = append([]IngressMapping(nil), node.Ingress...)
		if node.Ingress != nil && cloned[index].Ingress == nil {
			cloned[index].Ingress = []IngressMapping{}
		}
	}
	return cloned
}

func validCanonicalIP(value string) bool {
	address, err := netip.ParseAddr(value)
	return err == nil && address.String() == value
}

func validPortRange(value PortRange) bool {
	return value.First >= 1 && value.First <= value.Last && value.Last <= 65535
}

func validHost(value string) bool {
	if validCanonicalIP(value) {
		return true
	}
	if value == "" || len(value) > 253 || value != strings.ToLower(value) || strings.HasSuffix(value, ".") {
		return false
	}
	for _, label := range strings.Split(value, ".") {
		if !hostLabelPattern.MatchString(label) {
			return false
		}
	}
	return true
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
			return nil, fmt.Errorf("%s is invalid", name)
		}
		if seen[value] {
			return nil, fmt.Errorf("%s is duplicated", name)
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
	if value == "" || strings.ContainsFunc(value, unicode.IsControl) || strings.ContainsAny(value, "`$") {
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

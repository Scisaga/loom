package linuxclient

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

const DefaultMigrationOverlay = "/var/lib/loom-device/migration-overlay.json"

type migrationOverlay struct {
	Schema       int                 `json:"schema"`
	SourceSHA256 string              `json:"source_sha256"`
	Protocol     string              `json:"protocol"`
	ListenPort   int                 `json:"listen_port"`
	Users        []migrationUser     `json:"users"`
	Rules        []migrationRule     `json:"rules"`
	Outbounds    []migrationOutbound `json:"outbounds"`
}

type migrationUser struct {
	Name     string `json:"name"`
	Password string `json:"password"`
}

type migrationRule struct {
	Users        []string `json:"users"`
	Outbound     string   `json:"outbound"`
	Domain       []string `json:"domain,omitempty"`
	DomainSuffix []string `json:"domain_suffix,omitempty"`
	IPCIDR       []string `json:"ip_cidr,omitempty"`
	Ports        []int    `json:"ports,omitempty"`
}

type migrationOutbound struct {
	Tag           string `json:"tag"`
	Kind          string `json:"kind,omitempty"`
	BindInterface string `json:"bind_interface,omitempty"`
}

func (overlay migrationOverlay) validate() error {
	if overlay.Schema != 1 || len(overlay.SourceSHA256) != sha256.Size*2 ||
		overlay.Protocol != "hysteria2" && overlay.Protocol != "trojan" ||
		overlay.ListenPort < 1 || overlay.ListenPort > 65535 || len(overlay.Users) == 0 {
		return errors.New("migration overlay header is invalid")
	}
	if _, err := hex.DecodeString(overlay.SourceSHA256); err != nil || strings.ToLower(overlay.SourceSHA256) != overlay.SourceSHA256 {
		return errors.New("migration overlay source digest is invalid")
	}
	users := map[string]bool{}
	for index, user := range overlay.Users {
		if user.Name == "" || user.Password == "" || index > 0 && overlay.Users[index-1].Name >= user.Name {
			return errors.New("migration overlay users are invalid")
		}
		users[user.Name] = true
	}
	outbounds := map[string]bool{}
	for index, outbound := range overlay.Outbounds {
		if outbound.Tag == "" || outbound.Kind != "" && outbound.Kind != "direct" && outbound.Kind != "block" ||
			outbound.Kind == "block" && outbound.BindInterface != "" ||
			index > 0 && overlay.Outbounds[index-1].Tag >= outbound.Tag {
			return errors.New("migration overlay outbounds are invalid")
		}
		outbounds[outbound.Tag] = true
	}
	for _, rule := range overlay.Rules {
		if len(rule.Users) == 0 || rule.Outbound == "" || !outbounds[rule.Outbound] {
			return errors.New("migration overlay rule is incomplete")
		}
		for index, user := range rule.Users {
			if !users[user] || index > 0 && rule.Users[index-1] >= user {
				return errors.New("migration overlay rule users are invalid")
			}
		}
		for _, values := range [][]string{rule.Domain, rule.DomainSuffix, rule.IPCIDR} {
			for index, value := range values {
				if value == "" || index > 0 && values[index-1] >= value {
					return errors.New("migration overlay rule matchers are invalid")
				}
			}
		}
		for index, port := range rule.Ports {
			if port < 1 || port > 65535 || index > 0 && rule.Ports[index-1] >= port {
				return errors.New("migration overlay rule ports are invalid")
			}
		}
	}
	return nil
}

// StageMigrationOverlay extracts only the bounded old server user/ACL subset.
// Neither the source body nor the resulting secrets are printed by this API.
func StageMigrationOverlay(source, destination string) (string, error) {
	body, err := readOwnerOnlyRegular(source, 16<<20)
	if err != nil {
		return "", err
	}
	overlay, err := extractMigrationOverlay(body)
	if err != nil {
		return "", err
	}
	existing, existingErr := loadMigrationOverlay(destination)
	if existingErr != nil {
		return "", existingErr
	}
	if existing != nil {
		if existing.SourceSHA256 == overlay.SourceSHA256 {
			return overlay.SourceSHA256, nil
		}
		return "", errors.New("refusing to replace a migration overlay from a different source")
	}
	encoded, err := json.Marshal(overlay)
	if err != nil {
		return "", err
	}
	encoded = append(encoded, '\n')
	if err := atomicJSONBytes(destination, encoded); err != nil {
		return "", err
	}
	info, err := os.Lstat(destination)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
		return "", errors.New("migration overlay was not saved as an owner-only regular file")
	}
	return overlay.SourceSHA256, nil
}

func readOwnerOnlyRegular(path string, limit int64) ([]byte, error) {
	before, err := os.Lstat(path)
	if err != nil || !before.Mode().IsRegular() || before.Mode()&os.ModeSymlink != 0 ||
		before.Mode().Perm()&0o077 != 0 || before.Size() < 1 || before.Size() > limit {
		return nil, errors.New("migration input must be a bounded owner-only regular file")
	}
	body, err := os.ReadFile(path)
	after, statErr := os.Lstat(path)
	if err != nil || statErr != nil || !os.SameFile(before, after) || int64(len(body)) != before.Size() {
		return nil, errors.New("migration input changed while reading")
	}
	return body, nil
}

func extractMigrationOverlay(body []byte) (migrationOverlay, error) {
	if err := rejectDuplicateJSONFields(body); err != nil {
		return migrationOverlay{}, err
	}
	var document map[string]json.RawMessage
	if err := json.Unmarshal(body, &document); err != nil {
		return migrationOverlay{}, errors.New("legacy runtime is not valid JSON")
	}
	var inbounds []json.RawMessage
	var outbounds []json.RawMessage
	var route struct {
		Rules []json.RawMessage `json:"rules"`
	}
	if json.Unmarshal(document["inbounds"], &inbounds) != nil || json.Unmarshal(document["outbounds"], &outbounds) != nil ||
		json.Unmarshal(document["route"], &route) != nil {
		return migrationOverlay{}, errors.New("legacy server runtime collections are missing")
	}
	overlay := migrationOverlay{Schema: 1}
	serverInboundTag := ""
	sum := sha256.Sum256(body)
	overlay.SourceSHA256 = hex.EncodeToString(sum[:])
	for _, raw := range inbounds {
		var kind struct {
			Type string `json:"type"`
		}
		if json.Unmarshal(raw, &kind) != nil {
			return migrationOverlay{}, errors.New("legacy inbound is invalid")
		}
		if kind.Type != "hysteria2" && kind.Type != "trojan" {
			continue
		}
		if overlay.Protocol != "" {
			return migrationOverlay{}, errors.New("legacy runtime has multiple server inbounds")
		}
		var inbound struct {
			Type       string          `json:"type"`
			Tag        string          `json:"tag"`
			Listen     string          `json:"listen"`
			ListenPort int             `json:"listen_port"`
			Users      []migrationUser `json:"users"`
			TLS        json.RawMessage `json:"tls"`
		}
		if err := decodeStrictLocal(raw, &inbound); err != nil || inbound.Tag == "" || len(inbound.TLS) == 0 {
			return migrationOverlay{}, errors.New("legacy server inbound is unsupported")
		}
		overlay.Protocol, overlay.ListenPort, overlay.Users = inbound.Type, inbound.ListenPort, inbound.Users
		serverInboundTag = inbound.Tag
	}
	if overlay.Protocol == "" {
		return migrationOverlay{}, errors.New("legacy runtime has no server inbound")
	}
	sort.Slice(overlay.Users, func(i, j int) bool { return overlay.Users[i].Name < overlay.Users[j].Name })
	userSet := map[string]bool{}
	for _, user := range overlay.Users {
		if userSet[user.Name] {
			return migrationOverlay{}, errors.New("legacy server inbound has duplicate users")
		}
		userSet[user.Name] = true
	}
	referenced := map[string]bool{}
	for _, raw := range route.Rules {
		var fields map[string]json.RawMessage
		if json.Unmarshal(raw, &fields) != nil || fields["auth_user"] == nil {
			continue
		}
		var rule struct {
			Users        []string `json:"auth_user"`
			Inbound      []string `json:"inbound,omitempty"`
			Outbound     string   `json:"outbound"`
			Domain       []string `json:"domain,omitempty"`
			DomainSuffix []string `json:"domain_suffix,omitempty"`
			IPCIDR       []string `json:"ip_cidr,omitempty"`
			Ports        []int    `json:"port,omitempty"`
		}
		if err := decodeStrictLocal(raw, &rule); err != nil {
			return migrationOverlay{}, errors.New("legacy authenticated route rule is unsupported")
		}
		if len(rule.Inbound) != 0 && !containsString(rule.Inbound, serverInboundTag) {
			continue
		}
		serverUsers := rule.Users[:0]
		for _, user := range rule.Users {
			if userSet[user] {
				serverUsers = append(serverUsers, user)
			}
		}
		rule.Users = serverUsers
		if len(rule.Users) == 0 {
			continue
		}
		sort.Strings(rule.Users)
		sort.Strings(rule.Domain)
		sort.Strings(rule.DomainSuffix)
		sort.Strings(rule.IPCIDR)
		sort.Ints(rule.Ports)
		overlay.Rules = append(overlay.Rules, migrationRule{Users: rule.Users, Outbound: rule.Outbound,
			Domain: rule.Domain, DomainSuffix: rule.DomainSuffix, IPCIDR: rule.IPCIDR, Ports: rule.Ports})
		referenced[rule.Outbound] = true
	}
	for _, raw := range outbounds {
		var base struct {
			Type string `json:"type"`
			Tag  string `json:"tag"`
		}
		if json.Unmarshal(raw, &base) != nil || !referenced[base.Tag] {
			continue
		}
		var outbound struct {
			Type          string `json:"type"`
			Tag           string `json:"tag"`
			BindInterface string `json:"bind_interface,omitempty"`
		}
		if err := decodeStrictLocal(raw, &outbound); err != nil || outbound.Type != "direct" && outbound.Type != "block" {
			return migrationOverlay{}, errors.New("legacy authenticated rule requires an unsupported outbound")
		}
		kind := ""
		if outbound.Type == "block" {
			kind = "block"
		}
		overlay.Outbounds = append(overlay.Outbounds, migrationOutbound{Tag: outbound.Tag, Kind: kind, BindInterface: outbound.BindInterface})
		delete(referenced, outbound.Tag)
	}
	if len(referenced) != 0 {
		return migrationOverlay{}, errors.New("legacy authenticated rule outbound is missing")
	}
	sort.Slice(overlay.Outbounds, func(i, j int) bool { return overlay.Outbounds[i].Tag < overlay.Outbounds[j].Tag })
	if err := overlay.validate(); err != nil {
		return migrationOverlay{}, err
	}
	return overlay, nil
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func loadMigrationOverlay(path string) (*migrationOverlay, error) {
	body, err := readOwnerOnlyRegular(path, 16<<20)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		if _, statErr := os.Lstat(path); errors.Is(statErr, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	if err := rejectDuplicateJSONFields(body); err != nil {
		return nil, err
	}
	var overlay migrationOverlay
	if err := decodeStrictLocal(body, &overlay); err != nil || overlay.validate() != nil {
		return nil, errors.New("migration overlay is invalid")
	}
	return &overlay, nil
}

func applyMigrationOverlay(config string, profile controlServerProfile, path string) (string, bool, error) {
	overlay, err := loadMigrationOverlay(path)
	if err != nil || overlay == nil {
		return config, overlay == nil, err
	}
	if overlay.Protocol != profile.Protocol || overlay.ListenPort != profile.ListenPort {
		return "", false, errors.New("migration overlay listener does not match certified ServerRuntime")
	}
	var document map[string]any
	if err := json.Unmarshal([]byte(config), &document); err != nil {
		return "", false, errors.New("rendered server runtime is invalid")
	}
	inbounds, ok := document["inbounds"].([]any)
	if !ok {
		return "", false, errors.New("rendered server inbounds are invalid")
	}
	var serverInbound map[string]any
	for _, raw := range inbounds {
		inbound, _ := raw.(map[string]any)
		if inbound["tag"] == "loom-server-in" {
			serverInbound = inbound
			break
		}
	}
	if serverInbound == nil {
		return "", false, errors.New("rendered server inbound is missing")
	}
	users, ok := serverInbound["users"].([]any)
	if !ok {
		return "", false, errors.New("rendered server users are invalid")
	}
	names := map[string]string{}
	for _, raw := range users {
		user, _ := raw.(map[string]any)
		name, _ := user["name"].(string)
		password, _ := user["password"].(string)
		names[name] = password
	}
	for _, user := range overlay.Users {
		if _, found := names[user.Name]; found {
			return "", false, errors.New("migration overlay user conflicts with certified ServerRuntime")
		}
		users = append(users, map[string]any{"name": user.Name, "password": user.Password})
	}
	serverInbound["users"] = users

	outbounds, ok := document["outbounds"].([]any)
	if !ok {
		return "", false, errors.New("rendered server outbounds are invalid")
	}
	tags := map[string]bool{}
	for _, raw := range outbounds {
		outbound, _ := raw.(map[string]any)
		tag, _ := outbound["tag"].(string)
		tags[tag] = true
	}
	mapped := map[string]string{}
	for _, outbound := range overlay.Outbounds {
		if outbound.Kind == "block" {
			mapped[outbound.Tag] = "loom-server-block"
			continue
		}
		sum := sha256.Sum256([]byte(outbound.Tag + "\x00" + outbound.BindInterface))
		tag := "loom-migration-" + hex.EncodeToString(sum[:6])
		if tags[tag] {
			return "", false, errors.New("migration overlay outbound conflicts with certified ServerRuntime")
		}
		value := map[string]any{"type": "direct", "tag": tag}
		if outbound.BindInterface != "" {
			value["bind_interface"] = outbound.BindInterface
		}
		outbounds = append(outbounds, value)
		tags[tag], mapped[outbound.Tag] = true, tag
	}
	document["outbounds"] = outbounds
	route, ok := document["route"].(map[string]any)
	if !ok {
		return "", false, errors.New("rendered server route is invalid")
	}
	rules, ok := route["rules"].([]any)
	if !ok {
		return "", false, errors.New("rendered server rules are invalid")
	}
	insert := -1
	for index, raw := range rules {
		rule, _ := raw.(map[string]any)
		if rule["outbound"] == "loom-server-block" {
			insert = index
			break
		}
	}
	if insert < 0 {
		return "", false, errors.New("rendered server fail-closed rule is missing")
	}
	migrationRules := make([]any, 0, len(overlay.Rules))
	for _, rule := range overlay.Rules {
		value := map[string]any{"auth_user": append([]string(nil), rule.Users...), "outbound": mapped[rule.Outbound]}
		if len(rule.Domain) != 0 {
			value["domain"] = append([]string(nil), rule.Domain...)
		}
		if len(rule.DomainSuffix) != 0 {
			value["domain_suffix"] = append([]string(nil), rule.DomainSuffix...)
		}
		if len(rule.IPCIDR) != 0 {
			value["ip_cidr"] = append([]string(nil), rule.IPCIDR...)
		}
		if len(rule.Ports) != 0 {
			value["port"] = append([]int(nil), rule.Ports...)
		}
		migrationRules = append(migrationRules, value)
	}
	mergedRules := make([]any, 0, len(rules)+len(migrationRules))
	mergedRules = append(mergedRules, rules[:insert]...)
	mergedRules = append(mergedRules, migrationRules...)
	mergedRules = append(mergedRules, rules[insert:]...)
	rules = mergedRules
	route["rules"] = rules
	body, err := json.Marshal(document)
	return string(body), false, err
}

// controlServerProfile keeps this local adapter independent of a second
// migration model while accepting the two certified listener coordinates.
type controlServerProfile struct {
	Protocol   string
	ListenPort int
}

func decodeStrictLocal(body []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return errors.New("JSON has trailing content")
	}
	return nil
}

func rejectDuplicateJSONFields(body []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(body))
	type frame struct {
		object    bool
		expectKey bool
		keys      map[string]bool
	}
	stack := []frame{}
	for {
		token, err := decoder.Token()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
		switch value := token.(type) {
		case json.Delim:
			switch value {
			case '{':
				stack = append(stack, frame{object: true, expectKey: true, keys: map[string]bool{}})
			case '[':
				stack = append(stack, frame{})
			case '}', ']':
				if len(stack) == 0 {
					return errors.New("JSON delimiter is unbalanced")
				}
				stack = stack[:len(stack)-1]
				if len(stack) > 0 && stack[len(stack)-1].object {
					stack[len(stack)-1].expectKey = true
				}
			}
		case string:
			if len(stack) > 0 && stack[len(stack)-1].object && stack[len(stack)-1].expectKey {
				current := &stack[len(stack)-1]
				if current.keys[value] {
					return fmt.Errorf("duplicate JSON field %q", value)
				}
				current.keys[value], current.expectKey = true, false
			} else if len(stack) > 0 && stack[len(stack)-1].object {
				stack[len(stack)-1].expectKey = true
			}
		default:
			if len(stack) > 0 && stack[len(stack)-1].object {
				stack[len(stack)-1].expectKey = true
			}
		}
	}
}

// FinalizeMigrationOverlay removes exactly the staged source digest. The next
// service restart must render the pure certified ServerRuntime and can then
// report exact=true.
func FinalizeMigrationOverlay(path, expectedDigest string) error {
	overlay, err := loadMigrationOverlay(path)
	if err != nil {
		return err
	}
	if overlay == nil {
		return errors.New("migration overlay does not exist")
	}
	if expectedDigest == "" || overlay.SourceSHA256 != expectedDigest {
		return errors.New("migration overlay source digest does not match")
	}
	if err := os.Remove(path); err != nil {
		return err
	}
	directory, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}

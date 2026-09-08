package ssotedit

import (
	"bytes"
	"errors"
	"fmt"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"

	"loom/internal/model"
	"loom/internal/validate"
)

// DeviceRemovalPlan is the complete SSOT side of removing an already
// decommissioned access-only Enrollment Device. SecretRefs are returned so the
// caller can garbage-collect only those now-unreferenced values after the
// removal snapshot has converged.
type DeviceRemovalPlan struct {
	Content       []byte
	CredentialIDs []string
	SecretRefs    []string
}

// SetAccessDevicePaused 只改可恢复的访问开关，不撤销身份或停掉 pull(§14.4)。
// 控制设备职责由调用方校验，因为 control 是中控本地事实。
func SetAccessDevicePaused(content []byte, id string, paused bool) ([]byte, error) {
	current, err := model.Load(content)
	if err != nil {
		return nil, err
	}
	if findings := validate.Validate(current); len(findings) > 0 {
		return nil, &ValidationError{Findings: findings}
	}
	node := current.NodeByID()[id]
	if node == nil || !node.IsAccess() || node.IsServer() || node.Decommission {
		return nil, errors.New("暂停/恢复只适用于未下线的纯 use_loom 设备")
	}
	if node.Paused == paused {
		return append([]byte(nil), content...), nil
	}
	doc, root, err := parseDocument(content)
	if err != nil {
		return nil, err
	}
	nodes, err := clientSequenceAt(root, "nodes")
	if err != nil {
		return nil, err
	}
	item, err := uniqueMappingByID(nodes, "nodes", id)
	if err != nil {
		return nil, err
	}
	value := "false"
	if paused {
		value = "true"
	}
	setMappingValue(item, "paused", &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!bool", Value: value})
	return encodeAndValidate(doc)
}

// DecommissionAccessDevice writes the authenticated stop instruction for one
// access-only Device. It deliberately refuses server and combined Devices:
// retiring an egress also requires policy, pool and tunnel migration and must
// not be hidden behind this narrow Enrollment cleanup path.
func DecommissionAccessDevice(content []byte, id string) ([]byte, error) {
	current, node, err := removableAccessDevice(content, id, false)
	if err != nil {
		return nil, err
	}
	if node.Decommission {
		return append([]byte(nil), content...), nil
	}
	if err := validateGeneratedAccessShape(current, node); err != nil {
		return nil, err
	}

	doc, root, err := parseDocument(content)
	if err != nil {
		return nil, err
	}
	nodes, err := clientSequenceAt(root, "nodes")
	if err != nil {
		return nil, err
	}
	item, err := uniqueMappingByID(nodes, "nodes", id)
	if err != nil {
		return nil, err
	}
	setMappingValue(item, "decommission", &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!bool", Value: "true"})
	if node.Paused {
		setMappingValue(item, "paused", &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!bool", Value: "false"})
	}
	return encodeAndValidate(doc)
}

// RemoveDecommissionedAccessDevice removes the declarative node and its
// generated, device-owned credentials only after the signed decommission phase
// has completed. Runtime confirmation is intentionally a caller responsibility;
// this pure editor cannot infer that a Device consumed the stop instruction.
func RemoveDecommissionedAccessDevice(content []byte, id string) (DeviceRemovalPlan, error) {
	return removeAccessDevice(content, id, true)
}

// RemoveLostAccessDevice 只供操作者确认本机身份已删除后的替换事务调用。
// 撤销旧凭据随签名配置下发；这不证明旧设备执行过 signed decommission。
func RemoveLostAccessDevice(content []byte, id string) (DeviceRemovalPlan, error) {
	return removeAccessDevice(content, id, false)
}

func removeAccessDevice(content []byte, id string, requireDecommission bool) (DeviceRemovalPlan, error) {
	current, node, err := removableAccessDevice(content, id, requireDecommission)
	if err != nil {
		return DeviceRemovalPlan{}, err
	}
	if err := validateGeneratedAccessShape(current, node); err != nil {
		return DeviceRemovalPlan{}, err
	}

	credentialIDs := append([]string(nil), node.Access.Credentials...)
	sort.Strings(credentialIDs)
	removeCredentials := make(map[string]bool, len(credentialIDs))
	secretRefs := make([]string, 0, len(credentialIDs))
	credentials := current.CredentialByID()
	for _, credentialID := range credentialIDs {
		credential := credentials[credentialID]
		if credential == nil || credential.Owner != id {
			return DeviceRemovalPlan{}, fmt.Errorf("Device %q credential %q is not exclusively owned by it", id, credentialID)
		}
		removeCredentials[credentialID] = true
		secretRefs = append(secretRefs, credential.Ref())
	}
	for _, other := range current.AccessNodes() {
		if other.ID == id {
			continue
		}
		for _, credentialID := range other.Access.Credentials {
			if removeCredentials[credentialID] {
				return DeviceRemovalPlan{}, fmt.Errorf("Device %q credential %q is still referenced by %q", id, credentialID, other.ID)
			}
		}
	}
	sort.Strings(secretRefs)

	doc, root, err := parseDocument(content)
	if err != nil {
		return DeviceRemovalPlan{}, err
	}
	nodes, err := clientSequenceAt(root, "nodes")
	if err != nil {
		return DeviceRemovalPlan{}, err
	}
	if err := removeUniqueMappingByID(nodes, "nodes", id); err != nil {
		return DeviceRemovalPlan{}, err
	}
	credentialSequence, err := clientSequenceAt(root, "credentials")
	if err != nil {
		return DeviceRemovalPlan{}, err
	}
	removed := 0
	kept := credentialSequence.Content[:0]
	for index, item := range credentialSequence.Content {
		itemID, err := mappingID(item, "credentials", index)
		if err != nil {
			return DeviceRemovalPlan{}, err
		}
		if removeCredentials[itemID] {
			removed++
			continue
		}
		kept = append(kept, item)
	}
	credentialSequence.Content = kept
	if removed != len(removeCredentials) {
		return DeviceRemovalPlan{}, fmt.Errorf("Device %q credential removal matched %d entries, want %d", id, removed, len(removeCredentials))
	}

	result, err := encodeAndValidate(doc)
	if err != nil {
		return DeviceRemovalPlan{}, err
	}
	return DeviceRemovalPlan{Content: result, CredentialIDs: credentialIDs, SecretRefs: secretRefs}, nil
}

func removableAccessDevice(content []byte, id string, requireDecommission bool) (*model.SSOT, *model.Node, error) {
	id = strings.TrimSpace(id)
	if !model.ValidNodeID(id) {
		return nil, nil, fmt.Errorf("Device id %q is invalid", id)
	}
	current, err := model.Load(content)
	if err != nil {
		return nil, nil, fmt.Errorf("load current SSOT: %w", err)
	}
	if findings := validate.Validate(current); len(findings) > 0 {
		return nil, nil, &ValidationError{Findings: findings}
	}
	node := current.NodeByID()[id]
	if node == nil {
		return nil, nil, fmt.Errorf("Device %q does not exist in SSOT", id)
	}
	if node.Access == nil || node.Server != nil {
		return nil, nil, fmt.Errorf("Device %q is not access-only; server retirement requires explicit policy and tunnel migration", id)
	}
	for _, tunnel := range current.Tunnels {
		if tunnel.From == id || tunnel.To == id {
			return nil, nil, fmt.Errorf("Device %q still has tunnel %s; access-only cleanup refuses topology changes", id, tunnel.Pair())
		}
	}
	if requireDecommission && !node.Decommission {
		return nil, nil, errors.New("Device must consume a signed decommission snapshot before removal")
	}
	return current, node, nil
}

func validateGeneratedAccessShape(current *model.SSOT, node *model.Node) error {
	grants := make([]string, 0, len(node.Access.Credentials))
	credentials := current.CredentialByID()
	for _, id := range node.Access.Credentials {
		credential := credentials[id]
		if credential == nil {
			return fmt.Errorf("Device %q references missing credential %q", node.ID, id)
		}
		grants = append(grants, credential.Declaration)
	}
	sort.Strings(grants)
	return ValidateAccessClientShape(current, node, ClientInput{
		ID: node.ID, Name: node.Name, Platform: node.Access.Platform, DestinationGrants: grants,
	})
}

func uniqueMappingByID(sequence *yaml.Node, label, id string) (*yaml.Node, error) {
	var match *yaml.Node
	for index, item := range sequence.Content {
		itemID, err := mappingID(item, label, index)
		if err != nil {
			return nil, err
		}
		if itemID != id {
			continue
		}
		if match != nil {
			return nil, fmt.Errorf("%s contains duplicate id %q", label, id)
		}
		match = item
	}
	if match == nil {
		return nil, fmt.Errorf("%s id %q does not exist", label, id)
	}
	return match, nil
}

func removeUniqueMappingByID(sequence *yaml.Node, label, id string) error {
	match := -1
	for index, item := range sequence.Content {
		itemID, err := mappingID(item, label, index)
		if err != nil {
			return err
		}
		if itemID != id {
			continue
		}
		if match >= 0 {
			return fmt.Errorf("%s contains duplicate id %q", label, id)
		}
		match = index
	}
	if match < 0 {
		return fmt.Errorf("%s id %q does not exist", label, id)
	}
	sequence.Content = append(sequence.Content[:match], sequence.Content[match+1:]...)
	return nil
}

func mappingID(item *yaml.Node, label string, index int) (string, error) {
	if item.Kind != yaml.MappingNode {
		return "", fmt.Errorf("%s[%d] must be a mapping", label, index)
	}
	id := mappingValue(item, "id")
	if id == nil || id.Kind != yaml.ScalarNode || strings.TrimSpace(id.Value) == "" {
		return "", fmt.Errorf("%s[%d] must have a scalar id", label, index)
	}
	return id.Value, nil
}

func sameDocument(a, b []byte) bool { return bytes.Equal(a, b) }

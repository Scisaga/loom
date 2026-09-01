package ssotedit

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"

	"loom/internal/model"
	"loom/internal/validate"
)

// ClientInput 是一次纯接入节点声明的完整可写输入。平台来自已安装客户端，
// 不是管理 UI 的人工选项；v1 只交付 linux-server。
type ClientInput struct {
	ID, Name string
	Platform model.Platform
	// DestinationGrants is the immutable ProfileVersion expansion. Nil keeps
	// the historical all-from_request shape only for validating already-managed
	// legacy clients; new Enrollment must always pass an explicit non-empty set.
	DestinationGrants []string
}

// ClientPlan 描述将写入 SSOT 的纯声明结果。秘密值不属于这个包；调用方必须
// 先按 CredentialRefs 生成并预置秘密层，再提交 Content（§12.1、§18）。
type ClientPlan struct {
	Content            []byte
	CredentialIDs      []string
	CredentialRefs     []string
	DefaultDeclaration string
}

type clientShape struct {
	declarationIDs     []string
	credentialIDs      []string
	credentialRefs     []string
	defaultDeclaration string
	mixedPorts         []model.MixedPort
}

// AddAccessClient 为一台 Device 生成完整且可发布的 SSOT 候选，但不修改输入或
// 外部文件。新 Enrollment 只为 ProfileVersion 明确展开的 DestinationGrants
// 生成独立凭据；nil grants 仅用于验证旧客户端的历史全量形状。
func AddAccessClient(content []byte, input ClientInput) (ClientPlan, error) {
	return addAccessClient(content, input, false)
}

// AddAccessRole attaches the same generated use_loom role to a Device that was
// already added as a server by enrollplan. It preserves the server block and
// remains one in-memory SSOT transaction in the caller before any commit.
func AddAccessRole(content []byte, input ClientInput) (ClientPlan, error) {
	return addAccessClient(content, input, true)
}

func addAccessClient(content []byte, input ClientInput, attach bool) (ClientPlan, error) {
	input.ID = strings.TrimSpace(input.ID)
	input.Name = strings.TrimSpace(input.Name)
	if !model.ValidNodeID(input.ID) {
		return ClientPlan{}, fmt.Errorf("client node id %q is invalid", input.ID)
	}
	if input.Platform != model.LinuxServer {
		return ClientPlan{}, fmt.Errorf("client platform %q is not delivered; v1 only supports linux-server", input.Platform)
	}

	current, err := model.Load(content)
	if err != nil {
		return ClientPlan{}, fmt.Errorf("load current SSOT: %w", err)
	}
	if findings := validate.Validate(current); len(findings) > 0 {
		return ClientPlan{}, &ValidationError{Findings: findings}
	}
	existingNode := current.NodeByID()[input.ID]
	if attach {
		if existingNode == nil || existingNode.Access != nil || existingNode.Server == nil {
			return ClientPlan{}, fmt.Errorf("node id %q is not an access-free server Device", input.ID)
		}
	} else if existingNode != nil {
		return ClientPlan{}, fmt.Errorf("node id %q already exists in SSOT", input.ID)
	}

	shape, err := expectedClientShape(current, input)
	if err != nil {
		return ClientPlan{}, err
	}

	existingCredentials := current.CredentialByID()
	usedRefs := make(map[string]string, len(current.Credentials)*2)
	for i := range current.Credentials {
		credential := &current.Credentials[i]
		for _, ref := range []string{credential.Ref(), credential.PrevRef()} {
			if ref != "" {
				usedRefs[ref] = credential.ID
			}
		}
	}
	for i, id := range shape.credentialIDs {
		if existingCredentials[id] != nil {
			return ClientPlan{}, fmt.Errorf("generated credential id %q already exists", id)
		}
		if owner := usedRefs[shape.credentialRefs[i]]; owner != "" {
			return ClientPlan{}, fmt.Errorf("generated credential secret_ref %q conflicts with current or previous ref of credential %q", shape.credentialRefs[i], owner)
		}
	}

	doc, root, err := parseDocument(content)
	if err != nil {
		return ClientPlan{}, err
	}
	nodes, err := clientSequenceAt(root, "nodes")
	if err != nil {
		return ClientPlan{}, err
	}
	credentials, err := clientSequenceAt(root, "credentials")
	if err != nil {
		return ClientPlan{}, err
	}

	var node *yaml.Node
	if attach {
		for _, item := range nodes.Content {
			if item.Kind == yaml.MappingNode {
				id := mappingValue(item, "id")
				if id != nil && id.Kind == yaml.ScalarNode && id.Value == input.ID {
					node = item
					break
				}
			}
		}
		if node == nil {
			return ClientPlan{}, fmt.Errorf("node id %q disappeared while attaching access role", input.ID)
		}
	} else {
		node = &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
		appendMappingValue(node, "id", scalarNode(input.ID))
		if input.Name != "" {
			appendMappingValue(node, "name", scalarNode(input.Name))
		}
	}
	access := &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
	appendMappingValue(access, "platform", scalarNode(string(input.Platform)))
	setMappingSequence(access, "credentials", shape.credentialIDs)
	if shape.defaultDeclaration != "" {
		appendMappingValue(access, "default_declaration", scalarNode(shape.defaultDeclaration))
	}
	mixed := &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq"}
	for _, port := range shape.mixedPorts {
		mixed.Content = append(mixed.Content, clientMixedPort(port.Port, port.Declaration, port.Services))
	}
	appendMappingValue(access, "mixed_ports", mixed)
	appendMappingValue(node, "access", access)
	if !attach {
		nodes.Content = append(nodes.Content, node)
	}

	for i, declarationID := range shape.declarationIDs {
		credential := &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
		appendMappingValue(credential, "id", scalarNode(shape.credentialIDs[i]))
		appendMappingValue(credential, "owner", scalarNode(input.ID))
		appendMappingValue(credential, "declaration", scalarNode(declarationID))
		appendMappingValue(credential, "secret_ref", scalarNode(shape.credentialRefs[i]))
		credentials.Content = append(credentials.Content, credential)
	}

	result, err := encodeAndValidate(doc)
	if err != nil {
		return ClientPlan{}, err
	}
	edited, err := model.Load(result)
	if err != nil {
		return ClientPlan{}, fmt.Errorf("load edited SSOT: %w", err)
	}
	if findings := validate.Validate(edited); len(findings) > 0 {
		return ClientPlan{}, &ValidationError{Findings: findings}
	}
	return ClientPlan{
		Content: result, CredentialIDs: shape.credentialIDs, CredentialRefs: shape.credentialRefs,
		DefaultDeclaration: shape.defaultDeclaration,
	}, nil
}

// ValidateAccessClientShape checks that an already-present client is exactly
// the authorization shape AddAccessClient would generate from the current
// declarations and Services surface. It is pure so provisioning replays can
// reject partial or broadened nodes before reading or returning secrets.
func ValidateAccessClientShape(s *model.SSOT, node *model.Node, input ClientInput) error {
	if s == nil || node == nil || node.Access == nil {
		return errors.New("client access shape is missing")
	}
	shape, err := expectedClientShape(s, input)
	if err != nil {
		return err
	}
	if len(node.Access.Credentials) != len(shape.credentialIDs) {
		return fmt.Errorf("client %q has %d credentials, want exactly %d", input.ID, len(node.Access.Credentials), len(shape.credentialIDs))
	}
	listed := make(map[string]bool, len(node.Access.Credentials))
	for _, id := range node.Access.Credentials {
		if listed[id] {
			return fmt.Errorf("client %q lists credential %q more than once", input.ID, id)
		}
		listed[id] = true
	}
	credentials := s.CredentialByID()
	for i, id := range shape.credentialIDs {
		if !listed[id] {
			return fmt.Errorf("client %q is missing generated credential %q", input.ID, id)
		}
		credential := credentials[id]
		if credential == nil {
			return fmt.Errorf("client %q references missing generated credential %q", input.ID, id)
		}
		if credential.Owner != input.ID || credential.Declaration != shape.declarationIDs[i] ||
			credential.Ref() != shape.credentialRefs[i] || credential.PrevRef() != "" ||
			credential.AcceptPrevious || credential.ExpiresAt != "" || credential.RevokedAt != "" {
			return fmt.Errorf("client %q credential %q does not match generated owner/declaration/ref shape", input.ID, id)
		}
	}
	for i := range s.Credentials {
		credential := &s.Credentials[i]
		if credential.Owner == input.ID && !listed[credential.ID] {
			return fmt.Errorf("client %q has extra credential %q outside its generated access list", input.ID, credential.ID)
		}
	}
	if node.Access.DefaultDeclaration != shape.defaultDeclaration {
		return fmt.Errorf("client %q default_declaration is %q, want %q", input.ID, node.Access.DefaultDeclaration, shape.defaultDeclaration)
	}
	if len(node.Access.MixedPorts) != len(shape.mixedPorts) {
		return fmt.Errorf("client %q has %d mixed ports, want exactly %d", input.ID, len(node.Access.MixedPorts), len(shape.mixedPorts))
	}
	for i := range shape.mixedPorts {
		if node.Access.MixedPorts[i] != shape.mixedPorts[i] {
			return fmt.Errorf("client %q mixed port %d does not match generated shape", input.ID, i)
		}
	}
	return nil
}

func expectedClientShape(s *model.SSOT, input ClientInput) (clientShape, error) {
	var zero clientShape
	if s == nil {
		return zero, errors.New("SSOT is missing")
	}
	if !model.ValidNodeID(input.ID) {
		return zero, fmt.Errorf("client node id %q is invalid", input.ID)
	}
	if input.Platform != model.LinuxServer {
		return zero, fmt.Errorf("client platform %q is not delivered; v1 only supports linux-server", input.Platform)
	}
	declarationIDs := append([]string(nil), input.DestinationGrants...)
	if input.DestinationGrants == nil {
		declarationIDs = declarationIDs[:0]
		for i := range s.Declarations {
			if s.Declarations[i].AddressFromRequest() {
				declarationIDs = append(declarationIDs, s.Declarations[i].ID)
			}
		}
	}
	sort.Strings(declarationIDs)
	if len(declarationIDs) == 0 {
		return zero, errors.New("client profile grants no from_request access declaration")
	}
	declarations := s.DeclarationByID()
	for i, declarationID := range declarationIDs {
		if i > 0 && declarationID == declarationIDs[i-1] {
			return zero, fmt.Errorf("client profile repeats destination grant %q", declarationID)
		}
		declaration := declarations[declarationID]
		if declaration == nil || !declaration.AddressFromRequest() {
			return zero, fmt.Errorf("client profile destination grant %q is not a current from_request declaration", declarationID)
		}
	}
	shape := clientShape{declarationIDs: declarationIDs}
	for i, declarationID := range declarationIDs {
		shape.credentialIDs = append(shape.credentialIDs, clientCredentialID(input.ID, declarationID))
		shape.credentialRefs = append(shape.credentialRefs, "cred/"+input.ID+"/"+declarationID)
		if len(s.Services) == 0 {
			shape.mixedPorts = append(shape.mixedPorts, model.MixedPort{Port: 1080 + i, Declaration: declarationID})
		}
	}
	if len(s.Services) > 0 {
		shape.defaultDeclaration = automaticDefault(s, declarationIDs)
		shape.mixedPorts = []model.MixedPort{{Port: 1080, Services: true}}
	}
	return shape, nil
}

func clientMixedPort(port int, declaration string, services bool) *yaml.Node {
	mixedPort := &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
	appendMappingValue(mixedPort, "port", &yaml.Node{
		Kind: yaml.ScalarNode, Tag: "!!int", Value: fmt.Sprintf("%d", port),
	})
	if services {
		appendMappingValue(mixedPort, "services", &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!bool", Value: "true"})
	} else {
		appendMappingValue(mixedPort, "declaration", scalarNode(declaration))
	}
	return mixedPort
}

func automaticDefault(s *model.SSOT, granted []string) string {
	allowed := make(map[string]bool, len(granted))
	for _, id := range granted {
		allowed[id] = true
	}
	var matches []string
	for i := range s.Declarations {
		d := &s.Declarations[i]
		if !allowed[d.ID] || !d.AddressFromRequest() || d.EgressAxis != model.EgressAny {
			continue
		}
		matches = append(matches, d.ID)
	}
	sort.Strings(matches)
	if len(matches) == 1 {
		return matches[0]
	}
	return ""
}

func clientCredentialID(nodeID, declarationID string) string {
	base := "cred-" + nodeID + "-" + declarationID
	if len(base) <= 96 {
		return base
	}
	sum := sha256.Sum256([]byte(base))
	return base[:79] + "-" + hex.EncodeToString(sum[:8])
}

func clientSequenceAt(root *yaml.Node, key string) (*yaml.Node, error) {
	value := mappingValue(root, key)
	if value == nil {
		value = &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq"}
		appendMappingValue(root, key, value)
	}
	if value.Kind == yaml.ScalarNode && value.Tag == "!!null" {
		value.Kind, value.Tag, value.Value, value.Content = yaml.SequenceNode, "!!seq", "", nil
	}
	if value.Kind != yaml.SequenceNode {
		return nil, fmt.Errorf("SSOT %s must be a sequence", key)
	}
	return value, nil
}

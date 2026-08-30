package ssotedit

import (
	"errors"
	"fmt"
	"strings"

	"gopkg.in/yaml.v3"
)

// SetAccessDefaultDeclaration 更新一个接入节点的设备默认出口。declaration 为空
// 表示显式选择 fail closed；编辑只触碰 access.default_declaration，并继续通过
// 完整 SSOT 校验，避免设备偏好成为绕过 §12 唯一期望态的旁路。
func SetAccessDefaultDeclaration(content []byte, nodeID, declaration string) ([]byte, error) {
	nodeID = strings.TrimSpace(nodeID)
	declaration = strings.TrimSpace(declaration)
	if nodeID == "" {
		return nil, errors.New("node id is required")
	}

	doc, root, err := parseDocument(content)
	if err != nil {
		return nil, err
	}
	nodes, err := mappingSequence(root, "nodes")
	if err != nil {
		return nil, err
	}

	var access *yaml.Node
	for i, item := range nodes.Content {
		if item.Kind != yaml.MappingNode {
			return nil, fmt.Errorf("nodes[%d] must be a mapping", i)
		}
		if mappingScalar(item, "id") != nodeID {
			continue
		}
		if access != nil {
			return nil, fmt.Errorf("nodes contains duplicate id %q", nodeID)
		}
		access = mappingValue(item, "access")
		if access == nil {
			return nil, fmt.Errorf("node %q is not an access node", nodeID)
		}
		if access.Kind != yaml.MappingNode {
			return nil, fmt.Errorf("node %q access must be a mapping", nodeID)
		}
	}
	if access == nil {
		return nil, fmt.Errorf("access node %q does not exist", nodeID)
	}

	if declaration == "" {
		removeMappingValue(access, "default_declaration")
	} else {
		setMappingScalar(access, "default_declaration", declaration)
	}
	return encodeAndValidate(doc)
}

func mappingSequence(root *yaml.Node, key string) (*yaml.Node, error) {
	value := mappingValue(root, key)
	if value == nil {
		return nil, fmt.Errorf("SSOT %s must be a sequence", key)
	}
	if value.Kind != yaml.SequenceNode {
		return nil, fmt.Errorf("SSOT %s must be a sequence", key)
	}
	return value, nil
}

func mappingValue(mapping *yaml.Node, key string) *yaml.Node {
	if mapping == nil || mapping.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i < len(mapping.Content); i += 2 {
		if mapping.Content[i].Value == key {
			return mapping.Content[i+1]
		}
	}
	return nil
}

func mappingScalar(mapping *yaml.Node, key string) string {
	value := mappingValue(mapping, key)
	if value == nil || value.Kind != yaml.ScalarNode {
		return ""
	}
	return value.Value
}

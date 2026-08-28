// Package ssotedit provides small, structure-aware edits to an SSOT document.
//
// The editor deliberately works on yaml.Node instead of round-tripping through
// model.SSOT.  A model round-trip would reorder the document and discard comments
// whenever the control UI changes one service.  The edited result is still loaded
// and validated through the normal model boundary before it is returned.
package ssotedit

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"strings"

	"gopkg.in/yaml.v3"

	"loom/internal/model"
	"loom/internal/validate"
)

// ServiceInput is the complete editable shape of a service.  Name is optional;
// all other fields are required.
type ServiceInput struct {
	ID          string
	Name        string
	Addresses   []string
	Declaration string
}

// ValidationError reports findings from validating the complete edited SSOT.
// Callers may use errors.As to render individual findings in a UI.
type ValidationError struct {
	Findings []validate.Finding
}

func (e *ValidationError) Error() string {
	if e == nil || len(e.Findings) == 0 {
		return "SSOT validation failed"
	}
	parts := make([]string, len(e.Findings))
	for i := range e.Findings {
		parts[i] = e.Findings[i].String()
	}
	return "SSOT validation failed: " + strings.Join(parts, "; ")
}

// UpsertService replaces the service with input.ID in place, or appends it to
// the services sequence when it does not yet exist.  It leaves all unrelated
// YAML nodes, comments and mapping order intact.
func UpsertService(content []byte, input ServiceInput) ([]byte, error) {
	if err := validateInput(input); err != nil {
		return nil, err
	}

	doc, root, err := parseDocument(content)
	if err != nil {
		return nil, err
	}
	services, err := servicesSequence(root, true)
	if err != nil {
		return nil, err
	}

	match := -1
	for i, item := range services.Content {
		id, err := serviceID(item, i)
		if err != nil {
			return nil, err
		}
		if id == input.ID {
			if match >= 0 {
				return nil, fmt.Errorf("services contains duplicate id %q", input.ID)
			}
			match = i
		}
	}

	if match >= 0 {
		updateServiceNode(services.Content[match], input)
	} else {
		services.Content = append(services.Content, newServiceNode(input))
	}

	return encodeAndValidate(doc)
}

// DeleteService removes the service with id while preserving the order of all
// remaining services.  Deleting an absent or ambiguous id is an error.
func DeleteService(content []byte, id string) ([]byte, error) {
	if strings.TrimSpace(id) == "" {
		return nil, errors.New("service id is required")
	}

	doc, root, err := parseDocument(content)
	if err != nil {
		return nil, err
	}
	services, err := servicesSequence(root, false)
	if err != nil {
		return nil, err
	}
	if services == nil {
		return nil, fmt.Errorf("service %q does not exist", id)
	}

	match := -1
	for i, item := range services.Content {
		itemID, err := serviceID(item, i)
		if err != nil {
			return nil, err
		}
		if itemID == id {
			if match >= 0 {
				return nil, fmt.Errorf("services contains duplicate id %q", id)
			}
			match = i
		}
	}
	if match < 0 {
		return nil, fmt.Errorf("service %q does not exist", id)
	}

	services.Content = append(services.Content[:match], services.Content[match+1:]...)
	return encodeAndValidate(doc)
}

func validateInput(input ServiceInput) error {
	switch {
	case strings.TrimSpace(input.ID) == "":
		return errors.New("service id is required")
	case len(input.Addresses) == 0:
		return errors.New("at least one service address is required")
	case strings.TrimSpace(input.Declaration) == "":
		return errors.New("service declaration is required")
	}
	for i, address := range input.Addresses {
		if strings.TrimSpace(address) == "" {
			return fmt.Errorf("service address %d is empty", i+1)
		}
	}
	return nil
}

func parseDocument(content []byte) (*yaml.Node, *yaml.Node, error) {
	dec := yaml.NewDecoder(bytes.NewReader(content))
	var doc yaml.Node
	if err := dec.Decode(&doc); err != nil {
		return nil, nil, fmt.Errorf("parse SSOT YAML: %w", err)
	}
	if len(doc.Content) != 1 || doc.Content[0].Kind != yaml.MappingNode {
		return nil, nil, errors.New("SSOT YAML root must be a mapping")
	}

	var extra yaml.Node
	if err := dec.Decode(&extra); err != io.EOF {
		if err == nil {
			return nil, nil, errors.New("SSOT YAML must contain exactly one document")
		}
		return nil, nil, fmt.Errorf("parse trailing SSOT YAML: %w", err)
	}
	return &doc, doc.Content[0], nil
}

func servicesSequence(root *yaml.Node, create bool) (*yaml.Node, error) {
	for i := 0; i < len(root.Content); i += 2 {
		if root.Content[i].Value != "services" {
			continue
		}
		value := root.Content[i+1]
		if value.Kind == yaml.ScalarNode && value.Tag == "!!null" && create {
			value.Kind = yaml.SequenceNode
			value.Tag = "!!seq"
			value.Value = ""
			value.Content = nil
		}
		if value.Kind != yaml.SequenceNode {
			return nil, errors.New("SSOT services must be a sequence")
		}
		return value, nil
	}
	if !create {
		return nil, nil
	}
	key := scalarNode("services")
	key.Tag = "!!str"
	seq := &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq"}
	root.Content = append(root.Content, key, seq)
	return seq, nil
}

func serviceID(item *yaml.Node, index int) (string, error) {
	if item.Kind != yaml.MappingNode {
		return "", fmt.Errorf("services[%d] must be a mapping", index)
	}
	for i := 0; i < len(item.Content); i += 2 {
		if item.Content[i].Value == "id" {
			return item.Content[i+1].Value, nil
		}
	}
	return "", nil
}

func updateServiceNode(item *yaml.Node, input ServiceInput) {
	setMappingScalar(item, "id", input.ID)
	if input.Name == "" {
		removeMappingValue(item, "name")
	} else {
		setMappingScalar(item, "name", input.Name)
	}
	setMappingSequence(item, "addresses", input.Addresses)
	setMappingScalar(item, "declaration", input.Declaration)
}

func newServiceNode(input ServiceInput) *yaml.Node {
	item := &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
	appendMappingValue(item, "id", scalarNode(input.ID))
	if input.Name != "" {
		appendMappingValue(item, "name", scalarNode(input.Name))
	}
	appendMappingValue(item, "addresses", stringSequence(input.Addresses))
	appendMappingValue(item, "declaration", scalarNode(input.Declaration))
	return item
}

func setMappingScalar(mapping *yaml.Node, key, value string) {
	setMappingValue(mapping, key, scalarNode(value))
}

func setMappingSequence(mapping *yaml.Node, key string, values []string) {
	sequence := stringSequence(values)
	for i := 0; i < len(mapping.Content); i += 2 {
		if mapping.Content[i].Value != key {
			continue
		}
		old := mapping.Content[i+1]
		if old.Kind != yaml.SequenceNode {
			break
		}

		// Reuse each matching scalar at most once. Besides avoiding needless
		// yaml.Node churn, this keeps comments attached to an unchanged address
		// even when another address is inserted, removed or reordered.
		byValue := make(map[string][]*yaml.Node, len(old.Content))
		for _, child := range old.Content {
			if child.Kind == yaml.ScalarNode {
				byValue[child.Value] = append(byValue[child.Value], child)
			}
		}
		for j, child := range sequence.Content {
			matches := byValue[child.Value]
			if len(matches) == 0 {
				continue
			}
			sequence.Content[j] = matches[0]
			byValue[child.Value] = matches[1:]
		}
		break
	}
	setMappingValue(mapping, key, sequence)
}

func setMappingValue(mapping *yaml.Node, key string, value *yaml.Node) {
	for i := 0; i < len(mapping.Content); i += 2 {
		if mapping.Content[i].Value != key {
			continue
		}
		old := mapping.Content[i+1]
		value.HeadComment = old.HeadComment
		value.LineComment = old.LineComment
		value.FootComment = old.FootComment
		// Keeping flow style avoids a large formatting-only diff for existing
		// inline service definitions.
		if old.Style&yaml.FlowStyle != 0 {
			value.Style |= yaml.FlowStyle
		}
		mapping.Content[i+1] = value
		return
	}
	appendMappingValue(mapping, key, value)
}

func appendMappingValue(mapping *yaml.Node, key string, value *yaml.Node) {
	k := scalarNode(key)
	k.Tag = "!!str"
	mapping.Content = append(mapping.Content, k, value)
}

func removeMappingValue(mapping *yaml.Node, key string) {
	for i := 0; i < len(mapping.Content); i += 2 {
		if mapping.Content[i].Value == key {
			mapping.Content = append(mapping.Content[:i], mapping.Content[i+2:]...)
			return
		}
	}
}

func scalarNode(value string) *yaml.Node {
	return &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: value}
}

func stringSequence(values []string) *yaml.Node {
	seq := &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq"}
	for _, value := range values {
		seq.Content = append(seq.Content, scalarNode(value))
	}
	return seq
}

func encodeAndValidate(doc *yaml.Node) ([]byte, error) {
	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(doc); err != nil {
		return nil, fmt.Errorf("encode SSOT YAML: %w", err)
	}
	if err := enc.Close(); err != nil {
		return nil, fmt.Errorf("finish SSOT YAML: %w", err)
	}

	result := buf.Bytes()
	ssot, err := model.Load(result)
	if err != nil {
		return nil, fmt.Errorf("load edited SSOT: %w", err)
	}
	if findings := validate.Validate(ssot); len(findings) > 0 {
		return nil, &ValidationError{Findings: findings}
	}
	if len(result) == 0 || result[len(result)-1] != '\n' {
		result = append(result, '\n')
	}
	return result, nil
}

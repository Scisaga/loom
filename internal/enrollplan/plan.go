// Package enrollplan builds and applies the declarative part of enrolling a
// server node. It deliberately has no SSH or filesystem side effects: callers
// can preview the complete node/tunnel transaction before deciding how and
// where to persist it.
package enrollplan

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"

	"loom/internal/model"
	"loom/internal/validate"
)

const defaultInboundPort = 61698

// NodeInput is the operator/discovery result used to create one server node.
// EgressCapable is a pointer so an omitted value can safely default to true
// while an explicit false remains representable.
type NodeInput struct {
	ID             string
	Name           string
	Country        string
	City           string
	Provider       string
	PublicEndpoint string
	SSHPort        int
	Direction      model.Direction
	WGPublicKey    string
	EgressCapable  *bool
}

// Plan is the complete SSOT change produced by Preview. Tunnels contains every
// persistent tunnel required between Node and the nodes already in the SSOT.
// FixedPolicy 是出口能力的声明式配套项；凭据值属于秘密层，不能由纯 SSOT
// 规划器伪造，须在安全分发后才会成为接入节点的可选项。
type Plan struct {
	Node        model.Node
	Tunnels     []model.Tunnel
	FixedPolicy *model.AccessDeclaration
}

// ValidationError reports findings from validating the complete current or
// proposed SSOT. Callers can use errors.As to present the individual findings.
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

// Preview parses and validates the current SSOT, then returns the exact node
// and tunnel declarations that an Apply would append. It never changes the
// input bytes or any external state.
func Preview(content []byte, input NodeInput) (Plan, error) {
	node, err := nodeFromInput(input)
	if err != nil {
		return Plan{}, err
	}

	ssot, err := model.Load(content)
	if err != nil {
		return Plan{}, fmt.Errorf("load current SSOT: %w", err)
	}
	if findings := validate.Validate(ssot); len(findings) > 0 {
		return Plan{}, &ValidationError{Findings: findings}
	}
	if ssot.NodeByID()[node.ID] != nil {
		return Plan{}, fmt.Errorf("node id %q already exists in SSOT", node.ID)
	}

	plan, err := allocate(ssot, node)
	if err != nil {
		return Plan{}, err
	}

	// A preview must itself be publishable. This catches not only allocation
	// conflicts, but also interactions with declarations and service policy in
	// unrelated portions of the complete SSOT.
	candidate := *ssot
	candidate.Nodes = append([]model.Node(nil), ssot.Nodes...)
	candidate.Nodes = append(candidate.Nodes, plan.Node)
	candidate.Tunnels = append(append([]model.Tunnel(nil), ssot.Tunnels...), plan.Tunnels...)
	if plan.FixedPolicy != nil {
		candidate.Declarations = append(append([]model.AccessDeclaration(nil), ssot.Declarations...), *plan.FixedPolicy)
	}
	if findings := validate.Validate(&candidate); len(findings) > 0 {
		return Plan{}, &ValidationError{Findings: findings}
	}
	return plan, nil
}

// Apply appends the previewed node and tunnels to their existing YAML
// sequences. It preserves unrelated yaml.Node values, mapping order and
// comments, then loads and validates the complete encoded SSOT once more.
// On every error it returns a nil output.
func Apply(content []byte, input NodeInput) ([]byte, error) {
	plan, err := Preview(content, input)
	if err != nil {
		return nil, err
	}

	doc, root, err := parseDocument(content)
	if err != nil {
		return nil, err
	}
	nodes, err := sequenceAt(root, "nodes", true)
	if err != nil {
		return nil, err
	}
	tunnels, err := sequenceAt(root, "tunnels", true)
	if err != nil {
		return nil, err
	}

	nodes.Content = append(nodes.Content, nodeYAML(plan.Node))
	for _, tunnel := range plan.Tunnels {
		tunnels.Content = append(tunnels.Content, tunnelYAML(tunnel))
	}
	if plan.FixedPolicy != nil {
		declarations, err := sequenceAt(root, "declarations", true)
		if err != nil {
			return nil, err
		}
		declarations.Content = append(declarations.Content, declarationYAML(*plan.FixedPolicy))
	}

	result, err := encodeDocument(doc)
	if err != nil {
		return nil, err
	}
	edited, err := model.Load(result)
	if err != nil {
		return nil, fmt.Errorf("load edited SSOT: %w", err)
	}
	if findings := validate.Validate(edited); len(findings) > 0 {
		return nil, &ValidationError{Findings: findings}
	}
	return result, nil
}

func nodeFromInput(input NodeInput) (model.Node, error) {
	if !model.ValidNodeID(input.ID) {
		return model.Node{}, fmt.Errorf("node id %q is invalid: use 1-63 lowercase ASCII letters, digits, or internal hyphens", input.ID)
	}
	if !input.Direction.Valid() {
		return model.Node{}, fmt.Errorf("direction %q is invalid: use bidirectional, reverse_only, or direct_only", input.Direction)
	}
	if err := validateWGPublicKey(input.WGPublicKey); err != nil {
		return model.Node{}, err
	}
	endpoint := strings.TrimSpace(input.PublicEndpoint)
	if endpoint == "" {
		return model.Node{}, errors.New("现有 SSOT schema 要求 endpoint，控制面尚未完成独立 endpoint discovery")
	}
	if input.SSHPort < 0 || input.SSHPort > 65535 {
		return model.Node{}, fmt.Errorf("SSH port %d is outside 1-65535 (or 0 for the default 22)", input.SSHPort)
	}
	country := strings.ToUpper(strings.TrimSpace(input.Country))
	if country != "" && !model.ValidCountryCode(country) {
		return model.Node{}, fmt.Errorf("country %q is invalid: use a two-letter ISO 3166-1 alpha-2 code", input.Country)
	}

	egress := true
	if input.EgressCapable != nil {
		egress = *input.EgressCapable
	}
	return model.Node{
		ID:             input.ID,
		Name:           strings.TrimSpace(input.Name),
		Country:        country,
		City:           strings.TrimSpace(input.City),
		Provider:       strings.TrimSpace(input.Provider),
		PublicEndpoint: endpoint,
		SSHPort:        input.SSHPort,
		Server: &model.ServerRole{
			Direction:     input.Direction,
			InboundPort:   defaultInboundPort,
			EgressCapable: egress,
			WGPublicKey:   input.WGPublicKey,
		},
	}, nil
}

func validateWGPublicKey(key string) error {
	if len(key) != 44 {
		return fmt.Errorf("WireGuard public key must be canonical base64 for exactly 32 bytes (44 characters), got %d characters", len(key))
	}
	decoded, err := base64.StdEncoding.Strict().DecodeString(key)
	if err != nil || len(decoded) != 32 || base64.StdEncoding.EncodeToString(decoded) != key {
		return errors.New("WireGuard public key must be canonical base64 encoding of exactly 32 bytes")
	}
	return nil
}

func allocate(ssot *model.SSOT, node model.Node) (Plan, error) {
	peers := ssot.TunnelPeersFor(&node)
	work := *ssot
	work.Nodes = append([]model.Node(nil), ssot.Nodes...)
	work.Tunnels = append([]model.Tunnel(nil), ssot.Tunnels...)

	// If the new node accepts a persistent tunnel, its WireGuard listener must
	// not be allocated the same port as its sing-box inbound. AllocateTunnel
	// intentionally sees occupied tunnel ports; this private sentinel extends
	// that occupied set while planning without ever entering the returned plan.
	for _, peer := range peers {
		newInitiates, err := model.ResolveInitiator(node.ID, node.Server.Direction, peer.ID, peer.Server.Direction)
		if err != nil {
			return Plan{}, err
		}
		if !newInitiates {
			work.Tunnels = append(work.Tunnels, model.Tunnel{ListenPort: defaultInboundPort})
			break
		}
	}

	plan := Plan{Node: node}
	for _, peer := range peers {
		fromAddr, toAddr, port, err := work.AllocateTunnel(&node, peer)
		if err != nil {
			return Plan{}, fmt.Errorf("allocate tunnel %s ↔ %s: %w", node.ID, peer.ID, err)
		}
		tunnel := model.Tunnel{
			From:       node.ID,
			To:         peer.ID,
			Protocol:   model.WG,
			ListenPort: port,
			FromAddr:   fromAddr,
			ToAddr:     toAddr,
		}
		plan.Tunnels = append(plan.Tunnels, tunnel)
		// Every subsequent allocation must see earlier planned addresses and
		// ports; otherwise a multi-peer enrollment can allocate duplicates.
		work.Tunnels = append(work.Tunnels, tunnel)
	}
	if node.Server.EgressCapable {
		policy, err := fixedEgressPolicy(ssot, node)
		if err != nil {
			return Plan{}, err
		}
		plan.FixedPolicy = &policy
	}
	return plan, nil
}

func fixedEgressPolicy(ssot *model.SSOT, node model.Node) (model.AccessDeclaration, error) {
	policyID := node.ID + "-fixed"
	if ssot.DeclarationByID()[policyID] != nil {
		return model.AccessDeclaration{}, fmt.Errorf("§4 出口轴：自动生成的固定出口策略 id %q 已存在", policyID)
	}

	var template *model.AccessDeclaration
	for i := range ssot.Declarations {
		declaration := &ssot.Declarations[i]
		if !declaration.AddressFromRequest() || declaration.ProbeURL == "" {
			continue
		}
		if template == nil || (template.PinnedEgress() == "" && declaration.PinnedEgress() != "") {
			template = declaration
		}
	}
	if template == nil {
		return model.AccessDeclaration{}, errors.New("§4.5 服务：无法自动生成固定出口策略，SSOT 中没有带 probe_url 的 from_request 声明可作模板")
	}

	label := node.City
	if label == "" {
		label = node.Name
	}
	if label == "" {
		label = node.ID
	}
	allowed := make([]string, 0, len(ssot.Nodes)+1)
	for i := range ssot.Nodes {
		candidate := &ssot.Nodes[i]
		if !candidate.IsServer() || candidate.Drain || candidate.Decommission || candidate.Server.Direction == model.ReverseOnly {
			continue
		}
		allowed = append(allowed, candidate.ID)
	}
	allowed = append(allowed, node.ID)
	allowed = uniqueSorted(allowed)

	policy := model.AccessDeclaration{
		ID: policyID, Name: "固定" + label + "出口",
		AddressAxis: model.FromRequest, EgressAxis: model.PinnedPrefix + node.ID,
		ProbeURL: template.ProbeURL, ProbeBudget: template.ProbeBudget,
		Objective: model.Latency, AllowedServers: allowed, MaxHops: template.MaxHops,
		TuningPeriod: template.TuningPeriod, SwitchThreshold: template.SwitchThreshold,
		TopN: template.TopN, Window: template.Window, MinSamples: template.MinSamples,
		StaleAfter: template.StaleAfter, Fallback: template.Fallback,
	}
	if policy.MaxHops == 0 {
		policy.MaxHops = 2
	}
	return policy, nil
}

func uniqueSorted(values []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(values))
	for _, value := range values {
		if value != "" && !seen[value] {
			seen[value] = true
			out = append(out, value)
		}
	}
	sort.Strings(out)
	return out
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

func sequenceAt(root *yaml.Node, key string, create bool) (*yaml.Node, error) {
	for i := 0; i < len(root.Content); i += 2 {
		if root.Content[i].Value != key {
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
			return nil, fmt.Errorf("SSOT %s must be a sequence", key)
		}
		return value, nil
	}
	if !create {
		return nil, nil
	}
	keyNode := scalar(key, "!!str")
	seq := &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq"}
	root.Content = append(root.Content, keyNode, seq)
	return seq, nil
}

func nodeYAML(node model.Node) *yaml.Node {
	item := mapping()
	appendValue(item, "id", stringScalar(node.ID))
	for _, field := range []struct {
		key, value string
	}{
		{"name", node.Name},
		{"country", node.Country},
		{"city", node.City},
		{"provider", node.Provider},
		{"public_endpoint", node.PublicEndpoint},
	} {
		if field.value != "" {
			appendValue(item, field.key, stringScalar(field.value))
		}
	}
	if node.SSHPort != 0 {
		appendValue(item, "ssh_port", intScalar(node.SSHPort))
	}
	server := mapping()
	appendValue(server, "direction", stringScalar(string(node.Server.Direction)))
	appendValue(server, "inbound_port", intScalar(node.Server.InboundPort))
	appendValue(server, "egress_capable", boolScalar(node.Server.EgressCapable))
	appendValue(server, "wg_public_key", stringScalar(node.Server.WGPublicKey))
	appendValue(item, "server", server)
	return item
}

func tunnelYAML(tunnel model.Tunnel) *yaml.Node {
	item := mapping()
	appendValue(item, "from", stringScalar(tunnel.From))
	appendValue(item, "to", stringScalar(tunnel.To))
	appendValue(item, "protocol", stringScalar(string(tunnel.Protocol)))
	appendValue(item, "listen_port", intScalar(tunnel.ListenPort))
	appendValue(item, "from_addr", stringScalar(tunnel.FromAddr))
	appendValue(item, "to_addr", stringScalar(tunnel.ToAddr))
	return item
}

func declarationYAML(declaration model.AccessDeclaration) *yaml.Node {
	item := mapping()
	appendValue(item, "id", stringScalar(declaration.ID))
	if declaration.Name != "" {
		appendValue(item, "name", stringScalar(declaration.Name))
	}
	appendValue(item, "address_axis", stringScalar(declaration.AddressAxis))
	appendValue(item, "egress_axis", stringScalar(declaration.EgressAxis))
	appendValue(item, "objective", stringScalar(string(declaration.Objective)))
	appendValue(item, "probe_url", stringScalar(declaration.ProbeURL))
	if declaration.ProbeBudget != 0 {
		appendValue(item, "probe_budget", intScalar(declaration.ProbeBudget))
	}
	allowed := &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq"}
	for _, server := range declaration.AllowedServers {
		allowed.Content = append(allowed.Content, stringScalar(server))
	}
	appendValue(item, "allowed_servers", allowed)
	appendValue(item, "max_hops", intScalar(declaration.MaxHops))
	appendValue(item, "tuning_period", stringScalar(declaration.TuningPeriod))
	appendValue(item, "switch_threshold", floatScalar(declaration.SwitchThreshold))
	if declaration.TopN != 0 {
		appendValue(item, "top_n", intScalar(declaration.TopN))
	}
	if declaration.Window != "" {
		appendValue(item, "window", stringScalar(declaration.Window))
	}
	if declaration.MinSamples != 0 {
		appendValue(item, "min_samples", intScalar(declaration.MinSamples))
	}
	if declaration.StaleAfter != "" {
		appendValue(item, "stale_after", stringScalar(declaration.StaleAfter))
	}
	if declaration.Fallback != "" {
		appendValue(item, "fallback", stringScalar(string(declaration.Fallback)))
	}
	return item
}

func mapping() *yaml.Node {
	return &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
}

func appendValue(mapping *yaml.Node, key string, value *yaml.Node) {
	mapping.Content = append(mapping.Content, scalar(key, "!!str"), value)
}

func stringScalar(value string) *yaml.Node { return scalar(value, "!!str") }
func intScalar(value int) *yaml.Node       { return scalar(strconv.Itoa(value), "!!int") }
func boolScalar(value bool) *yaml.Node     { return scalar(strconv.FormatBool(value), "!!bool") }
func floatScalar(value float64) *yaml.Node {
	return scalar(strconv.FormatFloat(value, 'g', -1, 64), "!!float")
}

func scalar(value, tag string) *yaml.Node {
	return &yaml.Node{Kind: yaml.ScalarNode, Tag: tag, Value: value}
}

func encodeDocument(doc *yaml.Node) ([]byte, error) {
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
	if len(result) == 0 || result[len(result)-1] != '\n' {
		result = append(result, '\n')
	}
	return result, nil
}

package enrollplan

import (
	"bytes"
	"errors"
	"slices"
	"strings"
	"testing"

	"loom/internal/model"
	"loom/internal/validate"
)

const (
	keyZero = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
	keyOne  = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE="
	keyTwo  = "AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI="
)

func TestPreviewAllocatesCompleteConflictFreePlan(t *testing.T) {
	content := fixtureSSOT()
	original := append([]byte(nil), content...)

	plan, err := Preview(content, NodeInput{
		ID:             "edge-b",
		Name:           "Edge B",
		Country:        "jp",
		City:           "Tokyo",
		Provider:       "example",
		PublicEndpoint: "edge-b.example.net",
		SSHPort:        2222,
		Direction:      model.ReverseOnly,
		WGPublicKey:    keyZero,
	})
	if err != nil {
		t.Fatalf("Preview: %v", err)
	}
	if !bytes.Equal(content, original) {
		t.Fatal("Preview mutated its input")
	}
	if !plan.Node.Server.EgressCapable {
		t.Fatal("omitted EgressCapable did not default to true")
	}
	if plan.Node.Server.InboundPort != defaultInboundPort {
		t.Fatalf("inbound port = %d, want %d", plan.Node.Server.InboundPort, defaultInboundPort)
	}
	if len(plan.Tunnels) != 2 {
		t.Fatalf("tunnels = %#v, want one for each bidirectional peer", plan.Tunnels)
	}
	if len(plan.FixedPolicies) != 4 {
		t.Fatalf("fixed policies = %#v, want one per egress-capable node", plan.FixedPolicies)
	}
	if len(plan.ExpandedPolicies) != 1 || plan.ExpandedPolicies[0].ID != "example-policy" ||
		!slices.Equal(plan.ExpandedPolicies[0].AllowedServers, []string{"core-a", "core-b", "edge-a", "edge-b"}) {
		t.Fatalf("expanded policies = %#v, want example-policy to include the new egress", plan.ExpandedPolicies)
	}
	fixedPolicy := planPolicyByID(t, plan, "edge-b-fixed")
	if fixedPolicy.EgressAxis != "pinned:edge-b" || fixedPolicy.Name != "固定Tokyo出口" ||
		fixedPolicy.Objective != model.Latency ||
		!slices.Equal(fixedPolicy.AllowedServers, []string{"core-a", "core-b", "edge-b"}) {
		t.Fatalf("fixed policy = %#v", fixedPolicy)
	}

	seenPorts := map[int]bool{61637: true}
	seenAddrs := map[string]bool{"10.99.0.1/32": true, "10.99.0.2/32": true}
	for _, tunnel := range plan.Tunnels {
		if tunnel.Protocol != model.WG {
			t.Errorf("protocol = %q, want wg", tunnel.Protocol)
		}
		if seenPorts[tunnel.ListenPort] {
			t.Errorf("allocated duplicate port %d", tunnel.ListenPort)
		}
		seenPorts[tunnel.ListenPort] = true
		for _, address := range []string{tunnel.FromAddr, tunnel.ToAddr} {
			if seenAddrs[address] {
				t.Errorf("allocated duplicate address %s", address)
			}
			seenAddrs[address] = true
		}
	}

	result, err := Apply(content, NodeInput{
		ID:             "edge-b",
		Name:           "Edge B",
		Country:        "jp",
		City:           "Tokyo",
		Provider:       "example",
		PublicEndpoint: "edge-b.example.net",
		SSHPort:        2222,
		Direction:      model.ReverseOnly,
		WGPublicKey:    keyZero,
	})
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if !bytes.Contains(result, []byte("allowed_servers: [core-a, core-b, edge-a, edge-b]")) {
		t.Fatalf("automatic pool edit did not preserve the existing YAML sequence style:\n%s", result)
	}
	assertValid(t, result)
	ssot, err := model.Load(result)
	if err != nil {
		t.Fatalf("load result: %v", err)
	}
	got := ssot.NodeByID()["edge-b"]
	if got == nil || got.Name != "Edge B" || got.Country != "JP" || got.City != "Tokyo" ||
		got.Provider != "example" || got.SSHPort != 2222 {
		t.Fatalf("applied node = %#v", got)
	}
	fixed := ssot.DeclarationByID()["edge-b-fixed"]
	if fixed == nil || fixed.PinnedEgress() != "edge-b" {
		t.Fatalf("applied fixed policy = %#v", fixed)
	}
	automatic := ssot.DeclarationByID()["example-policy"]
	if automatic == nil || !slices.Equal(automatic.AllowedServers, []string{"core-a", "core-b", "edge-a", "edge-b"}) {
		t.Fatalf("applied automatic policy = %#v", automatic)
	}
}

func TestPreviewPreservesRestrictedAutomaticPools(t *testing.T) {
	content := bytes.Replace(fixtureSSOT(),
		[]byte("allowed_servers: [core-a, core-b, edge-a]"),
		[]byte("allowed_servers: [core-a, edge-a]"), 1)
	plan, err := Preview(content, NodeInput{
		ID: "edge-b", PublicEndpoint: "edge-b.example.net",
		Direction: model.ReverseOnly, WGPublicKey: keyZero,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.ExpandedPolicies) != 0 {
		t.Fatalf("restricted policy was expanded: %#v", plan.ExpandedPolicies)
	}
	result, err := Apply(content, NodeInput{
		ID: "edge-b", PublicEndpoint: "edge-b.example.net",
		Direction: model.ReverseOnly, WGPublicKey: keyZero,
	})
	if err != nil {
		t.Fatal(err)
	}
	ssot, err := model.Load(result)
	if err != nil {
		t.Fatal(err)
	}
	if got := ssot.DeclarationByID()["example-policy"].AllowedServers; !slices.Equal(got, []string{"core-a", "edge-a"}) {
		t.Fatalf("restricted allowed_servers = %#v", got)
	}
}

func TestPreviewReconcilesByPinnedNodeAndKeepsLegacyPolicyIDs(t *testing.T) {
	content := bytes.Replace(fixtureSSOT(), []byte("declarations:\n"), []byte(`declarations:
  - id: legacy-edge
    address_axis: from_request
    egress_axis: pinned:edge-a
    objective: latency
    probe_url: https://probe.example.net/
    allowed_servers: [core-a, core-b, edge-a]
    max_hops: 2
    tuning_period: 5m
    switch_threshold: 0.2
    window: 1h
    min_samples: 6
    stale_after: 20m
`), 1)
	plan, err := Preview(content, NodeInput{
		ID: "edge-b", City: "Tokyo", PublicEndpoint: "edge-b.example.net",
		Direction: model.ReverseOnly, WGPublicKey: keyZero,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.FixedPolicies) != 3 {
		t.Fatalf("fixed policies = %#v, want missing core-a/core-b/edge-b only", plan.FixedPolicies)
	}
	for _, policy := range plan.FixedPolicies {
		if policy.PinnedEgress() == "edge-a" {
			t.Fatalf("legacy pinned declaration was duplicated: %#v", plan.FixedPolicies)
		}
	}
}

func TestPreviewRecalculatesTunnelsForDirection(t *testing.T) {
	content := fixtureSSOT()
	base := NodeInput{
		ID:             "new-node",
		PublicEndpoint: "new-node.example.net",
		WGPublicKey:    keyZero,
	}

	reverse := base
	reverse.Direction = model.ReverseOnly
	reversePlan, err := Preview(content, reverse)
	if err != nil {
		t.Fatalf("reverse Preview: %v", err)
	}
	if len(reversePlan.Tunnels) != 2 {
		t.Fatalf("reverse_only tunnel count = %d, want 2 bidirectional peers", len(reversePlan.Tunnels))
	}
	for _, tunnel := range reversePlan.Tunnels {
		if tunnel.To == "edge-a" {
			t.Errorf("reverse_only node was incorrectly paired with reverse_only edge-a: %#v", tunnel)
		}
	}

	bidirectional := base
	bidirectional.Direction = model.Bidirectional
	biPlan, err := Preview(content, bidirectional)
	if err != nil {
		t.Fatalf("bidirectional Preview: %v", err)
	}
	if len(biPlan.Tunnels) != 1 || biPlan.Tunnels[0].To != "edge-a" {
		t.Fatalf("bidirectional tunnels = %#v, want only edge-a", biPlan.Tunnels)
	}
	if bytes.Equal(mustPlanBytes(t, reversePlan), mustPlanBytes(t, biPlan)) {
		t.Fatal("changing direction reused a stale tunnel plan")
	}
}

func TestPreviewReservesNewNodeInboundPort(t *testing.T) {
	// sha256(edge-a|n132) maps to 61698 before collision handling. edge-a is
	// reverse_only, so n132 accepts this tunnel and also owns its sing-box
	// inbound on 61698. The planner must make AllocateTunnel choose another
	// available port before the full validator sees the transaction.
	plan, err := Preview(fixtureSSOT(), NodeInput{
		ID:             "n132",
		PublicEndpoint: "n132.example.net",
		Direction:      model.Bidirectional,
		WGPublicKey:    keyZero,
	})
	if err != nil {
		t.Fatalf("Preview: %v", err)
	}
	if len(plan.Tunnels) != 1 {
		t.Fatalf("tunnels = %#v", plan.Tunnels)
	}
	if plan.Tunnels[0].ListenPort == defaultInboundPort {
		t.Fatalf("tunnel reused node inbound port %d", defaultInboundPort)
	}
}

func TestExplicitEgressFalseIsPreserved(t *testing.T) {
	disabled := false
	input := NodeInput{
		ID:             "core-c",
		PublicEndpoint: "core-c.example.net",
		Direction:      model.Bidirectional,
		WGPublicKey:    keyZero,
		EgressCapable:  &disabled,
	}
	plan, err := Preview(fixtureSSOT(), input)
	if err != nil {
		t.Fatalf("Preview: %v", err)
	}
	if plan.Node.Server.EgressCapable {
		t.Fatal("explicit false egress was changed to true")
	}
	if len(plan.ExpandedPolicies) != 0 {
		t.Fatalf("non-egress node expanded automatic pools: %#v", plan.ExpandedPolicies)
	}
	result, err := Apply(fixtureSSOT(), input)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if !bytes.Contains(result, []byte("egress_capable: false")) {
		t.Fatalf("explicit false missing from YAML:\n%s", result)
	}
}

func TestApplyPreservesCommentsAndOtherSections(t *testing.T) {
	result, err := Apply(fixtureSSOT(), NodeInput{
		ID:             "core-c",
		Name:           "Core C",
		PublicEndpoint: "core-c.example.net",
		Direction:      model.Bidirectional,
		WGPublicKey:    keyZero,
	})
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	for _, preserved := range []string{
		"# preserve document comment",
		"# keep the node sequence comment",
		"# keep the existing tunnel comment",
		"# unrelated known top-level section",
		"services:",
		"example-service",
	} {
		if !bytes.Contains(result, []byte(preserved)) {
			t.Errorf("edited YAML lost %q", preserved)
		}
	}
	if nodes, added, tunnels := bytes.Index(result, []byte("nodes:")), bytes.Index(result, []byte("id: core-c")), bytes.Index(result, []byte("tunnels:")); !(nodes < added && added < tunnels) {
		t.Errorf("node was not appended in the existing nodes section: nodes=%d added=%d tunnels=%d", nodes, added, tunnels)
	}
	if tunnel, services := bytes.LastIndex(result, []byte("from: core-c")), bytes.Index(result, []byte("services:")); !(tunnel > 0 && tunnel < services) {
		t.Errorf("tunnel was not appended in the existing tunnels section: tunnel=%d services=%d", tunnel, services)
	}
	assertValid(t, result)
}

func TestInvalidInputAndDuplicateFailWithoutOutput(t *testing.T) {
	content := fixtureSSOT()
	cases := []struct {
		name  string
		input NodeInput
		want  string
	}{
		{
			name:  "invalid id",
			input: NodeInput{ID: "Bad ID", PublicEndpoint: "bad.example.net", Direction: model.Bidirectional, WGPublicKey: keyZero},
			want:  "node id",
		},
		{
			name:  "duplicate id",
			input: NodeInput{ID: "core-a", PublicEndpoint: "duplicate.example.net", Direction: model.Bidirectional, WGPublicKey: keyZero},
			want:  "already exists",
		},
		{
			name:  "invalid direction",
			input: NodeInput{ID: "new-node", PublicEndpoint: "new.example.net", Direction: model.Direction("automatic"), WGPublicKey: keyZero},
			want:  "direction",
		},
		{
			name:  "invalid key",
			input: NodeInput{ID: "new-node", PublicEndpoint: "new.example.net", Direction: model.Bidirectional, WGPublicKey: "not-a-wireguard-key"},
			want:  "WireGuard public key",
		},
		{
			name:  "missing discovered endpoint",
			input: NodeInput{ID: "new-node", Direction: model.ReverseOnly, WGPublicKey: keyZero},
			want:  "endpoint discovery",
		},
		{
			name:  "invalid ssh port",
			input: NodeInput{ID: "new-node", PublicEndpoint: "new.example.net", SSHPort: -1, Direction: model.Bidirectional, WGPublicKey: keyZero},
			want:  "SSH port",
		},
		{
			name:  "invalid country",
			input: NodeInput{ID: "new-node", Country: "HKG", PublicEndpoint: "new.example.net", Direction: model.Bidirectional, WGPublicKey: keyZero},
			want:  "country",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			plan, err := Preview(content, tc.input)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("Preview error = %v, want containing %q", err, tc.want)
			}
			if plan.Node.ID != "" || len(plan.Tunnels) != 0 {
				t.Fatalf("invalid Preview leaked a partial plan: %#v", plan)
			}

			result, err := Apply(content, tc.input)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("Apply error = %v, want containing %q", err, tc.want)
			}
			if result != nil {
				t.Fatalf("invalid Apply returned output:\n%s", result)
			}
		})
	}
}

func TestUnrelatedInvalidSSOTFailsClosed(t *testing.T) {
	content := bytes.Replace(fixtureSSOT(), []byte("agent: 0.1.0"), []byte("agent: latest"), 1)
	input := NodeInput{
		ID:             "new-node",
		PublicEndpoint: "new.example.net",
		Direction:      model.Bidirectional,
		WGPublicKey:    keyZero,
	}
	result, err := Apply(content, input)
	var validationErr *ValidationError
	if !errors.As(err, &validationErr) {
		t.Fatalf("Apply error = %T %v, want ValidationError", err, err)
	}
	if result != nil {
		t.Fatalf("invalid current SSOT returned output:\n%s", result)
	}
}

func fixtureSSOT() []byte {
	return []byte(`# preserve document comment
defaults:
  dns: [192.0.2.53]
  components:
    sing_box: 1.11.4
    wireguard: 1.0.20250521
    agent: 0.1.0

nodes:
  # keep the node sequence comment
  - id: core-a
    public_endpoint: core-a.example.net
    server:
      direction: bidirectional
      inbound_port: 443
      egress_capable: true
      wg_public_key: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
  - id: core-b
    public_endpoint: core-b.example.net
    server:
      direction: bidirectional
      inbound_port: 443
      egress_capable: true
      wg_public_key: AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=
  - id: edge-a
    public_endpoint: edge-a.example.net
    server:
      direction: reverse_only
      inbound_port: 443
      egress_capable: true
      wg_public_key: AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=

tunnels:
  # keep the existing tunnel comment
  - from: core-a
    to: edge-a
    protocol: wg
    listen_port: 61637
    from_addr: 10.99.0.1/32
    to_addr: 10.99.0.2/32

# unrelated known top-level section
services:
  - id: example-service
    addresses: [example.net]
    declaration: example-policy

declarations:
  - id: example-policy
    address_axis: from_request
    egress_axis: any
    objective: latency
    probe_url: https://probe.example.net/
    allowed_servers: [core-a, core-b, edge-a]
    max_hops: 2
    tuning_period: 5m
    switch_threshold: 0.2
    window: 1h
    min_samples: 6
    stale_after: 20m
`)
}

func assertValid(t *testing.T, content []byte) {
	t.Helper()
	ssot, err := model.Load(content)
	if err != nil {
		t.Fatalf("model.Load: %v\n%s", err, content)
	}
	if findings := validate.Validate(ssot); len(findings) > 0 {
		t.Fatalf("validation findings: %v\n%s", findings, content)
	}
}

func mustPlanBytes(t *testing.T, plan Plan) []byte {
	t.Helper()
	var b strings.Builder
	b.WriteString(plan.Node.ID)
	b.WriteString("|")
	b.WriteString(string(plan.Node.Server.Direction))
	for _, tunnel := range plan.Tunnels {
		b.WriteString("|")
		b.WriteString(tunnel.Pair())
		b.WriteString("|")
		b.WriteString(tunnel.FromAddr)
		b.WriteString("|")
		b.WriteString(tunnel.ToAddr)
	}
	for _, policy := range plan.FixedPolicies {
		b.WriteString("|")
		b.WriteString(policy.ID)
		b.WriteString("|")
		b.WriteString(policy.EgressAxis)
	}
	for _, policy := range plan.ExpandedPolicies {
		b.WriteString("|")
		b.WriteString(policy.ID)
		b.WriteString("|")
		b.WriteString(strings.Join(policy.AllowedServers, ","))
	}
	return []byte(b.String())
}

func planPolicyByID(t *testing.T, plan Plan, id string) *model.AccessDeclaration {
	t.Helper()
	for i := range plan.FixedPolicies {
		if plan.FixedPolicies[i].ID == id {
			return &plan.FixedPolicies[i]
		}
	}
	t.Fatalf("policy %q absent from %#v", id, plan.FixedPolicies)
	return nil
}

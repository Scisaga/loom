package ssotedit

import (
	"bytes"
	"slices"
	"strings"
	"testing"

	"loom/internal/model"
)

func TestAddAccessClientBuildsIndependentAutomaticLinuxAccess(t *testing.T) {
	content := bytes.Replace(fixtureSSOT(t), []byte("declarations:\n"), []byte(`services:
  - id: web
    declaration: best-egress
    addresses: [api.example.com, .example.com]
declarations:
`), 1)
	content = append([]byte("# preserve client enrollment comment\n"), content...)
	plan, err := AddAccessClient(content, ClientInput{
		ID: "build-laptop", Name: "Build laptop", Platform: model.LinuxServer,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(plan.Content, []byte("# preserve client enrollment comment")) {
		t.Fatal("client edit lost existing YAML comments")
	}
	ssot := loadResult(t, plan.Content)
	node := ssot.NodeByID()["build-laptop"]
	if node == nil || !node.IsAccess() || node.IsServer() || node.Access.Platform != model.LinuxServer {
		t.Fatalf("added client = %#v", node)
	}
	if len(node.Access.MixedPorts) != 1 || node.Access.MixedPorts[0].Port != 1080 ||
		!node.Access.MixedPorts[0].ManagedAutomatic() {
		t.Fatalf("managed Linux inbound = %#v", node.Access.MixedPorts)
	}
	if plan.DefaultDeclaration != "best-egress" || node.Access.DefaultDeclaration != "best-egress" {
		t.Fatalf("automatic default = plan %q node %q", plan.DefaultDeclaration, node.Access.DefaultDeclaration)
	}
	if len(plan.CredentialIDs) != len(plan.CredentialRefs) || len(plan.CredentialIDs) < 2 ||
		!slices.Equal(node.Access.Credentials, plan.CredentialIDs) {
		t.Fatalf("credential plan = ids %v refs %v node %v", plan.CredentialIDs, plan.CredentialRefs, node.Access.Credentials)
	}
	for i, id := range plan.CredentialIDs {
		credential := ssot.CredentialByID()[id]
		if credential == nil || credential.Owner != node.ID || credential.SecretRef != plan.CredentialRefs[i] ||
			!ssot.DeclarationByID()[credential.Declaration].AddressFromRequest() {
			t.Fatalf("credential %q = %#v", id, credential)
		}
	}
}

func TestAddAccessClientUsesOnlyPinnedDestinationGrants(t *testing.T) {
	content := bytes.Replace(fixtureSSOT(t), []byte("declarations:\n"), []byte(`services:
  - id: web
    declaration: best-egress
    addresses: [api.example.com]
declarations:
`), 1)
	plan, err := AddAccessClient(content, ClientInput{
		ID: "least-privilege", Platform: model.LinuxServer,
		DestinationGrants: []string{"best-egress"},
	})
	if err != nil {
		t.Fatal(err)
	}
	node := loadResult(t, plan.Content).NodeByID()["least-privilege"]
	if node == nil || len(node.Access.Credentials) != 1 || len(plan.CredentialIDs) != 1 ||
		plan.DefaultDeclaration != "best-egress" {
		t.Fatalf("explicit profile grant shape node=%+v plan=%+v", node, plan)
	}
	if strings.Contains(string(plan.Content), "cred-least-privilege-llm-ttft") {
		t.Fatal("an ungranted current declaration was added to the Device")
	}
}

func TestAddAccessClientBuildsWindowsDesktopAccess(t *testing.T) {
	plan, err := AddAccessClient(fixtureSSOT(t), ClientInput{
		ID: "windows-laptop", Name: "Windows laptop", Platform: model.WindowsDesktop,
		DestinationGrants: []string{"best-egress"},
	})
	if err != nil {
		t.Fatal(err)
	}
	node := loadResult(t, plan.Content).NodeByID()["windows-laptop"]
	if node == nil || node.Server != nil || node.Access == nil || node.Access.Platform != model.WindowsDesktop {
		t.Fatalf("Windows access node = %#v", node)
	}
	if err := ValidateAccessClientShape(loadResult(t, plan.Content), node, ClientInput{
		ID: node.ID, Name: node.Name, Platform: model.WindowsDesktop,
		DestinationGrants: []string{"best-egress"},
	}); err != nil {
		t.Fatalf("validate Windows access shape: %v", err)
	}
}

func TestAddAccessClientBuildsAndroidTUNOnlyAccess(t *testing.T) {
	plan, err := AddAccessClient(fixtureSSOT(t), ClientInput{
		ID: "android-phone", Name: "Android phone", Platform: model.Android,
		DestinationGrants: []string{"best-egress"},
	})
	if err != nil {
		t.Fatal(err)
	}
	ssot := loadResult(t, plan.Content)
	node := ssot.NodeByID()["android-phone"]
	if node == nil || node.Server != nil || node.Access == nil || node.Access.Platform != model.Android {
		t.Fatalf("Android access node = %#v", node)
	}
	if len(node.Access.MixedPorts) != 0 {
		t.Fatalf("Android access declared mixed ports = %#v", node.Access.MixedPorts)
	}
	if plan.DefaultDeclaration != "best-egress" || node.Access.DefaultDeclaration != "best-egress" {
		t.Fatalf("Android automatic default = plan %q node %q", plan.DefaultDeclaration, node.Access.DefaultDeclaration)
	}
	if err := ValidateAccessClientShape(ssot, node, ClientInput{
		ID: node.ID, Name: node.Name, Platform: model.Android,
		DestinationGrants: []string{"best-egress"},
	}); err != nil {
		t.Fatalf("validate Android access shape: %v", err)
	}
}

func TestAddAccessRolePreservesExistingServerDevice(t *testing.T) {
	content := fixtureSSOT(t)
	before := loadResult(t, content).NodeByID()["cn-bj"]
	if before == nil || before.Server == nil || before.Access != nil {
		t.Fatalf("fixture server = %#v", before)
	}
	server := *before.Server
	plan, err := AddAccessRole(content, ClientInput{
		ID: "cn-bj", Name: before.Name, Platform: model.LinuxServer,
		DestinationGrants: []string{"best-egress"},
	})
	if err != nil {
		t.Fatal(err)
	}
	after := loadResult(t, plan.Content).NodeByID()["cn-bj"]
	if after == nil || after.Access == nil || after.Server == nil || *after.Server != server ||
		after.PublicEndpoint != before.PublicEndpoint || after.Name != before.Name {
		t.Fatalf("combined Device = %#v, previous server = %#v", after, before)
	}
	if len(after.Access.Credentials) != 1 || len(plan.CredentialRefs) != 1 ||
		len(after.Access.MixedPorts) != 1 || after.Access.MixedPorts[0].Declaration != "best-egress" {
		t.Fatalf("attached access credentials=%v mixed=%v refs=%v", after.Access.Credentials, after.Access.MixedPorts, plan.CredentialRefs)
	}
}

func TestAddAccessClientRejectsUnsupportedOrDuplicateClient(t *testing.T) {
	content := fixtureSSOT(t)
	for _, tc := range []struct {
		name string
		in   ClientInput
		want string
	}{
		{"invalid id", ClientInput{ID: "Not Safe", Platform: model.LinuxServer}, "invalid"},
		{"unsupported platform", ClientInput{ID: "new-client", Platform: model.Platform("ios")}, "not delivered"},
		{"duplicate", ClientInput{ID: "workstation", Platform: model.LinuxServer}, "already exists"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := AddAccessClient(content, tc.in)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v, want %q", err, tc.want)
			}
		})
	}
}

func TestAddAccessClientRejectsGeneratedSecretRefCollision(t *testing.T) {
	for _, tc := range []struct {
		name       string
		generation string
	}{
		{name: "current ref"},
		{name: "previous ref", generation: ", generation: 2"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			content := bytes.Replace(fixtureSSOT(t), []byte("credentials:\n"), []byte(`credentials:
  - {id: existing-collision, owner: existing, declaration: best-egress, secret_ref: "cred/new-client/best-egress"`+tc.generation+`}
`), 1)
			_, err := AddAccessClient(content, ClientInput{ID: "new-client", Platform: model.LinuxServer})
			if err == nil || !strings.Contains(err.Error(), "conflicts with current or previous ref") {
				t.Fatalf("AddAccessClient error = %v", err)
			}
		})
	}
}

func TestAddAccessClientKeepsFailClosedWhenAutomaticDefaultIsAmbiguous(t *testing.T) {
	content := bytes.Replace(fixtureSSOT(t), []byte("declarations:\n"), []byte(`declarations:
  - id: another-auto
    address_axis: from_request
    egress_axis: any
    objective: latency
    probe_url: https://probe.example.net/
    allowed_servers: [cn-bj, cn-sh, cn-gz, cn-cd, sg-vps, jp-vps]
    max_hops: 2
    tuning_period: 5m
    switch_threshold: 0.2
    probe_budget: 9
    window: 2h
    min_samples: 6
    stale_after: 20m
`), 1)
	plan, err := AddAccessClient(content, ClientInput{ID: "ambiguous", Platform: model.LinuxServer})
	if err != nil {
		t.Fatal(err)
	}
	if plan.DefaultDeclaration != "" {
		t.Fatalf("ambiguous automatic declarations selected %q", plan.DefaultDeclaration)
	}
	if got := loadResult(t, plan.Content).NodeByID()["ambiguous"].Access.DefaultDeclaration; got != "" {
		t.Fatalf("ambiguous client default = %q", got)
	}
}

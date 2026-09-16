package report

import (
	"os"
	"strings"
	"testing"

	"loom/internal/clientregistry"
	"loom/internal/model"
	"loom/internal/ssotedit"
)

func TestValidateProvisionedClientRequiresExactGeneratedShape(t *testing.T) {
	for _, withServices := range []bool{false, true} {
		name := "without services"
		if withServices {
			name = "with services"
		}
		t.Run(name, func(t *testing.T) {
			s, node, client := generatedProvisionedClient(t, withServices)
			if err := validateProvisionedClient(s, node, client); err != nil {
				t.Fatalf("generated shape rejected: %v", err)
			}
		})
	}

	tests := []struct {
		name         string
		withServices bool
		mutate       func(*model.SSOT, *model.Node, clientregistry.Client)
		want         string
	}{
		{
			name: "missing declaration credential",
			mutate: func(_ *model.SSOT, node *model.Node, _ clientregistry.Client) {
				node.Access.Credentials = node.Access.Credentials[:len(node.Access.Credentials)-1]
			}, want: "want exactly",
		},
		{
			name: "extra listed credential",
			mutate: func(_ *model.SSOT, node *model.Node, _ clientregistry.Client) {
				node.Access.Credentials = append(node.Access.Credentials, "cred-ws-sg")
			}, want: "want exactly",
		},
		{
			name: "wrong credential owner",
			mutate: func(s *model.SSOT, node *model.Node, _ clientregistry.Client) {
				s.CredentialByID()[node.Access.Credentials[0]].Owner = "other-client"
			}, want: "owner/declaration/ref",
		},
		{
			name: "wrong credential declaration",
			mutate: func(s *model.SSOT, node *model.Node, _ clientregistry.Client) {
				s.CredentialByID()[node.Access.Credentials[0]].Declaration = "llm-ttft"
			}, want: "owner/declaration/ref",
		},
		{
			name: "wrong credential ref",
			mutate: func(s *model.SSOT, node *model.Node, _ clientregistry.Client) {
				s.CredentialByID()[node.Access.Credentials[0]].SecretRef = "cred/wrong/ref"
			}, want: "owner/declaration/ref",
		},
		{
			name: "extra unlisted owned credential",
			mutate: func(s *model.SSOT, _ *model.Node, client clientregistry.Client) {
				s.Credentials = append(s.Credentials, model.Credential{
					ID: "extra-client-credential", Owner: client.ID,
					Declaration: "best-egress", SecretRef: "cred/extra/client",
				})
			}, want: "extra credential",
		},
		{
			name: "no-services wrong port",
			mutate: func(_ *model.SSOT, node *model.Node, _ clientregistry.Client) {
				node.Access.MixedPorts[0].Port++
			}, want: "mixed port",
		},
		{
			name: "no-services wrong declaration",
			mutate: func(_ *model.SSOT, node *model.Node, _ clientregistry.Client) {
				node.Access.MixedPorts[0].Declaration = "llm-ttft"
			}, want: "mixed port",
		},
		{
			name: "services unmanaged 1080", withServices: true,
			mutate: func(_ *model.SSOT, node *model.Node, _ clientregistry.Client) {
				node.Access.MixedPorts[0].Services = false
				node.Access.MixedPorts[0].Declaration = "best-egress"
			}, want: "mixed port",
		},
		{
			name: "services extra port", withServices: true,
			mutate: func(_ *model.SSOT, node *model.Node, _ clientregistry.Client) {
				node.Access.MixedPorts = append(node.Access.MixedPorts, model.MixedPort{Port: 1081, Services: true})
			}, want: "want exactly 1",
		},
		{
			name: "services wrong default", withServices: true,
			mutate: func(_ *model.SSOT, node *model.Node, _ clientregistry.Client) {
				node.Access.DefaultDeclaration = "sg-fixed"
			}, want: "default_declaration",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s, node, client := generatedProvisionedClient(t, tc.withServices)
			tc.mutate(s, node, client)
			if err := validateProvisionedClient(s, node, client); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("validateProvisionedClient error = %v, want %q", err, tc.want)
			}
		})
	}
}

func generatedProvisionedClient(t *testing.T, withServices bool) (*model.SSOT, *model.Node, clientregistry.Client) {
	t.Helper()
	body, err := os.ReadFile("../../testdata/matrix/ssot.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if withServices {
		body = []byte(strings.Replace(string(body), "declarations:\n", `services:
  - id: web
    declaration: best-egress
    addresses: [api.example.com, .example.com]
declarations:
`, 1))
	}
	base, err := model.Load(body)
	if err != nil {
		t.Fatal(err)
	}
	var grants []string
	for _, declaration := range base.Declarations {
		if declaration.AddressFromRequest() {
			grants = append(grants, declaration.ID)
		}
	}
	client := clientregistry.Client{
		ID: "client-shape01", Name: "Shape client", Platform: string(model.LinuxServer),
	}
	pinTestIntent(t, &client, clientregistry.EnrollmentIntent{
		Platform: client.Platform, Responsibilities: []string{"use_loom"}, DestinationGrants: grants,
	})
	plan, err := ssotedit.AddAccessClient(body, ssotedit.ClientInput{
		ID: client.ID, Name: client.Name, Platform: model.LinuxServer, DestinationGrants: grants,
	})
	if err != nil {
		t.Fatal(err)
	}
	s, err := model.Load(plan.Content)
	if err != nil {
		t.Fatal(err)
	}
	return s, s.NodeByID()[client.ID], client
}

func pinTestIntent(t *testing.T, client *clientregistry.Client, input clientregistry.EnrollmentIntent) {
	t.Helper()
	intent, err := clientregistry.NormalizeEnrollmentIntent(input)
	if err != nil {
		t.Fatal(err)
	}
	client.Platform = intent.Platform
	client.Responsibilities = append([]string(nil), intent.Responsibilities...)
	client.DestinationGrants = append([]string(nil), intent.DestinationGrants...)
	client.Direction = intent.Direction
}

package ssotedit

import (
	"bytes"
	"errors"
	"os"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"loom/internal/model"
)

func TestUpsertServiceAddsAndPreservesDocument(t *testing.T) {
	content := append([]byte("# editor must keep this comment\n"), fixtureSSOT(t)...)
	input := ServiceInput{
		ID:          "intl-api",
		Name:        "International API",
		Addresses:   []string{"api.example.com", ".example.net"},
		Declaration: "best-egress",
	}

	got, err := UpsertService(content, input)
	if err != nil {
		t.Fatalf("UpsertService: %v", err)
	}
	if !bytes.HasSuffix(got, []byte("\n")) {
		t.Fatal("edited YAML does not end with a newline")
	}
	for _, preserved := range []string{
		"# editor must keep this comment",
		"equivalence_classes:",
		"llm:qwen3-32b-int8@openai-v1",
		"credentials:",
		"cred-phone",
	} {
		if !bytes.Contains(got, []byte(preserved)) {
			t.Errorf("edited YAML lost unrelated content %q", preserved)
		}
	}

	ssot := loadResult(t, got)
	if len(ssot.Services) != 1 {
		t.Fatalf("services = %#v, want one service", ssot.Services)
	}
	service := ssot.Services[0]
	if service.ID != input.ID || service.Name != input.Name ||
		service.Declaration != input.Declaration {
		t.Errorf("service = %#v, want %#v", service, input)
	}
	if strings.Join(service.Addresses, ",") != strings.Join(input.Addresses, ",") {
		t.Errorf("addresses = %#v, want %#v", service.Addresses, input.Addresses)
	}

	stable, err := UpsertService(got, input)
	if err != nil {
		t.Fatalf("repeat UpsertService: %v", err)
	}
	if !bytes.Equal(stable, got) {
		t.Error("repeating the same upsert changed the encoded document")
	}
}

func TestUpsertServiceUpdatesInPlace(t *testing.T) {
	content := append(fixtureSSOT(t), []byte(`
services:
  # keep the first service in this position
  - id: first
    name: Old name
    addresses: [old.example.com] # keep address note
    declaration: best-egress
  - id: second
    addresses: [second.example.org]
    declaration: best-egress
`)...)

	got, err := UpsertService(content, ServiceInput{
		ID:          "first",
		Addresses:   []string{"new.example.com", ".new.example.com"},
		Declaration: "sg-fixed",
	})
	if err != nil {
		t.Fatalf("UpsertService: %v", err)
	}
	if !bytes.Contains(got, []byte("# keep the first service in this position")) {
		t.Error("service comment was lost")
	}
	if !bytes.Contains(got, []byte("# keep address note")) {
		t.Error("field comment was lost")
	}
	if bytes.Index(got, []byte("id: first")) > bytes.Index(got, []byte("id: second")) {
		t.Error("existing service was not updated in place")
	}

	ssot := loadResult(t, got)
	if len(ssot.Services) != 2 {
		t.Fatalf("services = %#v", ssot.Services)
	}
	if got := ssot.Services[0]; got.ID != "first" || got.Name != "" ||
		got.Declaration != "sg-fixed" || len(got.Addresses) != 2 {
		t.Errorf("updated service = %#v", got)
	}
}

func TestUpdateServiceReusesUnchangedAddressNodes(t *testing.T) {
	keptFirst := scalarNode("same.example.com")
	keptFirst.HeadComment = "first head"
	keptFirst.LineComment = "first line"
	keptFirst.FootComment = "first foot"
	keptDuplicate := scalarNode("same.example.com")
	keptDuplicate.LineComment = "duplicate line"
	removed := scalarNode("removed.example.com")
	removed.LineComment = "must disappear"

	addresses := &yaml.Node{
		Kind:        yaml.SequenceNode,
		Tag:         "!!seq",
		HeadComment: "addresses head",
		LineComment: "addresses line",
		FootComment: "addresses foot",
		Content:     []*yaml.Node{keptFirst, removed, keptDuplicate},
	}
	item := &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
	appendMappingValue(item, "id", scalarNode("api"))
	appendMappingValue(item, "addresses", addresses)
	appendMappingValue(item, "declaration", scalarNode("old-policy"))

	updateServiceNode(item, ServiceInput{
		ID:          "api",
		Addresses:   []string{"new.example.com", "same.example.com", "same.example.com"},
		Declaration: "new-policy",
	})

	var got *yaml.Node
	for i := 0; i < len(item.Content); i += 2 {
		if item.Content[i].Value == "addresses" {
			got = item.Content[i+1]
			break
		}
	}
	if got == nil || len(got.Content) != 3 {
		t.Fatalf("updated addresses = %#v", got)
	}
	if got.Content[0] == keptFirst || got.Content[0] == keptDuplicate || got.Content[0] == removed {
		t.Fatal("new address reused an unrelated old yaml.Node")
	}
	if got.Content[1] != keptFirst || got.Content[2] != keptDuplicate {
		t.Fatalf("unchanged duplicate nodes were not reused once and in source order: %#v", got.Content)
	}
	if got.Content[1].HeadComment != "first head" || got.Content[1].LineComment != "first line" || got.Content[1].FootComment != "first foot" {
		t.Fatalf("unchanged address comments were lost: %#v", got.Content[1])
	}
	if got.Content[2].LineComment != "duplicate line" {
		t.Fatalf("duplicate address comment was lost: %#v", got.Content[2])
	}
	if got.HeadComment != "addresses head" || got.LineComment != "addresses line" || got.FootComment != "addresses foot" {
		t.Fatalf("sequence comments were lost: %#v", got)
	}
	for _, child := range got.Content {
		if child == removed || child.LineComment == "must disappear" {
			t.Fatal("removed address node or its comment survived")
		}
	}
}

func TestDeleteService(t *testing.T) {
	content := append(fixtureSSOT(t), []byte(`
services:
  - {id: first, addresses: [first.example.com], declaration: best-egress}
  - {id: second, addresses: [second.example.com], declaration: best-egress}
`)...)

	got, err := DeleteService(content, "first")
	if err != nil {
		t.Fatalf("DeleteService: %v", err)
	}
	ssot := loadResult(t, got)
	if len(ssot.Services) != 1 || ssot.Services[0].ID != "second" {
		t.Fatalf("services after delete = %#v", ssot.Services)
	}
	if _, err := DeleteService(got, "missing"); err == nil ||
		!strings.Contains(err.Error(), "does not exist") {
		t.Fatalf("deleting absent service error = %v", err)
	}
}

func TestUpsertServiceRejectsInvalidInput(t *testing.T) {
	base := fixtureSSOT(t)
	for _, tc := range []struct {
		name  string
		input ServiceInput
	}{
		{"missing id", ServiceInput{Addresses: []string{"a.example.com"}, Declaration: "best-egress"}},
		{"missing addresses", ServiceInput{ID: "a", Declaration: "best-egress"}},
		{"empty address", ServiceInput{ID: "a", Addresses: []string{" "}, Declaration: "best-egress"}},
		{"missing declaration", ServiceInput{ID: "a", Addresses: []string{"a.example.com"}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := UpsertService(base, tc.input); err == nil {
				t.Fatal("UpsertService unexpectedly accepted invalid input")
			}
		})
	}
}

func TestUpsertServiceRejectsInvalidHostAndDeclaration(t *testing.T) {
	base := fixtureSSOT(t)
	for _, tc := range []struct {
		name        string
		addresses   []string
		declaration string
		want        string
	}{
		{"wildcard host", []string{"*.example.com"}, "best-egress", "wildcard"},
		{"URL instead of host", []string{"https://api.example.com/path"}, "best-egress", "URL"},
		{"unknown declaration", []string{"api.example.com"}, "does-not-exist", "不存在的声明"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := UpsertService(base, ServiceInput{
				ID:          "bad",
				Addresses:   tc.addresses,
				Declaration: tc.declaration,
			})
			var validationErr *ValidationError
			if !errors.As(err, &validationErr) {
				t.Fatalf("error = %T %v, want ValidationError", err, err)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error %q does not contain %q", err, tc.want)
			}
		})
	}
}

func TestUpsertServiceRejectsUnrelatedInvalidSSOT(t *testing.T) {
	content := fixtureSSOT(t)
	content = bytes.Replace(content, []byte("agent: 0.1.0"), []byte("agent: latest"), 1)

	_, err := UpsertService(content, ServiceInput{
		ID:          "valid-service",
		Addresses:   []string{"api.example.com"},
		Declaration: "best-egress",
	})
	var validationErr *ValidationError
	if !errors.As(err, &validationErr) {
		t.Fatalf("error = %T %v, want ValidationError", err, err)
	}
	if !strings.Contains(err.Error(), "latest") {
		t.Fatalf("error %q does not report unrelated invalid SSOT", err)
	}
}

func TestEditorRejectsSchemaUnknownTopLevelField(t *testing.T) {
	// model.Load uses KnownFields.  The editor must not return a document the
	// runtime itself cannot load, even though yaml.Node can preserve the field.
	content := append(fixtureSSOT(t), []byte("\nfuture_runtime_field: keep-me\n")...)
	_, err := UpsertService(content, ServiceInput{
		ID:          "service",
		Addresses:   []string{"api.example.com"},
		Declaration: "best-egress",
	})
	if err == nil || !strings.Contains(err.Error(), "future_runtime_field") {
		t.Fatalf("schema-unknown field error = %v", err)
	}
}

func fixtureSSOT(t *testing.T) []byte {
	t.Helper()
	content, err := os.ReadFile("../../testdata/matrix/ssot.yaml")
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	return content
}

func loadResult(t *testing.T, content []byte) *model.SSOT {
	t.Helper()
	ssot, err := model.Load(content)
	if err != nil {
		t.Fatalf("load edited SSOT: %v\n%s", err, content)
	}
	return ssot
}

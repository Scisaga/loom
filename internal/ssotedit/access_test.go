package ssotedit

import (
	"bytes"
	"strings"
	"testing"
)

func TestSetAccessDefaultDeclarationPreservesDocumentAndCanClear(t *testing.T) {
	content := append([]byte("# preserve access editor comment\n"), fixtureSSOT(t)...)

	selected, err := SetAccessDefaultDeclaration(content, "workstation", "sg-fixed")
	if err != nil {
		t.Fatalf("SetAccessDefaultDeclaration: %v", err)
	}
	if !bytes.Contains(selected, []byte("# preserve access editor comment")) ||
		!bytes.Contains(selected, []byte("default_declaration: sg-fixed")) {
		t.Fatalf("编辑丢失注释或默认出口:\n%s", selected)
	}
	if got := loadResult(t, selected).NodeByID()["workstation"].Access.DefaultDeclaration; got != "sg-fixed" {
		t.Fatalf("default_declaration=%q,期望 sg-fixed", got)
	}

	stable, err := SetAccessDefaultDeclaration(selected, "workstation", "sg-fixed")
	if err != nil {
		t.Fatalf("repeat SetAccessDefaultDeclaration: %v", err)
	}
	if !bytes.Equal(stable, selected) {
		t.Fatal("重复写入相同设备默认出口改变了文档")
	}

	cleared, err := SetAccessDefaultDeclaration(selected, "workstation", "")
	if err != nil {
		t.Fatalf("clear SetAccessDefaultDeclaration: %v", err)
	}
	if got := bytes.Count(cleared, []byte("default_declaration: sg-fixed")); got != 1 {
		t.Fatalf("清除 workstation 后只应保留 phone 的字段,实际 %d 处", got)
	}
	if got := loadResult(t, cleared).NodeByID()["workstation"].Access.DefaultDeclaration; got != "" {
		t.Fatalf("清除后 default_declaration=%q", got)
	}
}

func TestSetAccessDefaultDeclarationRejectsUnknownAndUnauthorizedValues(t *testing.T) {
	content := fixtureSSOT(t)
	for _, tc := range []struct {
		name, node, declaration, want string
	}{
		{name: "unknown node", node: "missing", declaration: "sg-fixed", want: "does not exist"},
		{name: "not access", node: "cn-bj", declaration: "sg-fixed", want: "not an access node"},
		{name: "unauthorized declaration", node: "phone", declaration: "best-egress", want: "没有持有"},
		{name: "non-proxy declaration", node: "workstation", declaration: "llm-ttft", want: "address_axis 不是 from_request"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := SetAccessDefaultDeclaration(content, tc.node, tc.declaration)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error=%v,期望包含 %q", err, tc.want)
			}
		})
	}
}

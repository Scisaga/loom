package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestBinaryCandidateSelfcheckRequiresSignedCurrentCapability(t *testing.T) {
	tests := []struct {
		name  string
		quiet bool
		want  string
	}{
		{name: "pin-or-rollback", want: "selfcheck -require signed-current-v1"},
		{name: "release-quiet", quiet: true, want: "selfcheck -q -require signed-current-v1"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			bin := filepath.Join(t.TempDir(), "candidate")
			script := "#!/bin/sh\n" +
				"[ \"$*\" = '" + tc.want + "' ] || { echo \"unexpected args: $*\" >&2; exit 9; }\n"
			if err := os.WriteFile(bin, []byte(script), 0o755); err != nil {
				t.Fatal(err)
			}
			if out, err := selfcheckBinaryCandidate(bin, tc.quiet); err != nil {
				t.Fatalf("capability-aware candidate rejected: %v\n%s", err, out)
			}
		})
	}
}

func TestBinaryCandidateSelfcheckRejectsLegacySelfcheck(t *testing.T) {
	bin := filepath.Join(t.TempDir(), "legacy-candidate")
	// 模拟只认 `selfcheck` 、不认 -require 的历史二进制。它本来能
	// 通过旧冒烟测试，但不能被 release / pin / rollback 再次选中。
	script := "#!/bin/sh\n[ \"$#\" -eq 1 ] && [ \"$1\" = selfcheck ]\n"
	if err := os.WriteFile(bin, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	if out, err := selfcheckBinaryCandidate(bin, false); err == nil {
		t.Fatalf("legacy candidate without %s was accepted: %s", signedCurrentCapability, out)
	}
}

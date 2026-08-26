package model

import (
	"strings"
	"testing"
)

func TestValidNodeID(t *testing.T) {
	t.Parallel()

	for _, id := range []string{
		"a",
		"jm24",
		"ci-runner",
		"server-in-a-very-long-city",
		strings.Repeat("a", 63),
	} {
		if !ValidNodeID(id) {
			t.Errorf("ValidNodeID(%q) = false, want true", id)
		}
	}

	for _, id := range []string{
		"",
		"../escape",
		"a/b",
		`a\b`,
		".hidden",
		"-leading",
		"trailing-",
		"under_score",
		"with space",
		"Node-1",
		"节点",
		strings.Repeat("a", 64),
	} {
		if ValidNodeID(id) {
			t.Errorf("ValidNodeID(%q) = true, want false", id)
		}
	}
}

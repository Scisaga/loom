package linuxclient

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestLinuxNativeCheckAndStartFileDoNotConstructUnusedSenders(t *testing.T) {
	// A mechanism fixture exercises only the actual Check/file boundary. The
	// executable never starts a transport, capture, listener or host interface.
	source := `{"inbounds":[],"outbounds":[{"type":"block","tag":"reject"},{"type":"hysteria2","tag":"demo-sender","server":"192.0.2.10","server_port":443,"password":"demo-only","execution":{"authentication_digest":"sha256:1111111111111111111111111111111111111111111111111111111111111111"}}],"route":{"rules":[],"final":"reject"}}`
	root := t.TempDir()
	executable := filepath.Join(root, "demo-native")
	if err := os.WriteFile(executable, []byte("#!/bin/sh\ncat \"$3\" > \"$0.captured\"\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := preflightRuntimeConfig(executable, source); err != nil {
		t.Fatal(err)
	}
	started := filepath.Join(root, "demo-runtime.json")
	if err := writeNativeResourceConfig(started, source); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{executable + ".captured", started} {
		body, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		var document map[string]any
		if json.Unmarshal(body, &document) != nil {
			t.Fatal("native process input is not a complete JSON projection")
		}
		outbounds := document["outbounds"].([]any)
		if len(outbounds) != 1 || outbounds[0].(map[string]any)["tag"] != "reject" {
			t.Fatal("actual native process input eagerly constructed a sender")
		}
		if document["route"].(map[string]any)["final"] != "reject" {
			t.Fatal("stripping constructors changed final rejection")
		}
	}
}

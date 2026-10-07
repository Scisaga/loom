//go:build windows

package main

import (
	"bytes"
	"io"
	"os"
	"testing"
)

func TestWindowsRuntimeStatusReaderAllowsAtomicReplaceAndStop(t *testing.T) {
	root := t.TempDir()
	path := windowsRuntimeStatusPath(root)
	before := []byte(`{"schema":3,"view_digest":"demo-before"}`)
	after := []byte(`{"schema":3,"view_digest":"demo-after"}`)
	if err := writeWindowsRuntimeStatusFile(path, before); err != nil {
		t.Fatal(err)
	}
	reader, err := openWindowsRuntimeStatus(root)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	if err := writeWindowsRuntimeStatusFile(path, after); err != nil {
		t.Fatal("UI read handle prevented the next runtime status", err)
	}
	snapshot, err := io.ReadAll(reader)
	if err != nil || !bytes.Equal(snapshot, before) {
		t.Fatal("reader did not retain its complete original snapshot", err)
	}
	current, err := readWindowsRuntimeStatus(root)
	if err != nil || current.ViewDigest != "demo-after" {
		t.Fatal("next reader did not see the committed status", err)
	}
	currentReader, err := openWindowsRuntimeStatus(root)
	if err != nil {
		t.Fatal(err)
	}
	defer currentReader.Close()
	if err := os.Remove(path); err != nil {
		t.Fatal("UI read handle prevented normal stop cleanup", err)
	}
	// DeleteFile can leave the name delete-pending until the in-flight reader
	// finishes. The existing reader must still finish its complete snapshot.
	stoppedSnapshot, err := io.ReadAll(currentReader)
	if err != nil || !bytes.Equal(stoppedSnapshot, after) {
		t.Fatal("stop interrupted the opened status snapshot", err)
	}
	if err := currentReader.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := readWindowsRuntimeStatus(root); !os.IsNotExist(err) {
		t.Fatal("stop retained a readable current status", err)
	}
}

package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestAndroidOutputNewRetryAndConflict(t *testing.T) {
	path := filepath.Join(t.TempDir(), "demo-application.apk")
	body := []byte("demo-signed-application")
	for range 2 {
		if err := writeAndroidOutput(path, body); err != nil {
			t.Fatal(err)
		}
	}
	if err := writeAndroidOutput(path, []byte("demo-other-application")); err == nil {
		t.Fatal("different application replaced original output")
	}
	actual, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(body, actual) {
		t.Fatal("original application bytes were changed")
	}
	entries, err := os.ReadDir(filepath.Dir(path))
	if err != nil || len(entries) != 1 || entries[0].Name() != filepath.Base(path) {
		t.Fatal("packaging temporary files were retained")
	}
}

package report

import (
	"net"
	"os"
	"path/filepath"
	"testing"
)

func TestControlUISocketIsOwnerOnlyAndRefusesActiveListener(t *testing.T) {
	path := filepath.Join(t.TempDir(), "control-ui.sock")
	listener, err := listenControlUISocket(path)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	defer removeControlUISocket(path)
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode()&os.ModeSocket == 0 || info.Mode().Perm() != 0o600 {
		t.Fatalf("control UI socket mode = %v", info.Mode())
	}
	if second, err := listenControlUISocket(path); err == nil {
		_ = second.Close()
		t.Fatal("second listener replaced an active control UI socket")
	}
}

func TestControlUISocketReplacesOnlyStaleSocket(t *testing.T) {
	path := filepath.Join(t.TempDir(), "control-ui.sock")
	listener, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := listenControlUISocket(path)
	if err != nil {
		t.Fatalf("replace stale socket: %v", err)
	}
	_ = reopened.Close()
	removeControlUISocket(path)

	if err := os.WriteFile(path, []byte("do not replace"), 0o600); err != nil {
		t.Fatal(err)
	}
	if unexpected, err := listenControlUISocket(path); err == nil {
		_ = unexpected.Close()
		t.Fatal("control UI socket replaced a regular file")
	}
	body, err := os.ReadFile(path)
	if err != nil || string(body) != "do not replace" {
		t.Fatalf("regular file changed: body=%q err=%v", body, err)
	}
}

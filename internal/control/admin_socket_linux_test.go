package control

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"sync"
	"syscall"
	"testing"
	"time"
)

func TestAdminSocketServerProcess(t *testing.T) {
	for i, arg := range os.Args {
		if arg != "--demo-admin-server" || i+1 >= len(os.Args) {
			continue
		}
		root := os.Args[i+1]
		runtime, err := OpenRuntime(root, nil)
		if err != nil {
			t.Fatal(err)
		}
		defer runtime.Close()
		ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM)
		defer stop()
		server := &Server{Runtime: runtime, Config: runtime.Config, AdminSocket: filepath.Join(root, "admin.sock")}
		if err := server.Serve(ctx); err != nil {
			t.Fatal(err)
		}
		return
	}
}

func TestAdminSocketCrashRecovery(t *testing.T) {
	root, config, genesis := authorityFixture(t)
	if _, err := InitializeAuthority(root, config, genesis); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "admin.sock")
	transport := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", path)
	}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: time.Second}
	start := func() func(os.Signal) error {
		command := exec.Command(os.Args[0], "-test.run=^TestAdminSocketServerProcess$", "--", "--demo-admin-server", root)
		var output bytes.Buffer
		command.Stdout, command.Stderr = &output, &output
		if err := command.Start(); err != nil {
			t.Fatal(err)
		}
		var once sync.Once
		var result error
		stop := func(sig os.Signal) error {
			once.Do(func() {
				command.Process.Signal(sig)
				result = command.Wait()
			})
			return result
		}
		t.Cleanup(func() { stop(syscall.SIGKILL) })
		deadline := time.Now().Add(5 * time.Second)
		for {
			response, err := client.Get("http://localhost/api/control/ui/snapshot")
			if err == nil {
				io.Copy(io.Discard, response.Body)
				response.Body.Close()
				if response.StatusCode == http.StatusOK {
					return stop
				}
			}
			if time.Now().After(deadline) {
				stop(syscall.SIGKILL)
				t.Fatalf("formal management entry did not recover: %s", output.String())
			}
			time.Sleep(10 * time.Millisecond)
		}
	}
	write := func(id string) {
		body, err := EncodeOperation(authorityService(id, id+"-create"))
		if err != nil {
			t.Fatal(err)
		}
		response, err := client.Post("http://localhost/api/control/operations", "application/json", bytes.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		if response.StatusCode != http.StatusOK {
			t.Fatalf("formal write failed: %d", response.StatusCode)
		}
	}
	stop := start()
	write("demo-before-crash")
	original := map[string][]byte{}
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil || entry.IsDir() || entry.Type()&os.ModeSocket != 0 {
			return err
		}
		body, err := os.ReadFile(path)
		original[path] = body
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	if stop(syscall.SIGKILL) == nil {
		t.Fatal("the service did not exit abnormally")
	}
	transport.CloseIdleConnections()
	if info, err := os.Lstat(path); err != nil || info.Mode()&os.ModeSocket == 0 {
		t.Fatal("the crash did not leave the actual socket", err)
	}
	stop = start()
	for path, before := range original {
		after, err := os.ReadFile(path)
		if err != nil || !bytes.Equal(before, after) {
			t.Fatal("socket recovery changed existing persistent bytes", path, err)
		}
	}
	write("demo-after-crash")
	response, err := client.Get("http://localhost/api/control/ui/snapshot")
	if err != nil {
		t.Fatal(err)
	}
	var view struct{ Services []Service }
	err = json.NewDecoder(response.Body).Decode(&view)
	response.Body.Close()
	if err != nil || response.StatusCode != http.StatusOK || len(view.Services) != 2 {
		t.Fatal("restarted formal management entry lost ordinary writes", err)
	}
	if err := stop(syscall.SIGTERM); err != nil {
		t.Fatal("normal stop failed", err)
	}
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("normal stop left its owned socket", err)
	}
}

func TestAdminSocketOwnershipAndConcurrentStart(t *testing.T) {
	makePath := func(t *testing.T) string {
		root, err := os.MkdirTemp("", "loom-demo-admin-")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { os.RemoveAll(root) })
		return filepath.Join(root, "admin.sock")
	}
	legacy := func(t *testing.T, path string) *net.UnixListener {
		listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
		if err != nil {
			t.Fatal(err)
		}
		listener.SetUnlinkOnClose(false)
		t.Cleanup(func() { listener.Close() })
		if err := os.Chmod(path, 0o600); err != nil {
			t.Fatal(err)
		}
		return listener
	}
	for _, kind := range []string{"regular", "symlink", "public-socket", "foreign-socket", "live-legacy"} {
		t.Run(kind, func(t *testing.T) {
			path := makePath(t)
			switch kind {
			case "regular":
				if err := os.WriteFile(path, []byte("demo-preserve"), 0o600); err != nil {
					t.Fatal(err)
				}
			case "symlink":
				if err := os.Symlink("demo-unowned", path); err != nil {
					t.Fatal(err)
				}
			default:
				listener := legacy(t, path)
				if kind != "live-legacy" {
					listener.Close()
				}
				if kind == "public-socket" {
					if err := os.Chmod(path, 0o666); err != nil {
						t.Fatal(err)
					}
				}
				if kind == "foreign-socket" {
					if os.Geteuid() != 0 {
						t.Skip("changing the demo socket owner requires root")
					}
					if err := os.Chown(path, 65534, -1); err != nil {
						t.Fatal(err)
					}
				}
			}
			before, err := os.Lstat(path)
			if err != nil {
				t.Fatal(err)
			}
			listener, err := listenControlAdmin(context.Background(), path)
			if err == nil {
				listener.Close()
				t.Fatal("unsafe admin entry was replaced")
			}
			after, err := os.Lstat(path)
			if err != nil || !os.SameFile(before, after) || before.Mode() != after.Mode() {
				t.Fatal("rejected entry was changed", err)
			}
		})
	}
	t.Run("authority-lock-remains-independent", func(t *testing.T) {
		path := filepath.Join(filepath.Dir(makePath(t)), ".authority")
		listener, err := listenControlAdmin(context.Background(), path)
		if err != nil {
			t.Fatal(err)
		}
		defer listener.Close()
		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
		defer cancel()
		lock, err := lockAuthority(ctx, filepath.Dir(path))
		if err != nil {
			t.Fatal("custom admin path blocked ordinary authority writes", err)
		}
		lock.Close()
	})
	t.Run("concurrent-recovery-and-replaced-close", func(t *testing.T) {
		path := makePath(t)
		legacy(t, path).Close()
		ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
		defer cancel()
		results := make(chan net.Listener, 2)
		for range 2 {
			go func() { listener, _ := listenControlAdmin(ctx, path); results <- listener }()
		}
		first, second := <-results, <-results
		if first == nil {
			first, second = second, first
		}
		if first == nil || second != nil {
			if second != nil {
				second.Close()
			}
			if first != nil {
				first.Close()
			}
			t.Fatal("concurrent recoveries did not preserve exactly one listener")
		}
		defer first.Close()
		connection, err := net.Dial("unix", path)
		if err != nil {
			t.Fatal("losing recovery removed the winning listener", err)
		}
		connection.Close()
		if err := os.Remove(path); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte("demo-replacement"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := first.Close(); err == nil {
			t.Fatal("closing a replaced socket did not report failed cleanup")
		}
		body, err := os.ReadFile(path)
		if err != nil || string(body) != "demo-replacement" {
			t.Fatal("close removed an unowned replacement", err)
		}
	})
}

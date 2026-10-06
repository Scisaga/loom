package linuxclient

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
	"golang.org/x/sys/unix"
	"loom/internal/control"
)

func TestOfficialIsolatedTUNApplicationLifecycle(t *testing.T) {
	singBox := os.Getenv("LOOM_TUN_ROUTING_EXECUTABLE")
	if singBox == "" || os.Geteuid() != 0 {
		t.Skip("requires root namespace capability and the exact TUN data plane")
	}
	// Filesystem bytes alone cannot detect a resolved/networkd mutation over
	// the host system bus. Read each authoritative per-link setting as well.
	if resolver, err := exec.LookPath("resolvectl"); err == nil {
		for _, property := range []string{"dns", "domain", "default-route"} {
			before, err := exec.Command(resolver, property).Output()
			if err != nil {
				continue
			}
			t.Cleanup(func() {
				after, err := exec.Command(resolver, property).Output()
				if err != nil || !bytes.Equal(before, after) {
					t.Errorf("capture changed host resolver property %s", property)
				}
			})
		}
	}
	root := t.TempDir()
	loom := filepath.Join(root, "loom")
	if body, err := exec.Command("go", "build", "-o", loom, "../../cmd/loom").CombinedOutput(); err != nil {
		t.Fatalf("build normal CLI: %v %s", err, body)
	}
	t.Run("initial_namespace_refused", func(t *testing.T) {
		initial, err := os.Open("/proc/1/ns/net")
		if err != nil {
			t.Fatal(err)
		}
		defer initial.Close()
		current, err := os.Stat("/proc/self/ns/net")
		origin, initialErr := initial.Stat()
		if err != nil || initialErr != nil {
			t.Fatal("namespace readback failed")
		}
		if !os.SameFile(current, origin) {
			t.Skip("host namespace refusal requires the initial namespace")
		}
		fd, err := unix.PidfdOpen(os.Getpid(), 0)
		if err != nil {
			t.Fatal(err)
		}
		parent := os.NewFile(uintptr(fd), "test-parent")
		defer parent.Close()
		command := exec.Command(loom, "client", "_tun-worker", singBox, filepath.Join(root, "unused.json"))
		command.ExtraFiles = []*os.File{initial, parent, initial}
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		if body, err := command.CombinedOutput(); err == nil || !strings.Contains(string(body), "initial network namespace") {
			t.Fatalf("real worker did not refuse initial namespace: %v %s", err, body)
		}
		mount, err := os.Open("/proc/thread-self/ns/mnt")
		if err != nil {
			t.Fatal(err)
		}
		defer mount.Close()
		command = exec.Command(loom, "client", "_tun-worker", singBox, filepath.Join(root, "unused.json"))
		command.ExtraFiles = []*os.File{initial, parent, initial, mount}
		command.SysProcAttr = &syscall.SysProcAttr{Cloneflags: unix.CLONE_NEWNET}
		if body, err := command.CombinedOutput(); err == nil || !strings.Contains(string(body), "mount namespace is not isolated") {
			t.Fatalf("real worker did not refuse a shared mount namespace: %v %s", err, body)
		}
	})
	before, err := os.ReadFile("/etc/resolv.conf")
	if err != nil {
		t.Fatal(err)
	}
	var dns net.PacketConn
	var dnsIP string
	for i := 64; i < 128; i++ {
		dnsIP = fmt.Sprintf("127.0.0.%d", i)
		dns, err = net.ListenPacket("udp4", dnsIP+":53")
		if err == nil {
			break
		}
	}
	if err != nil {
		t.Fatal("no free fixture DNS listener", err)
	}
	defer dns.Close()
	go func() {
		buffer := make([]byte, 4096)
		for {
			n, remote, err := dns.ReadFrom(buffer)
			if err != nil {
				return
			}
			var request dnsmessage.Message
			if request.Unpack(buffer[:n]) != nil || len(request.Questions) != 1 {
				continue
			}
			question := request.Questions[0]
			answer := dnsmessage.Message{Header: dnsmessage.Header{ID: request.ID, Response: true, RecursionDesired: true, RecursionAvailable: true}, Questions: request.Questions}
			if question.Name.String() == "demo-service.example." && question.Type == dnsmessage.TypeA {
				answer.Answers = []dnsmessage.Resource{{Header: dnsmessage.ResourceHeader{Name: question.Name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 30}, Body: &dnsmessage.AResource{A: [4]byte{127, 0, 0, 1}}}}
			}
			body, _ := answer.Pack()
			_, _ = dns.WriteTo(body, remote)
		}
	}()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	certificate := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Demo TUN root"}, DNSNames: []string{"demo-service.example"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, certificate, certificate, public, private)
	if err != nil {
		t.Fatal(err)
	}
	trust := filepath.Join(root, "demo-root.pem")
	if err := os.WriteFile(trust, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0600); err != nil {
		t.Fatal(err)
	}
	target := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "demo TUN business") }))
	target.TLS = &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: private}}}
	target.StartTLS()
	defer target.Close()
	port := target.Listener.Addr().(*net.TCPAddr).Port
	resourceLeaf := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "Demo resource"}, DNSNames: certificate.DNSNames, NotBefore: certificate.NotBefore, NotAfter: certificate.NotAfter, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: certificate.ExtKeyUsage}
	resourceCA, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	resourceDER, err := x509.CreateCertificate(rand.Reader, resourceLeaf, resourceCA, public, private)
	if err != nil {
		t.Fatal(err)
	}
	resourceParsed, err := x509.ParseCertificate(resourceDER)
	if err != nil {
		t.Fatal(err)
	}
	resourcePool := x509.NewCertPool()
	resourcePool.AddCert(resourceCA)
	if _, err := resourceParsed.Verify(x509.VerifyOptions{Roots: resourcePool, DNSName: "demo-service.example"}); err != nil {
		t.Fatal("invalid fixture resource certificate", err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(private)
	if err != nil {
		t.Fatal(err)
	}
	resourceCertificate, resourceKey := filepath.Join(root, "resource.pem"), filepath.Join(root, "resource-key.pem")
	for path, block := range map[string]*pem.Block{resourceCertificate: {Type: "CERTIFICATE", Bytes: resourceDER}, resourceKey: {Type: "PRIVATE KEY", Bytes: keyDER}} {
		if err := os.WriteFile(path, pem.EncodeToMemory(block), 0600); err != nil {
			t.Fatal(err)
		}
	}
	listener, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	resourcePort := listener.LocalAddr().(*net.UDPAddr).Port
	listener.Close()
	resourceInputs := filepath.Join(root, "resources.json")
	if err := atomicJSON(resourceInputs, ResourceInputs{Schema: 3, Listeners: []ResourceListenerInput{{ResourceID: "demo-resource", Listen: fmt.Sprintf("127.0.0.1:%d", resourcePort), CertificateFile: resourceCertificate, KeyFile: resourceKey}}}); err != nil {
		t.Fatal(err)
	}
	resourceName, resourceRoots := "demo-service.example", []string{base64.RawURLEncoding.EncodeToString(der)}
	store, state, makeView := linuxAcceptanceFixture(t, func(_ uint64, v *control.DeviceView) {
		v.Responsibilities = []string{"access", "forward", "internet_egress"}
		v.Resources = []control.TransportResource{{ID: "demo-resource", Kind: "hysteria2", OwnerNodeID: v.DeviceID, ListenerID: "demo-listener", DialHost: "127.0.0.1", DialPort: resourcePort, Authentication: control.ResourceAuthentication{ServerName: &resourceName, CACertificates: &resourceRoots}}}
		v.DNSServers = []string{dnsIP}
		v.Endpoints[0].Host = "127.0.0.1"
		v.Endpoints[0].Port = 1
		if len(v.Services) != 0 {
			v.BusinessProbeTargets = []control.ServiceProbeTargets{{ServiceID: "demo-service", Targets: []string{fmt.Sprintf("https://demo-service.example:%d/", port)}}}
		}
	})
	if err := store.SaveLKG(makeView(7, true)); err != nil {
		t.Fatal(err)
	}
	if body, err := exec.Command(loom, "client", "preflight", "-state", state, "-sing-box", singBox, "-capture", "tun", "-resource-inputs", resourceInputs).CombinedOutput(); err != nil {
		t.Fatalf("formal TUN preflight: %v %s", err, body)
	}
	for _, failure := range []string{"normal_stop", "supervisor_kill", "data_plane_kill", "server_plane_kill", "executor_kill", "authorization_removed"} {
		t.Run(failure, func(t *testing.T) {
			directory := t.TempDir()
			config := filepath.Join(directory, "runtime.json")
			status := filepath.Join(directory, "status.json")
			log, err := os.Create(filepath.Join(directory, "runtime.log"))
			if err != nil {
				t.Fatal(err)
			}
			defer log.Close()
			readLog := func() string { body, _ := os.ReadFile(log.Name()); return string(body) }
			start := func() (*exec.Cmd, <-chan error) {
				command := exec.Command(loom, "client", "run", "-capture", "tun", "-state", state, "-runtime-state", filepath.Join(directory, "local.json"), "-runtime-config", config, "-status", status, "-sing-box", singBox, "-resource-inputs", resourceInputs)
				command.Env = append(os.Environ(), "SSL_CERT_FILE="+trust)
				command.Stdout, command.Stderr = log, log
				if err := command.Start(); err != nil {
					t.Fatal(err)
				}
				done := make(chan error, 1)
				go func() { done <- command.Wait(); close(done) }()
				t.Cleanup(func() { _ = command.Process.Kill(); <-done })
				for deadline := time.Now().Add(40 * time.Second); time.Now().Before(deadline); {
					address, _ := captureAddress(config)
					connection, err := net.DialUnix("unixpacket", nil, address)
					if err == nil {
						connection.Close()
						return command, done
					}
					select {
					case err := <-done:
						t.Fatalf("formal TUN runtime exited: %v %s", err, readLog())
					case <-time.After(20 * time.Millisecond):
					}
				}
				t.Fatalf("formal TUN runtime did not open its application entry: %s", readLog())
				return nil, nil
			}
			execute := func(args ...string) *exec.Cmd {
				command := exec.Command(loom, append([]string{"client", "exec", "-runtime-config", config, "--"}, args...)...)
				command.WaitDelay = time.Second
				return command
			}
			business := func() {
				probe := execute("curl", "--noproxy", "*", "--silent", "--show-error", "--fail", "--max-time", "8", "--cacert", trust, fmt.Sprintf("https://demo-service.example:%d/", port))
				if body, err := probe.CombinedOutput(); err != nil || string(body) != "demo TUN business" {
					t.Fatalf("formal exec DNS/TLS/HTTPS: %v %s; runtime %s", err, body, readLog())
				}
			}
			command, stopped := start()
			dataPlane := tunTestChild(t, command.Process.Pid, true)
			serverPlane := tunTestChild(t, command.Process.Pid, false)
			current, err := ReadStatus(status)
			if err != nil || len(current.Resources) != 1 || current.Resources[0].ResourceID != "demo-resource" {
				t.Fatal("hybrid server did not read back its real TLS listener", err)
			}
			if len(current.Observations) != 1 || current.Observations[0].Result != "available" || current.Observations[0].Action != "https_request" {
				t.Fatal("runtime did not consume the real isolated DNS/HTTPS probe")
			}
			business()
			read, err := os.ReadFile("/etc/resolv.conf")
			if err != nil || !bytes.Equal(read, before) {
				t.Fatal("capture changed host DNS", err)
			}
			if body, err := execute("sh", "-c", "grep '^CapEff:' /proc/self/status").CombinedOutput(); err != nil || strings.TrimSpace(string(body)) != "CapEff:	0000000000000000" {
				t.Fatalf("workload retained network privileges: %v %s", err, body)
			}
			if err := execute("sh", "-c", "test ! -S /run/dbus/system_bus_socket && test ! -S /run/systemd/private").Run(); err != nil {
				t.Fatal("application can still access host control sockets", err)
			}
			workload := execute("sh", "-c", "sleep 60 & echo ready; wait")
			output, err := workload.StdoutPipe()
			if err != nil {
				t.Fatal(err)
			}
			workload.Stderr = log
			if err := workload.Start(); err != nil {
				t.Fatal(err)
			}
			finished := make(chan error, 1)
			go func() { finished <- workload.Wait(); close(finished) }()
			t.Cleanup(func() { _ = workload.Process.Kill(); <-finished })
			ready := make(chan bool, 1)
			go func() { scanner := bufio.NewScanner(output); ready <- scanner.Scan() && scanner.Text() == "ready" }()
			select {
			case ok := <-ready:
				if !ok {
					t.Fatalf("application did not start: %s", readLog())
				}
			case <-time.After(5 * time.Second):
				t.Fatal("application start timed out")
			}
			init := tunTestChild(t, workload.Process.Pid)
			shell := tunTestChild(t, init.pid)
			sleeper := tunTestChild(t, shell.pid)
			switch failure {
			case "normal_stop":
				err = command.Process.Signal(syscall.SIGTERM)
			case "supervisor_kill":
				err = command.Process.Kill()
			case "data_plane_kill":
				err = unix.PidfdSendSignal(dataPlane.fd, unix.SIGKILL, nil, 0)
			case "server_plane_kill":
				err = unix.PidfdSendSignal(serverPlane.fd, unix.SIGKILL, nil, 0)
			case "executor_kill":
				err = workload.Process.Kill()
			case "authorization_removed":
				err = store.SaveLKG(makeView(8, false))
				if err == nil {
					err = command.Process.Signal(syscall.SIGHUP)
				}
			}
			if err != nil {
				t.Fatal(err)
			}
			select {
			case err := <-finished:
				if err == nil {
					t.Fatal("terminated application reported success")
				}
			case <-time.After(10 * time.Second):
				t.Fatalf("generation stop left an application running: %s", readLog())
			}
			for _, process := range []tunTestProcess{init, shell, sleeper} {
				process.wait(t)
			}
			if failure == "authorization_removed" {
				awaitView := func(digest string) {
					for deadline := time.Now().Add(10 * time.Second); ; {
						current, err := ReadStatus(status)
						address, _ := captureAddress(config)
						connection, dialErr := net.DialUnix("unixpacket", nil, address)
						if connection != nil {
							connection.Close()
						}
						if err == nil && current.ViewDigest == digest && current.Runtime == "running" && dialErr == nil {
							return
						}
						if time.Now().After(deadline) {
							t.Fatalf("accepted authorization was not applied: %s", readLog())
						}
						time.Sleep(20 * time.Millisecond)
					}
				}
				awaitView(makeView(8, false).ViewDigest)
				denied := execute("curl", "--noproxy", "*", "--silent", "--fail", "--max-time", "2", "--cacert", trust, fmt.Sprintf("https://demo-service.example:%d/", port))
				if err := denied.Run(); err == nil {
					t.Fatal("removed authorization still permits business traffic")
				}
				if err := store.SaveLKG(makeView(9, true)); err != nil {
					t.Fatal(err)
				}
				if err := command.Process.Signal(syscall.SIGHUP); err != nil {
					t.Fatal(err)
				}
				awaitView(makeView(9, true).ViewDigest)
				business()
				if err := command.Process.Signal(syscall.SIGTERM); err != nil {
					t.Fatal(err)
				}
			}
			if failure == "executor_kill" {
				business() // Ending one application must not end this generation.
				if err := command.Process.Signal(syscall.SIGTERM); err != nil {
					t.Fatal(err)
				}
			}
			if failure == "data_plane_kill" || failure == "server_plane_kill" {
				// The existing model retains the authenticated repair channel
				// after an application failure, with all data-plane work stopped.
				deadline := time.Now().Add(5 * time.Second)
				for {
					current, err := ReadStatus(status)
					if err == nil && current.Runtime == "error" {
						break
					}
					if time.Now().After(deadline) {
						t.Fatalf("failed data plane did not report inactive: %s", readLog())
					}
					time.Sleep(20 * time.Millisecond)
				}
				if err := command.Process.Signal(syscall.SIGTERM); err != nil {
					t.Fatal(err)
				}
			}
			select {
			case err := <-stopped:
				if (failure == "normal_stop" || failure == "executor_kill") && err != nil {
					t.Fatalf("normal stop failed: %v %s", err, readLog())
				}
			case <-time.After(10 * time.Second):
				t.Fatal("runtime did not terminate")
			}
			dataPlane.wait(t)
			serverPlane.wait(t)
			address, _ := captureAddress(config)
			if connection, err := net.DialUnix("unixpacket", nil, address); err == nil {
				connection.Close()
				t.Fatal("stopped generation retained its application entry")
			}
			// Same persisted identity, view, preferences and path; no cleanup helper
			// or escape route is allowed between a failed process and its restart.
			command, stopped = start()
			business()
			if err := command.Process.Signal(syscall.SIGTERM); err != nil {
				t.Fatal(err)
			}
			select {
			case err := <-stopped:
				if err != nil {
					t.Fatalf("restarted generation stop: %v %s", err, readLog())
				}
			case <-time.After(10 * time.Second):
				t.Fatal("restarted generation did not stop")
			}
		})
	}
}

type tunTestProcess struct{ pid, fd int }

func tunTestChild(t *testing.T, parent int, isolated ...bool) tunTestProcess {
	t.Helper()
	for deadline := time.Now().Add(3 * time.Second); time.Now().Before(deadline); {
		paths, _ := filepath.Glob(fmt.Sprintf("/proc/%d/task/*/children", parent))
		for _, path := range paths {
			body, _ := os.ReadFile(path)
			for _, field := range strings.Fields(string(body)) {
				pid, err := strconv.Atoi(field)
				if err != nil {
					t.Fatal(err)
				}
				if len(isolated) != 0 {
					child, childErr := os.Stat(fmt.Sprintf("/proc/%d/ns/net", pid))
					host, hostErr := os.Stat("/proc/self/ns/net")
					if childErr != nil || hostErr != nil || !os.SameFile(child, host) != isolated[0] {
						continue
					}
				}
				fd, err := unix.PidfdOpen(pid, 0)
				if errors.Is(err, unix.ESRCH) {
					continue
				}
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = unix.PidfdSendSignal(fd, unix.SIGKILL, nil, 0); unix.Close(fd) })
				return tunTestProcess{pid, fd}
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("owned child process did not appear")
	return tunTestProcess{}
}

func (process tunTestProcess) wait(t *testing.T) {
	t.Helper()
	poll := []unix.PollFd{{Fd: int32(process.fd), Events: unix.POLLIN}}
	if n, err := unix.Poll(poll, 1000); err != nil || n != 1 || poll[0].Revents&unix.POLLIN == 0 {
		t.Fatalf("owned process did not terminate: %v", err)
	}
}

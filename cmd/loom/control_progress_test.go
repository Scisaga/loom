package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"loom/internal/controlplane"
	"loom/internal/wire"
)

func TestControlOperationProgressOverTLSDoesNotWaitForCommitLock(t *testing.T) {
	runtime, adminDir := progressTestRuntime(t)
	endpoint, client, address := progressTestServer(t, runtime, adminDir)
	status, err := fetchControlStatus(context.Background(), endpoint, client)
	if err != nil {
		t.Fatal(err)
	}
	request, err := newControlPingRequest(adminDir, endpoint, status, "demo-progress", runtime.now())
	if err != nil {
		t.Fatal(err)
	}
	paused, release := make(chan struct{}), make(chan struct{})
	runtime.checkpoint = func(phase controlplane.Phase) error {
		if phase == controlplane.PhaseCommittedNotCertified {
			close(paused)
			<-release
		}
		return nil
	}
	defer func() {
		select {
		case <-release:
		default:
			close(release)
		}
	}()
	encoded, _ := wire.MarshalCanonical(request)
	completed := make(chan error, 1)
	go func() {
		response, err := client.Post("https://"+address+controlplane.PrivateControlOperationPath,
			"application/json", bytes.NewReader(encoded))
		if err == nil {
			_, _ = io.Copy(io.Discard, response.Body)
			_ = response.Body.Close()
			if response.StatusCode != http.StatusOK {
				err = errors.New("demo-operation-failed")
			}
		}
		completed <- err
	}()
	select {
	case <-paused:
	case <-time.After(5 * time.Second):
		t.Fatal("未进入 commit/QC 边界")
	}
	progress := fetchOperationProgress(t, client, address, controlplane.PrivateControlOperationPath+"/"+request.RequestID)
	if progress.Writable || len(progress.Operations) != 1 || progress.Operations[0].Phase != controlplane.PhaseCommittedNotCertified || progress.Operations[0].Certified {
		t.Fatalf("QC 尚未形成却显示完成: %#v", progress)
	}
	response, err := client.Get("https://" + address + controlOperationsUIPath)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(response.Body)
	_ = response.Body.Close()
	if response.StatusCode != http.StatusOK || !strings.Contains(string(body), "committed_not_certified") {
		t.Fatal("管理 UI 未展示已提交但未认证的阶段")
	}
	close(release)
	if err := <-completed; err != nil {
		t.Fatal(err)
	}
	progress = fetchOperationProgress(t, client, address, controlplane.PrivateControlOperationPath)
	if len(progress.Operations) != 1 || !wire.EqualCanonical(progress.Operations[0].Phases, controlOperationPhases) || progress.Operations[0].Phase != controlplane.PhaseApplied {
		t.Fatalf("最终阶段未保留完整过程: %#v", progress)
	}
}

func TestControlOperationProgressRecoversAtEveryDurablePhase(t *testing.T) {
	for _, phase := range controlOperationPhases {
		t.Run(string(phase), func(t *testing.T) {
			runtime, adminDir := progressTestRuntime(t)
			peer := readAdminTestCertificate(t, filepath.Join(adminDir, controlAdminCertName))
			status := serveRuntimeStatus(t, runtime, peer)
			var endpoint controlAdminEndpointV1
			if err := readCanonicalFile(filepath.Join(adminDir, controlEndpointName), 4<<20, &endpoint); err != nil {
				t.Fatal(err)
			}
			submitted, err := newControlPingRequest(adminDir, endpoint, status, "demo-crash", runtime.now())
			if err != nil {
				t.Fatal(err)
			}
			runtime.checkpoint = func(reached controlplane.Phase) error {
				if reached == phase {
					return errors.New("demo-crash-after-fsync")
				}
				return nil
			}
			serveRuntimeOperation(t, runtime, peer, submitted, http.StatusServiceUnavailable)
			before := runtime.progress.Load().response.Operations[0]
			if before.Phase != phase {
				t.Fatalf("崩溃点与持久化进度不符: %s", before.Phase)
			}
			reopened, err := openControlRuntime(runtime.dir, runtime.now)
			if err != nil {
				t.Fatal(err)
			}
			progress := reopened.progress.Load().response
			if len(progress.Operations) != 1 || progress.Operations[0].RequestID != submitted.RequestID ||
				progress.Operations[0].Phase != controlplane.PhaseApplied || !progress.Operations[0].Certified {
				t.Fatalf("重启未恢复同一 operation: %#v", progress)
			}
			if phase != controlplane.PhasePending && progress.Operations[0].HeadHash != before.HeadHash {
				t.Fatal("已提交的 Head 被重算成另一个结果")
			}
			if len(reopened.journal.Records) != 1 || reopened.journal.Records[0].Result.OperationTreeSize != 1 {
				t.Fatal("重试产生了第二个生效结果")
			}
		})
	}
}

func TestControlOperationProgressRejectsOtherListenersAndAnonymousReaders(t *testing.T) {
	runtime, adminDir := progressTestRuntime(t)
	_, client, address := progressTestServer(t, runtime, adminDir)
	for _, path := range []string{controlplane.PrivateControlOperationPath, controlOperationsUIPath} {
		request := httptest.NewRequest(http.MethodGet, "https://"+address+path, nil)
		request = request.WithContext(context.WithValue(request.Context(), http.LocalAddrContextKey, controlTestAddress("203.0.113.10:17444")))
		request.TLS = &tls.ConnectionState{Version: tls.VersionTLS13, HandshakeComplete: true}
		response := httptest.NewRecorder()
		runtime.controlHandler().ServeHTTP(response, request)
		if response.Code == http.StatusOK {
			t.Fatal("公开 listener 可以读取操作状态")
		}
	}
	for _, suffix := range []string{"?token=demo", "/missing"} {
		response, err := client.Get("https://" + address + controlplane.PrivateControlOperationPath + suffix)
		if err != nil {
			t.Fatal(err)
		}
		_ = response.Body.Close()
		if response.StatusCode == http.StatusOK {
			t.Fatal("未经声明的查询或 ID 被接受")
		}
	}
}

func progressTestRuntime(t *testing.T) (*controlRuntime, string) {
	t.Helper()
	root := t.TempDir()
	stateDir, adminDir := filepath.Join(root, "state"), filepath.Join(root, "admin")
	now := time.Now().UTC().Truncate(time.Second)
	clock := func() time.Time { return now }
	if err := bootstrapControlRuntime(stateDir, adminDir, "demo-progress", "00000000000000000000000000", "demo-device", "10.40.0.2", 17444, 17445, clock); err != nil {
		t.Fatal(err)
	}
	runtime, err := openControlRuntime(stateDir, clock)
	if err != nil {
		t.Fatal(err)
	}
	return runtime, adminDir
}

type controlProgressTestListener struct {
	net.Listener
	address string
}
type controlProgressTestConn struct {
	net.Conn
	address string
}

func (listener *controlProgressTestListener) Addr() net.Addr {
	return controlTestAddress(listener.address)
}
func (connection *controlProgressTestConn) LocalAddr() net.Addr {
	return controlTestAddress(connection.address)
}
func (listener *controlProgressTestListener) Accept() (net.Conn, error) {
	connection, err := listener.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return &controlProgressTestConn{Conn: connection, address: listener.address}, nil
}

func progressTestServer(t *testing.T, runtime *controlRuntime, adminDir string) (controlAdminEndpointV1, *http.Client, string) {
	t.Helper()
	endpoint, client, err := loadControlAdminClient(adminDir)
	if err != nil {
		t.Fatal(err)
	}
	address := net.JoinHostPort(runtime.config.OverlayIP, strconv.FormatInt(runtime.config.ControlPort, 10))
	server := httptest.NewUnstartedServer(runtime.controlHandler())
	loopback := server.Listener.Addr().String()
	server.Listener = &controlProgressTestListener{Listener: server.Listener, address: address}
	server.TLS = runtime.controlServerTLSConfig(runtime.controlTLS)
	server.StartTLS()
	t.Cleanup(server.Close)
	transport := client.Transport.(*http.Transport)
	transport.DialContext = func(ctx context.Context, network, requested string) (net.Conn, error) {
		if requested != address {
			return nil, errors.New("demo-wrong-tuple")
		}
		return (&net.Dialer{}).DialContext(ctx, network, loopback)
	}
	client.Timeout = 3 * time.Second
	t.Cleanup(client.CloseIdleConnections)
	return endpoint, client, address
}

func fetchOperationProgress(t *testing.T, client *http.Client, address, path string) controlOperationProgressResponseV1 {
	t.Helper()
	response, err := client.Get("https://" + address + path)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil || response.StatusCode != http.StatusOK {
		t.Fatalf("进度读取失败: status=%d err=%v", response.StatusCode, err)
	}
	var progress controlOperationProgressResponseV1
	if _, err := wire.DecodeStrict(body, controlMaxResponseSize, &progress); err != nil {
		t.Fatal(err)
	}
	return progress
}

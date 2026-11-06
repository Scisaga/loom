package linuxclient

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"loom/internal/netx"
)

const nativeMultiForwardWorkerMarker = "--demo-native-multiforward-socket-worker"

// This small opt-in proof exercises only fixture transport, without a native
// runtime, probe samples or business facts. The runner supplies fresh outer
// user/network/mount namespaces just as for the actual acceptance.
func TestNativeMultiForwardSocketBridge(t *testing.T) {
	marker := false
	for _, argument := range os.Args {
		marker = marker || argument == "--demo-native-multiforward-socket-proof"
	}
	if !marker {
		t.Skip("socket proof requires the explicitly isolated fixture runner")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	pins, err := nativeMultiForwardOuterPins()
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		for _, pin := range pins {
			_ = pin.Close()
		}
	}()
	if _, err := nativeMultiForwardNetworkBoundary(true); err != nil {
		t.Fatal(err)
	}
	if err := exec.Command("ip", "link", "set", "lo", "up").Run(); err != nil {
		t.Fatal(err)
	}
	evidence := t.TempDir()
	if output := flag.Lookup("test.outputdir"); output != nil && output.Value.String() != "" {
		evidence = filepath.Join(output.Value.String(), "native-multiforward-network-proof")
		if err := os.Mkdir(evidence, 0700); err != nil {
			t.Fatal(err)
		}
	}
	a := newNativeMultiForwardNS(t, ctx, "demo-a", evidence, nil)
	b := newNativeMultiForwardNS(t, ctx, "demo-b", evidence, nil)
	if a.Cookie == b.Cookie || a.namespaceID == b.namespaceID {
		t.Fatal("independent nodes share their socket namespace")
	}
	for _, node := range []*nativeMultiForwardNS{a, b} {
		for _, port := range []string{"61800", "1080"} {
			if _, err := node.ListenTCP(net.JoinHostPort("127.0.0.1", port)); err != nil {
				t.Fatal("fixed native ports did not coexist", err)
			}
		}
		body, err := node.Command(ctx, "readlink", "/proc/self/ns/net").Output()
		if err != nil || strings.TrimSpace(string(body)) != node.namespaceID {
			t.Fatal("namespace descriptor did not confine the complete child process", err)
		}
	}
	target, err := b.ListenUDP("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	_ = target.SetDeadline(time.Now().Add(5 * time.Second))
	var delay atomic.Int64
	udp := StartNativeMultiForwardUDPBridge(t, ctx, a, b, "127.0.0.1:0", target.LocalAddr().String(), &delay)
	var clients []*net.UDPConn
	for i := 0; i < 2; i++ {
		client, err := a.DialUDP(udp.Address)
		if err != nil {
			t.Fatal(err)
		}
		_ = client.SetDeadline(time.Now().Add(5 * time.Second))
		clients = append(clients, client)
	}
	peers := map[string]string{}
	buffer := make([]byte, 65535)
	for index, payload := range [][]byte{nil, []byte("demo-binary\x00\xff"), bytes.Repeat([]byte{0, 255, 127}, 1024), []byte("demo-final")} {
		client := clients[index%2]
		if index == 1 {
			delay.Store(int64(15 * time.Millisecond))
		}
		started := time.Now()
		if _, err := client.Write(payload); err != nil {
			t.Fatal(err)
		}
		n, peer, err := target.ReadFromUDPAddrPort(buffer)
		if err != nil || !bytes.Equal(buffer[:n], payload) {
			t.Fatal("UDP bridge changed a datagram", err)
		}
		id := client.LocalAddr().String()
		if previous := peers[id]; previous != "" && previous != peer.String() {
			t.Fatal("UDP source lost its stable owner-side peer")
		}
		peers[id] = peer.String()
		reply := append([]byte("demo-reply:"), payload...)
		if _, err := target.WriteToUDPAddrPort(reply, peer); err != nil {
			t.Fatal(err)
		}
		n, err = client.Read(buffer)
		if err != nil || !bytes.Equal(buffer[:n], reply) || index > 0 && time.Since(started) < 30*time.Millisecond {
			t.Fatal("UDP return bytes or actual mutable wire delay were lost", err)
		}
	}
	if len(peers) != 2 || peers[clients[0].LocalAddr().String()] == peers[clients[1].LocalAddr().String()] {
		t.Fatal("UDP sources share their owner-side socket")
	}
	udp.Close(t)
	tcpTarget, err := b.ListenTCP("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	tcp := StartNativeMultiForwardTCPBridge(t, ctx, a, b, "127.0.0.1:0", tcpTarget.Addr().String())
	client, err := a.DialTCP(tcp.Address)
	if err != nil {
		t.Fatal(err)
	}
	_ = tcpTarget.SetDeadline(time.Now().Add(5 * time.Second))
	server, err := tcpTarget.AcceptTCP()
	if err != nil {
		t.Fatal(err)
	}
	if err := b.retain(server); err != nil {
		t.Fatal(err)
	}
	_ = server.SetDeadline(time.Now().Add(5 * time.Second))
	_ = client.SetDeadline(time.Now().Add(5 * time.Second))
	payload := bytes.Repeat([]byte("demo-stream\x00\xff"), 2048)
	reply := append([]byte("demo-half-close:"), payload...)
	served := make(chan error, 1)
	go func() {
		body, err := io.ReadAll(server)
		if err == nil && !bytes.Equal(body, payload) {
			err = errors.New("TCP bridge changed request bytes")
		}
		if err == nil {
			_, err = server.Write(reply)
		}
		if err == nil {
			err = server.CloseWrite()
		}
		served <- err
	}()
	if _, err := client.Write(payload); err != nil {
		t.Fatal(err)
	}
	if err := client.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(client)
	if err != nil || !bytes.Equal(body, reply) {
		t.Fatal("TCP half-close truncated its return stream", err)
	}
	if err := <-served; err != nil {
		t.Fatal(err)
	}
	tcp.Close(t)
	// The existing control CLI stays in the isolated outer namespace. Its
	// bridge has an explicit loopback-only entry, never an absent owner fallback.
	outerTarget, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = outerTarget.Close() })
	_ = outerTarget.SetDeadline(time.Now().Add(5 * time.Second))
	outerBridge := StartNativeMultiForwardTCPBridgeToOuter(t, ctx, a, "127.0.0.1:0", outerTarget.Addr().String())
	outerClient, err := a.DialTCP(outerBridge.Address)
	if err != nil {
		t.Fatal(err)
	}
	_ = outerClient.SetDeadline(time.Now().Add(5 * time.Second))
	outerServer, err := outerTarget.AcceptTCP()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = outerServer.Close() })
	if _, err := outerServer.Write([]byte("demo-outer-control")); err != nil {
		t.Fatal(err)
	}
	if err := outerServer.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	body, err = io.ReadAll(outerClient)
	if err != nil || string(body) != "demo-outer-control" {
		t.Fatal("explicit outer control bridge changed the stream", err)
	}
	outerBridge.Close(t)
	a.Close(t)
	b.Close(t)
	if err := writeNativeForwardEvidence(filepath.Join(evidence, "socket-proof.json"), map[string]any{"pass": true, "fixed_ports_coexist": true, "fd_namespace_cookies_differ": true, "udp_independent_stable_peers": len(peers), "udp_datagrams_including_empty": 4, "mutable_delay_changes_real_bytes_timing": true, "tcp_binary_equal_and_half_close": true, "explicit_outer_loopback_control_stream": true}); err != nil {
		t.Fatal(err)
	}
}

// This worker owns only a fresh loopback network. It creates sockets there and
// transfers their descriptors; neither the parent nor its Go threads use setns.
// Requests never contain business observations, selectors, or executable code.
func TestNativeMultiForwardNetworkWorker(t *testing.T) {
	index := -1
	for i, argument := range os.Args {
		if argument == nativeMultiForwardWorkerMarker {
			index = i
		}
	}
	if index < 0 {
		t.Skip("socket worker runs only as an explicitly isolated test child")
	}
	if index+2 != len(os.Args)-1 {
		t.Fatal("socket worker requires its label and loopback address list")
	}
	// ExtraFiles arrive without CLOEXEC. No setup subprocess may inherit the
	// control endpoint or the three parent namespace proofs.
	for fd := 3; fd <= 6; fd++ {
		unix.CloseOnExec(fd)
	}
	var addresses []netip.Addr
	if err := json.Unmarshal([]byte(os.Args[index+2]), &addresses); err != nil {
		t.Fatal(err)
	}
	for i, kind := range []string{"user", "net", "mnt"} {
		current, err := os.Stat("/proc/self/ns/" + kind)
		parent, parentErr := os.Stat(fmt.Sprintf("/proc/self/fd/%d", i+4))
		if err != nil || parentErr != nil || os.SameFile(current, parent) != (kind != "net") {
			t.Fatal("socket worker did not retain its parent's user/mount and separate network namespace")
		}
		if err := unix.Close(i + 4); err != nil {
			t.Fatal("close verified parent namespace proof", err)
		}
	}
	boundary, err := nativeMultiForwardNetworkBoundary(true)
	if err != nil {
		t.Fatal(err)
	}
	// A synthetic public address is permitted only after the fresh namespace
	// has been proved to contain lo alone and no route of either family.
	for _, address := range addresses {
		if !address.Is4() || !netx.IsPublicInternetAddress(address) {
			t.Fatal("socket worker accepts only the isolated fixture's public IPv4 addresses")
		}
	}
	if body, err := exec.Command("ip", "link", "set", "lo", "up").CombinedOutput(); err != nil {
		t.Fatalf("enable isolated loopback: %v %s", err, body)
	}
	for _, address := range addresses {
		if body, err := exec.Command("ip", "address", "add", netip.PrefixFrom(address, 32).String(), "dev", "lo").CombinedOutput(); err != nil {
			t.Fatalf("bind isolated fixture address: %v %s", err, body)
		}
	}
	controlFile := os.NewFile(3, "demo-socket-control")
	connection, err := net.FileConn(controlFile)
	_ = controlFile.Close()
	if err != nil {
		t.Fatal(err)
	}
	control := connection.(*net.UnixConn)
	defer control.Close()
	namespace, err := os.Open("/proc/self/ns/net")
	if err != nil {
		t.Fatal(err)
	}
	defer namespace.Close()
	probe, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	cookie, cookieErr := unix.GetsockoptUint64(probe, unix.SOL_SOCKET, unix.SO_NETNS_COOKIE)
	_ = unix.Close(probe)
	if cookieErr != nil || cookie == 0 {
		t.Fatal("kernel cannot prove namespace ownership of transferred sockets", cookieErr)
	}
	if err := nativeMultiForwardSend(control, nativeMultiForwardSocketReply{Cookie: cookie, Boundary: boundary}, namespace); err != nil {
		t.Fatal(err)
	}
	for {
		var request nativeMultiForwardSocketRequest
		file, err := nativeMultiForwardReceive(control, &request)
		if errors.Is(err, io.EOF) {
			return
		}
		if file != nil {
			_ = file.Close()
			t.Fatal("socket worker received an unexpected descriptor")
		}
		if err != nil {
			t.Fatal(err)
		}
		if request.Operation == "close" {
			if err := nativeMultiForwardSend(control, nativeMultiForwardSocketReply{}, nil); err != nil {
				t.Fatal(err)
			}
			return
		}
		file, err = nativeMultiForwardCreateSocket(request)
		reply := nativeMultiForwardSocketReply{Cookie: cookie}
		if err != nil {
			reply.Error = err.Error()
		}
		err = nativeMultiForwardSend(control, reply, file)
		if file != nil {
			_ = file.Close()
		}
		if err != nil {
			t.Fatal(err)
		}
	}
}

type nativeMultiForwardSocketRequest struct {
	Operation string
	Network   string
	Address   string
}

type nativeMultiForwardSocketReply struct {
	Error    string
	Cookie   uint64
	Boundary map[string]any
}

func nativeMultiForwardNetworkBoundary(fresh bool) (map[string]any, error) {
	interfaces, err := net.Interfaces()
	if err != nil || len(interfaces) != 1 || interfaces[0].Name != "lo" || interfaces[0].Flags&net.FlagLoopback == 0 || fresh && interfaces[0].Flags&net.FlagUp != 0 {
		return nil, errors.New("socket fixture requires only its isolated loopback")
	}
	result := map[string]any{}
	for _, kind := range []string{"user", "net", "mnt"} {
		result[kind], err = os.Readlink("/proc/self/ns/" + kind)
		if err != nil {
			return nil, err
		}
	}
	for _, family := range []string{"-4", "-6"} {
		body, err := exec.Command("ip", "-json", family, "route", "show", "table", "all").Output()
		var routes []struct {
			Destination string `json:"dst"`
			Device      string `json:"dev"`
		}
		if err != nil || json.Unmarshal(body, &routes) != nil || fresh && len(routes) != 0 {
			return nil, errors.New("could not prove an empty fresh routing namespace")
		}
		for _, route := range routes {
			if route.Device != "" && route.Device != "lo" || route.Destination == "default" || route.Destination == "0.0.0.0/0" || route.Destination == "::/0" {
				return nil, errors.New("socket fixture has an external or default route")
			}
		}
		result[family] = json.RawMessage(body)
	}
	return result, nil
}

func nativeMultiForwardSend(connection *net.UnixConn, value any, file *os.File) error {
	body, err := json.Marshal(value)
	if err != nil {
		return err
	}
	var rights []byte
	if file != nil {
		rights = unix.UnixRights(int(file.Fd()))
	}
	n, oob, err := connection.WriteMsgUnix(body, rights, nil)
	if err == nil && (n != len(body) || oob != len(rights)) {
		err = io.ErrShortWrite
	}
	return err
}

func nativeMultiForwardReceive(connection *net.UnixConn, value any) (*os.File, error) {
	var body [8192]byte
	rights := make([]byte, unix.CmsgSpace(4))
	n, oob, flags, _, err := connection.ReadMsgUnix(body[:], rights)
	if err != nil {
		return nil, err
	}
	if n == 0 {
		return nil, io.EOF
	}
	messages, err := unix.ParseSocketControlMessage(rights[:oob])
	if err != nil {
		return nil, err
	}
	var files []int
	for _, message := range messages {
		descriptors, err := unix.ParseUnixRights(&message)
		if err != nil {
			for _, fd := range files {
				_ = unix.Close(fd)
			}
			return nil, err
		}
		files = append(files, descriptors...)
	}
	if flags&(unix.MSG_TRUNC|unix.MSG_CTRUNC) != 0 || len(files) > 1 {
		for _, fd := range files {
			_ = unix.Close(fd)
		}
		return nil, errors.New("socket descriptor message was truncated or ambiguous")
	}
	var file *os.File
	if len(files) == 1 {
		unix.CloseOnExec(files[0])
		file = os.NewFile(uintptr(files[0]), "demo-transferred-socket")
	}
	if err := json.Unmarshal(body[:n], value); err != nil {
		if file != nil {
			_ = file.Close()
		}
		return nil, err
	}
	return file, nil
}

func nativeMultiForwardCreateSocket(request nativeMultiForwardSocketRequest) (*os.File, error) {
	address, err := netip.ParseAddrPort(request.Address)
	if err != nil || !address.Addr().Is4() || request.Network != "udp4" && request.Network != "tcp4" || request.Operation != "listen" && request.Operation != "dial" {
		return nil, errors.New("socket fixture requires a numeric IPv4 TCP/UDP listen or dial")
	}
	// Sockets can target only addresses already assigned to this worker's lo.
	addresses, err := net.InterfaceByName("lo")
	if err != nil {
		return nil, err
	}
	assigned, err := addresses.Addrs()
	if err != nil {
		return nil, err
	}
	found := false
	for _, assignedAddress := range assigned {
		prefix, err := netip.ParsePrefix(assignedAddress.String())
		found = found || err == nil && prefix.Contains(address.Addr())
	}
	if !found {
		return nil, errors.New("socket address is outside this worker's loopback")
	}
	if request.Network == "udp4" {
		var connection *net.UDPConn
		if request.Operation == "listen" {
			connection, err = net.ListenUDP("udp4", net.UDPAddrFromAddrPort(address))
		} else {
			connection, err = net.DialUDP("udp4", nil, net.UDPAddrFromAddrPort(address))
		}
		if err != nil {
			return nil, err
		}
		defer connection.Close()
		return connection.File()
	}
	if request.Operation == "listen" {
		listener, err := net.ListenTCP("tcp4", net.TCPAddrFromAddrPort(address))
		if err != nil {
			return nil, err
		}
		defer listener.Close()
		return listener.File()
	}
	connection, err := net.DialTimeout("tcp4", request.Address, 3*time.Second)
	if err != nil {
		return nil, err
	}
	defer connection.Close()
	return connection.(*net.TCPConn).File()
}

type nativeMultiForwardNS struct {
	label, evidence string
	Namespace       *os.File
	Cookie          uint64
	parentCookie    uint64
	control         *net.UnixConn
	process         *exec.Cmd
	done            chan error
	closed          chan struct{}
	mu              sync.Mutex
	sockets         []io.Closer
	closeOnce       sync.Once
	closeError      error
	cleanup         map[string]any
	namespaceID     string
}

func nativeMultiForwardOuterPins() (pins []*os.File, retErr error) {
	defer func() {
		if retErr != nil {
			for _, pin := range pins {
				_ = pin.Close()
			}
		}
	}()
	for _, kind := range []string{"user", "net", "mnt"} {
		pin, err := os.Open("/proc/self/ns/" + kind)
		if err != nil {
			return pins, err
		}
		pins = append(pins, pin)
		current, err := pin.Stat()
		initial, initialErr := os.Stat("/proc/1/ns/" + kind)
		if err != nil || initialErr != nil || os.SameFile(current, initial) {
			return pins, errors.New("socket fixture requires separate outer user, network and mount namespaces")
		}
	}
	return pins, nil
}

func newNativeMultiForwardNS(t *testing.T, ctx context.Context, label, evidence string, addresses []netip.Addr) *nativeMultiForwardNS {
	t.Helper()
	if filepath.Base(label) != label || !strings.HasPrefix(label, "demo-") {
		t.Fatal("socket fixture requires a single demo label")
	}
	if info, err := os.Stat(evidence); err != nil || !info.IsDir() || info.Mode().Perm()&0077 != 0 {
		t.Fatal("socket fixture evidence requires an owner-only directory")
	}
	if _, err := nativeMultiForwardNetworkBoundary(false); err != nil {
		t.Fatal(err)
	}
	pins, err := nativeMultiForwardOuterPins()
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		for _, pin := range pins {
			_ = pin.Close()
		}
	}()
	pair, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	parent, child := os.NewFile(uintptr(pair[0]), "demo-parent-control"), os.NewFile(uintptr(pair[1]), "demo-child-control")
	defer parent.Close()
	defer child.Close()
	connection, err := net.FileConn(parent)
	if err != nil {
		t.Fatal(err)
	}
	n := &nativeMultiForwardNS{label: label, evidence: evidence, control: connection.(*net.UnixConn), done: make(chan error, 1), closed: make(chan struct{})}
	t.Cleanup(func() { n.Close(t) })
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(addresses)
	if err != nil {
		t.Fatal(err)
	}
	log, err := os.OpenFile(filepath.Join(evidence, label+"-socket-worker.log"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	defer log.Close()
	n.process = exec.Command(binary, "-test.run=^TestNativeMultiForwardNetworkWorker$", "-test.v", "--", nativeMultiForwardWorkerMarker, label, string(encoded))
	n.process.ExtraFiles = append([]*os.File{child}, pins...)
	// The private control endpoint has no other inheritor. Parent exit closes
	// it and the worker returns on EOF; Pdeathsig would bind its lifetime to
	// the transient Go OS thread that happened to create it.
	n.process.SysProcAttr = &syscall.SysProcAttr{Cloneflags: syscall.CLONE_NEWNET}
	n.process.Stdout, n.process.Stderr = log, log
	if err := n.process.Start(); err != nil {
		t.Fatal(err)
	}
	_ = child.Close()
	go func() { n.done <- n.process.Wait() }()
	_ = n.control.SetDeadline(time.Now().Add(5 * time.Second))
	var reply nativeMultiForwardSocketReply
	n.Namespace, err = nativeMultiForwardReceive(n.control, &reply)
	if err != nil || n.Namespace == nil || reply.Error != "" || reply.Cookie == 0 {
		t.Fatal("isolated socket worker did not provide its namespace evidence", err, reply.Error)
	}
	if kind, err := unix.IoctlRetInt(int(n.Namespace.Fd()), unix.NS_GET_NSTYPE); err != nil || kind != unix.CLONE_NEWNET {
		t.Fatal("socket worker did not transfer a network namespace descriptor", err)
	}
	n.namespaceID, err = os.Readlink(fmt.Sprintf("/proc/self/fd/%d", n.Namespace.Fd()))
	parentID, parentErr := os.Readlink("/proc/self/ns/net")
	if err != nil || parentErr != nil || n.namespaceID == parentID || n.namespaceID != reply.Boundary["net"] {
		t.Fatal("socket worker namespace descriptor does not match its isolated boundary")
	}
	probe, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	parentCookie, err := unix.GetsockoptUint64(probe, unix.SOL_SOCKET, unix.SO_NETNS_COOKIE)
	_ = unix.Close(probe)
	if err != nil || parentCookie == reply.Cookie {
		t.Fatal("socket worker retained the parent's socket network namespace", err)
	}
	n.Cookie = reply.Cookie
	n.parentCookie = parentCookie
	if err := writeNativeForwardEvidence(filepath.Join(evidence, label+"-network-boundary.json"), reply); err != nil {
		t.Fatal(err)
	}
	go func() {
		select {
		case <-ctx.Done():
			n.close()
		case <-n.closed:
		}
	}()
	return n
}

func (n *nativeMultiForwardNS) socket(operation, network, address string) (*os.File, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	select {
	case <-n.closed:
		return nil, net.ErrClosed
	default:
	}
	_ = n.control.SetDeadline(time.Now().Add(5 * time.Second))
	if err := nativeMultiForwardSend(n.control, nativeMultiForwardSocketRequest{operation, network, address}, nil); err != nil {
		return nil, err
	}
	var reply nativeMultiForwardSocketReply
	file, err := nativeMultiForwardReceive(n.control, &reply)
	if err != nil {
		return nil, err
	}
	if reply.Error != "" {
		if file != nil {
			_ = file.Close()
		}
		return nil, errors.New(reply.Error)
	}
	if file == nil {
		return nil, errors.New("socket worker omitted its socket descriptor")
	}
	cookie, err := unix.GetsockoptUint64(int(file.Fd()), unix.SOL_SOCKET, unix.SO_NETNS_COOKIE)
	if err != nil || cookie != n.Cookie || reply.Cookie != n.Cookie {
		_ = file.Close()
		return nil, errors.New("transferred socket belongs to another network namespace")
	}
	return file, nil
}

func (n *nativeMultiForwardNS) connection(operation, network, address string) (net.Conn, error) {
	file, err := n.socket(operation, network, address)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	connection, err := net.FileConn(file)
	if err == nil {
		err = n.retain(connection)
	}
	return connection, err
}

func (n *nativeMultiForwardNS) retain(connection io.Closer) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	select {
	case <-n.closed:
		_ = connection.Close()
		return net.ErrClosed
	default:
		n.sockets = append(n.sockets, connection)
		return nil
	}
}

func (n *nativeMultiForwardNS) ListenUDP(address string) (*net.UDPConn, error) {
	connection, err := n.connection("listen", "udp4", address)
	if err != nil {
		return nil, err
	}
	return connection.(*net.UDPConn), nil
}

func (n *nativeMultiForwardNS) DialUDP(address string) (*net.UDPConn, error) {
	connection, err := n.connection("dial", "udp4", address)
	if err != nil {
		return nil, err
	}
	return connection.(*net.UDPConn), nil
}

func (n *nativeMultiForwardNS) DialTCP(address string) (*net.TCPConn, error) {
	connection, err := n.connection("dial", "tcp4", address)
	if err != nil {
		return nil, err
	}
	return connection.(*net.TCPConn), nil
}

func (n *nativeMultiForwardNS) ListenTCP(address string) (*net.TCPListener, error) {
	file, err := n.socket("listen", "tcp4", address)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	listener, err := net.FileListener(file)
	if err != nil {
		return nil, err
	}
	if err := n.retain(listener); err != nil {
		return nil, err
	}
	return listener.(*net.TCPListener), nil
}

func (n *nativeMultiForwardNS) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if network != "tcp" && network != "tcp4" {
		return nil, errors.New("fixture HTTP dialer supports numeric IPv4 TCP only")
	}
	return n.DialTCP(address)
}

// The immutable descriptor pins the owned namespace across CLI start/exit.
// The caller owns the CLI's normal stop and Wait, before this fixture closes.
func (n *nativeMultiForwardNS) Command(ctx context.Context, binary string, arguments ...string) *exec.Cmd {
	command := exec.CommandContext(ctx, "nsenter", append([]string{"--net=/proc/self/fd/3", "--", binary}, arguments...)...)
	command.ExtraFiles = []*os.File{n.Namespace}
	return command
}

func (n *nativeMultiForwardNS) close() {
	n.closeOnce.Do(func() {
		n.mu.Lock()
		defer n.mu.Unlock()
		close(n.closed)
		allClosed := true
		for _, socket := range n.sockets {
			_ = socket.Close()
			allClosed = nativeMultiForwardSocketClosed(socket) && allClosed
		}
		if n.Namespace != nil {
			_ = n.Namespace.Close()
		}
		cleanExit := false
		if n.process != nil && n.process.Process != nil {
			_ = n.control.SetDeadline(time.Now().Add(5 * time.Second))
			err := nativeMultiForwardSend(n.control, nativeMultiForwardSocketRequest{Operation: "close"}, nil)
			var reply nativeMultiForwardSocketReply
			if err == nil {
				var file *os.File
				file, err = nativeMultiForwardReceive(n.control, &reply)
				if file != nil {
					_ = file.Close()
					err = errors.New("close acknowledgment contained a descriptor")
				}
			}
			_ = n.control.Close()
			select {
			case waitErr := <-n.done:
				cleanExit = err == nil && waitErr == nil
				if waitErr != nil {
					n.closeError = waitErr
				}
			case <-time.After(5 * time.Second):
				_ = n.process.Process.Kill()
				<-n.done
				n.closeError = errors.New("socket worker required forced termination")
			}
			if err != nil && n.closeError == nil {
				n.closeError = err
			}
		} else {
			_ = n.control.Close()
		}
		pid := 0
		if n.process != nil && n.process.Process != nil {
			pid = n.process.Process.Pid
		}
		n.cleanup = map[string]any{"label": n.label, "worker_pid": pid, "worker_normal_exit": cleanExit, "namespace": n.namespaceID, "namespace_fd_closed": n.Namespace == nil || n.Namespace.Fd() == ^uintptr(0), "socket_handles": len(n.sockets), "all_socket_fds_closed": allClosed, "control_fd_closed": nativeMultiForwardSocketClosed(n.control)}
		if !allClosed && n.closeError == nil {
			n.closeError = errors.New("socket fixture left an open descriptor")
		}
	})
}

func nativeMultiForwardSocketClosed(connection io.Closer) bool {
	owner, ok := connection.(syscall.Conn)
	if !ok {
		return false
	}
	raw, err := owner.SyscallConn()
	if err == nil {
		err = raw.Control(func(uintptr) {})
	}
	return errors.Is(err, net.ErrClosed)
}

func (n *nativeMultiForwardNS) Close(t *testing.T) {
	t.Helper()
	n.close()
	if err := writeNativeForwardEvidence(filepath.Join(n.evidence, n.label+"-network-cleanup.json"), n.cleanup); err != nil {
		t.Error(err)
	}
	if n.closeError != nil {
		t.Error("isolated socket worker cleanup", n.closeError)
	}
}

type nativeMultiForwardBridge struct {
	Address     string
	stop        chan struct{}
	closeOnce   sync.Once
	mu          sync.Mutex
	connections []io.Closer
	workers     sync.WaitGroup
	packets     atomic.Uint64
	peerCount   atomic.Uint64
	filename    string
}

func (b *nativeMultiForwardBridge) pause(ctx context.Context, delay *atomic.Int64) bool {
	timer := time.NewTimer(time.Duration(delay.Load()))
	defer timer.Stop()
	select {
	case <-timer.C:
		return true
	case <-ctx.Done():
	case <-b.stop:
	}
	return false
}

func (b *nativeMultiForwardBridge) add(connection io.Closer) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	select {
	case <-b.stop:
		_ = connection.Close()
		return false
	default:
		b.connections = append(b.connections, connection)
		return true
	}
}

func (b *nativeMultiForwardBridge) close() {
	b.closeOnce.Do(func() {
		b.mu.Lock()
		close(b.stop)
		for _, connection := range b.connections {
			_ = connection.Close()
		}
		b.mu.Unlock()
		b.workers.Wait()
	})
}

func (b *nativeMultiForwardBridge) Close(t *testing.T) {
	t.Helper()
	b.close()
	if err := writeNativeForwardEvidence(b.filename, map[string]any{"address": b.Address, "peers": b.peerCount.Load(), "datagrams_forwarded": b.packets.Load(), "connection_handles_closed": len(b.connections), "workers_exited": true}); err != nil {
		t.Error(err)
	}
}

// P belongs to the source namespace; Q is the owner's unmodified native
// listener. Each source tuple gets one stable Q-side socket in the owner netns.
func StartNativeMultiForwardUDPBridge(t *testing.T, ctx context.Context, source, owner *nativeMultiForwardNS, publicAddress, localAddress string, delay *atomic.Int64) *nativeMultiForwardBridge {
	t.Helper()
	listener, err := source.ListenUDP(publicAddress)
	if err != nil {
		t.Fatal(err)
	}
	b := &nativeMultiForwardBridge{Address: listener.LocalAddr().String(), stop: make(chan struct{})}
	b.filename = filepath.Join(source.evidence, source.label+"-udp-"+strconv.Itoa(listener.LocalAddr().(*net.UDPAddr).Port)+"-bridge-cleanup.json")
	b.add(listener)
	t.Cleanup(func() { b.Close(t) })
	b.workers.Add(1)
	go func() {
		defer b.workers.Done()
		peers := map[netip.AddrPort]*net.UDPConn{}
		buffer := make([]byte, 65535)
		for {
			n, peer, err := listener.ReadFromUDPAddrPort(buffer)
			if err != nil {
				return
			}
			upstream := peers[peer]
			if upstream == nil {
				upstream, err = owner.DialUDP(localAddress)
				if err != nil || !b.add(upstream) {
					return
				}
				peers[peer] = upstream
				b.peerCount.Add(1)
				b.workers.Add(1)
				go func(connection *net.UDPConn, destination netip.AddrPort) {
					defer b.workers.Done()
					data := make([]byte, 65535)
					for {
						count, err := connection.Read(data)
						if errors.Is(err, syscall.ECONNREFUSED) {
							continue // Q may not have started its normal listener yet.
						}
						if err != nil || !b.pause(ctx, delay) {
							return
						}
						if _, err := listener.WriteToUDPAddrPort(data[:count], destination); err != nil {
							return
						}
						b.packets.Add(1)
					}
				}(upstream, peer)
			}
			if !b.pause(ctx, delay) {
				return
			}
			if _, err := upstream.Write(buffer[:n]); err == nil {
				b.packets.Add(1)
			}
		}
	}()
	go func() {
		select {
		case <-ctx.Done():
			b.close()
		case <-b.stop:
		}
	}()
	return b
}

// The stream bridge preserves EOF in each direction independently. It never
// interprets HTTP/TLS or selects a business path.
func StartNativeMultiForwardTCPBridge(t *testing.T, ctx context.Context, source, owner *nativeMultiForwardNS, publicAddress, localAddress string) *nativeMultiForwardBridge {
	t.Helper()
	return startNativeMultiForwardTCPBridge(t, ctx, source, publicAddress, func() (*net.TCPConn, error) { return owner.DialTCP(localAddress) })
}

func StartNativeMultiForwardTCPBridgeToOuter(t *testing.T, ctx context.Context, source *nativeMultiForwardNS, publicAddress, outerLoopbackQ string) *nativeMultiForwardBridge {
	t.Helper()
	address, err := netip.ParseAddrPort(outerLoopbackQ)
	if err != nil || !address.Addr().Is4() || !address.Addr().IsLoopback() || address.Port() == 0 {
		t.Fatal("outer control bridge requires its explicit numeric IPv4 loopback listener")
	}
	if _, err := nativeMultiForwardNetworkBoundary(false); err != nil {
		t.Fatal(err)
	}
	return startNativeMultiForwardTCPBridge(t, ctx, source, publicAddress, func() (*net.TCPConn, error) {
		connection, err := net.DialTimeout("tcp4", outerLoopbackQ, 3*time.Second)
		if err != nil {
			return nil, err
		}
		raw, err := connection.(*net.TCPConn).SyscallConn()
		var cookie uint64
		var optionError error
		if err == nil {
			err = raw.Control(func(fd uintptr) {
				cookie, optionError = unix.GetsockoptUint64(int(fd), unix.SOL_SOCKET, unix.SO_NETNS_COOKIE)
			})
		}
		if err != nil || optionError != nil || cookie != source.parentCookie {
			_ = connection.Close()
			return nil, errors.New("control bridge dial escaped its isolated outer namespace")
		}
		return connection.(*net.TCPConn), nil
	})
}

func startNativeMultiForwardTCPBridge(t *testing.T, ctx context.Context, source *nativeMultiForwardNS, publicAddress string, dial func() (*net.TCPConn, error)) *nativeMultiForwardBridge {
	t.Helper()
	listener, err := source.ListenTCP(publicAddress)
	if err != nil {
		t.Fatal(err)
	}
	b := &nativeMultiForwardBridge{Address: listener.Addr().String(), stop: make(chan struct{})}
	b.filename = filepath.Join(source.evidence, source.label+"-tcp-"+strconv.Itoa(listener.Addr().(*net.TCPAddr).Port)+"-bridge-cleanup.json")
	b.add(listener)
	t.Cleanup(func() { b.Close(t) })
	b.workers.Add(1)
	go func() {
		defer b.workers.Done()
		for {
			connection, err := listener.AcceptTCP()
			if err != nil {
				return
			}
			if !b.add(connection) {
				return
			}
			upstream, err := dial()
			if err != nil {
				_ = connection.Close()
				continue
			}
			if !b.add(upstream) {
				return
			}
			b.peerCount.Add(1)
			for _, pair := range [][2]*net.TCPConn{{connection, upstream}, {upstream, connection}} {
				b.workers.Add(1)
				go func(source, destination *net.TCPConn) {
					defer b.workers.Done()
					_, _ = io.Copy(destination, source)
					_ = destination.CloseWrite()
				}(pair[0], pair[1])
			}
		}
	}()
	go func() {
		select {
		case <-ctx.Done():
			b.close()
		case <-b.stop:
		}
	}()
	return b
}

//go:build linux

package linuxclient

import (
	"bufio"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"slices"
	"sort"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
	"golang.org/x/net/proxy"

	"loom/internal/clientadapter"
	"loom/internal/control"
	"loom/internal/deviceclient"
	"loom/internal/netx"
)

// Four separate ordinary CLI runtimes retain every automatically derived Link.
// Only the remote F2-to-exit wire delay changes. F1's local inputs stay fixed,
// so its actual new-flow decision exercises the delivered signed suffix sample.
func TestOfficialLinuxNativeMultiForwardSharedSuffixKeepsExistingTCP(t *testing.T) {
	native := os.Getenv("LOOM_LINUX_MIXED_EXECUTABLE")
	if native == "" {
		t.Skip("requires the reviewed native executable in dedicated namespaces")
	}
	cli := os.Getenv("LOOM_MEMBER_CLI")
	if cli == "" {
		t.Fatal("explicit native acceptance also requires the freshly built official CLI")
	}
	for _, kind := range []string{"user", "net", "mnt"} {
		current, err := os.Stat("/proc/self/ns/" + kind)
		initial, other := os.Stat("/proc/1/ns/" + kind)
		if err != nil || other != nil || os.SameFile(current, initial) {
			t.Fatal("multi-forward acceptance requires fresh user, network and mount namespaces")
		}
	}
	if _, err := nativeMultiForwardNetworkBoundary(true); err != nil {
		t.Fatal(err)
	}
	if err := exec.Command("ip", "link", "set", "lo", "up").Run(); err != nil {
		t.Fatal(err)
	}
	// No generated address is ever bound outside the exit's verified namespace.
	var business netip.Addr
	for !business.IsValid() {
		var bytes [4]byte
		if _, err := rand.Read(bytes[:]); err != nil {
			t.Fatal(err)
		}
		candidate := netip.AddrFrom4(bytes)
		if netx.IsPublicInternetAddress(candidate) {
			business = candidate
		}
	}
	timing := clientadapter.DefaultMeasurementTiming
	// One idle discovery, six active rounds, four full round deadlines, and
	// four normal 15-second refresh/report opportunities for remote delivery.
	limit := timing.IdlePeriod + 6*timing.ActivePeriod + 4*timing.RoundTimeout + time.Minute
	ctx, cancel := context.WithTimeout(context.Background(), limit)
	t.Cleanup(cancel)
	evidence := t.TempDir()
	if output := flag.Lookup("test.outputdir"); output != nil && output.Value.String() != "" {
		evidence = filepath.Join(output.Value.String(), "native-multiforward-evidence")
		if err := os.Mkdir(evidence, 0700); err != nil {
			t.Fatal(err)
		}
	}
	if info, err := os.Stat(evidence); err != nil || !info.IsDir() || info.Mode().Perm()&0077 != 0 {
		t.Fatal("multi-forward evidence requires an owner-only directory")
	}
	const access, f1, f2, exit = "demo-access", "demo-forward-a", "demo-forward-b", "demo-exit"
	ids := []string{access, f1, f2, exit}
	nodes := map[string]*nativeMultiForwardNS{}
	for _, id := range ids {
		var addresses []netip.Addr
		if id == exit {
			addresses = []netip.Addr{business}
		}
		nodes[id] = newNativeMultiForwardNS(t, ctx, id, evidence, addresses)
		nativeMultiForwardDNS(t, nodes[id], business.As4())
	}
	p, keys, input, _ := nativeProjectionFixture(t, limit+time.Minute)
	var generated ResourceInputs
	if err := readStrict(input, 1<<20, &generated); err != nil {
		t.Fatal(err)
	}
	keys[f1] = keys["demo-entry"]
	public := map[string]string{}
	for _, id := range []string{access, f2} {
		key, err := ecdh.X25519().GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		keys[id] = filepath.Join(evidence, id+"-wg.key")
		if err := os.WriteFile(keys[id], []byte(base64.StdEncoding.EncodeToString(key.Bytes())), 0600); err != nil {
			t.Fatal(err)
		}
		public[id] = base64.RawURLEncoding.EncodeToString(key.PublicKey().Bytes())
	}
	resourceInputs := map[string]ResourceInputs{}
	ownerPort := map[string]int{}
	publicPort := map[string]int{}
	var reservations []*net.UDPConn
	var outerReservations []net.PacketConn
	t.Cleanup(func() {
		for _, socket := range reservations {
			socket.Close()
		}
		for _, socket := range outerReservations {
			socket.Close()
		}
	})
	for i := range p.NetworkIntent.Resources {
		resource := &p.NetworkIntent.Resources[i]
		old := resource.ID
		switch resource.Kind {
		case "hysteria2":
			resource.ID, resource.ListenerID, resource.OwnerNodeID, resource.LinkOnly = "demo-forward-b-hy2", "demo-forward-b-hy2", f2, true
		case "wireguard":
			if resource.OwnerNodeID == "demo-entry" {
				resource.ID, resource.ListenerID, resource.OwnerNodeID = "demo-forward-a-wg", "demo-forward-a-wg", f1
			}
			resource.AccessEnabled = resource.OwnerNodeID == f1
			public[resource.OwnerNodeID] = *resource.Authentication.PublicKey
		default:
			t.Fatal("unexpected generated transport")
		}
		// Receiver Q is outside Linux's ordinary ephemeral range. Reservation
		// remains held until every public P has been bound in every source.
		q := 20001 + i
		reservation, err := nodes[resource.OwnerNodeID].ListenUDP(net.JoinHostPort("127.0.0.1", strconv.Itoa(q)))
		if err != nil {
			t.Fatal(err)
		}
		reservations = append(reservations, reservation)
		ownerPort[resource.ID] = q
		port, err := net.ListenPacket("udp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		outerReservations = append(outerReservations, port)
		publicPort[resource.ID] = port.LocalAddr().(*net.UDPAddr).Port
		resource.DialHost, resource.DialPort = "127.0.0.1", publicPort[resource.ID]
		for _, listener := range generated.Listeners {
			if listener.ResourceID != old {
				continue
			}
			listener.ResourceID = resource.ID
			if resource.Kind == "wireguard" {
				listener.ListenPort = q
			} else {
				listener.Listen = net.JoinHostPort("127.0.0.1", strconv.Itoa(q))
			}
			resourceInputs[resource.OwnerNodeID] = ResourceInputs{Schema: 3, Listeners: []ResourceListenerInput{listener}}
		}
	}
	sort.Slice(p.NetworkIntent.Resources, func(i, j int) bool { return p.NetworkIntent.Resources[i].ID < p.NetworkIntent.Resources[j].ID })
	const r1, r2, re = "demo-forward-a-wg", "demo-forward-b-hy2", "demo-exit-wg"
	delays := map[string]*atomic.Int64{}
	for _, path := range []struct {
		from, owner, resource string
		delay                 time.Duration
	}{{access, f1, r1, time.Millisecond}, {f1, f2, r2, time.Millisecond}, {f1, exit, re, 20 * time.Millisecond}, {f2, f1, r1, 100 * time.Millisecond}, {f2, exit, re, 60 * time.Millisecond}} {
		delay := new(atomic.Int64)
		delay.Store(int64(path.delay))
		delays[path.from+"/"+path.owner] = delay
		StartNativeMultiForwardUDPBridge(t, ctx, nodes[path.from], nodes[path.owner], net.JoinHostPort("127.0.0.1", strconv.Itoa(publicPort[path.resource])), net.JoinHostPort("127.0.0.1", strconv.Itoa(ownerPort[path.resource])), delay)
	}
	for _, socket := range reservations {
		socket.Close()
	}
	p.NetworkIntent.DNSRecords = []control.DNSRecord{}
	policy := &p.NetworkIntent.Policies[0]
	policy.EntryScope = control.PolicyScope{Mode: "only", NodeIDs: []string{f1}}
	policy.RelayScope = control.PolicyScope{Mode: "only", NodeIDs: []string{f1, f2}}
	policy.ExitScope = new(control.PolicyScope{Mode: "only", NodeIDs: []string{exit}})
	policy.MaxHops = 3
	devices := []control.DevicePut{}
	for _, id := range ids {
		roles, policies := []string{"forward"}, []string{}
		if id == access {
			roles, policies = []string{"access"}, []string{"demo-policy"}
		} else if id == exit {
			roles = []string{"internet_egress"}
		}
		devices = append(devices, control.DevicePut{ID: id, Name: id, Responsibilities: roles, PolicyIDs: policies, DNSServers: []string{"127.0.0.1"}, DistributionURLs: []string{}, WireGuardPublicKey: public[id]})
	}
	authority, stores, states := startNativeForwardControlDevices(t, ctx, cli, evidence, p.NetworkIntent, devices)
	initial := map[string]control.DeviceViewEnvelope{}
	configs, statuses := map[string]string{}, map[string]string{}
	stops := []func(){}
	for _, id := range ids {
		initial[id] = *stores[id].LKG()
		endpoints := initial[id].View.Endpoints
		if len(endpoints) != 1 || endpoints[0].Host != "127.0.0.1" {
			t.Fatal("normal LKG did not retain its isolated control endpoint")
		}
		endpoint := net.JoinHostPort(endpoints[0].Host, strconv.Itoa(endpoints[0].Port))
		StartNativeMultiForwardTCPBridgeToOuter(t, ctx, nodes[id], endpoint, endpoint)
		configs[id], statuses[id] = filepath.Join(evidence, id+"-runtime.json"), filepath.Join(evidence, id+"-status.json")
		args := []string{"client", "run", "-state", states[id], "-capture", "mixed", "-sing-box", native, "-wireguard-private-key", keys[id], "-runtime-config", configs[id], "-runtime-state", filepath.Join(evidence, id+"-observations.json"), "-status", statuses[id]}
		if inputs, ok := resourceInputs[id]; ok {
			path := filepath.Join(evidence, id+"-resource-inputs.json")
			if err := atomicJSON(path, inputs); err != nil {
				t.Fatal(err)
			}
			args = append(args, "-resource-inputs", path)
		}
		log, err := os.OpenFile(filepath.Join(evidence, id+"-run.log"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if err != nil {
			t.Fatal(err)
		}
		run := nodes[id].Command(ctx, cli, args...)
		run.Stdout, run.Stderr = log, log
		if err := run.Start(); err != nil {
			t.Fatal(err)
		}
		done := make(chan error, 1)
		go func() { done <- run.Wait() }()
		stopped := false
		stop := func() {
			if stopped {
				return
			}
			stopped = true
			_ = run.Process.Signal(os.Interrupt)
			select {
			case err := <-done:
				if err != nil {
					t.Error("normal node runtime did not stop", id, err)
				}
			case <-time.After(10 * time.Second):
				_ = run.Process.Kill()
				<-done
				t.Error("normal node runtime exceeded its stop bound", id)
			}
			log.Close()
		}
		stops = append(stops, stop)
		// Keep this node's control bridge alive until Signal/Wait completes.
		// All node cleanups are later than the control owner's cleanup.
		t.Cleanup(stop)
	}
	wait := func(stage string, check func() bool) {
		t.Helper()
		t.Log("waiting for", stage)
		ticker := time.NewTicker(250 * time.Millisecond)
		defer ticker.Stop()
		for !check() {
			select {
			case <-ctx.Done():
				t.Fatal("normal multi-forward runtime did not reach " + stage)
			case <-ticker.C:
			}
		}
	}
	links := map[string]control.NetworkLink{}
	specs, err := control.LinkSpecifications(initial[f1].View)
	if err != nil {
		t.Fatal(err)
	}
	forwardExecution, err := control.ProjectDeviceCandidates(initial[f1].View, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, link := range forwardExecution.Links {
		links[link.FromNodeID+"/"+link.ToNodeID] = link
	}
	if len(links) != 4 || links[f1+"/"+f2].ResourceID != r2 || links[f1+"/"+exit].ResourceID != re || links[f2+"/"+f1].ResourceID != r1 || links[f2+"/"+exit].ResourceID != re {
		t.Fatal("normal authority did not retain all four automatic directed Links")
	}
	for _, id := range []string{f1, f2} {
		if len(initial[id].View.PolicyIDs) != 0 {
			t.Fatal("forward acquired an access Policy assignment")
		}
	}
	execution, err := control.ProjectDeviceCandidates(initial[access].View, []string{"demo-policy"})
	if err != nil || len(execution.Routes) != 1 || execution.Routes[0].EntryNodeID != f1 || execution.Routes[0].FirstResourceID != r1 || execution.Routes[0].FinalExit != exit {
		t.Fatal("access did not retain its sole normal first-hop candidate", err)
	}
	var snapshot control.WebSnapshot
	current := map[string]*control.DeviceEvidence{}
	refresh := func() bool {
		value, err := authority.snapshot(ctx)
		if err != nil {
			return false
		}
		found := map[string]*control.DeviceEvidence{}
		for _, device := range value.Devices {
			lkg, ok := initial[device.ID]
			v := device.Evidence
			if ok && v != nil && v.Freshness == "current" && v.ViewDigest == lkg.ViewDigest && v.NetworkGeneration != "" && v.Runtime != nil && v.Runtime.State == "running" && v.Runtime.AppliedViewDigest == lkg.ViewDigest {
				found[device.ID] = v
			}
		}
		if len(found) != 4 {
			return false
		}
		snapshot, current = value, found
		return true
	}
	sample := func(from, to string, after int64) (control.Observation, bool) {
		v := current[from]
		if v == nil {
			return control.Observation{}, false
		}
		link := links[from+"/"+to]
		for _, item := range v.Measurements {
			o := item.Observation
			if o.Level == "link" && o.LinkID == link.ID && o.ResourceID == link.ResourceID && o.SpecDigest == specs[link.ID] && o.Action == link.ProbeTarget.Action && o.Target == net.JoinHostPort(link.ProbeTarget.Host, strconv.Itoa(link.ProbeTarget.Port)) && o.NetworkGeneration == v.NetworkGeneration && o.Result == "available" && o.RoundTripMS != nil && o.ObservedAt > after && o.ValidUntil > time.Now().UnixMilli() {
				return o, true
			}
		}
		return control.Observation{}, false
	}
	forward := func(id string) (nativeForwardSnapshot, error) {
		var value nativeForwardSnapshot
		err := nativeMultiForwardGet(ctx, nodes[id], configs[id], "/proxies/"+url.PathEscape("forward:demo-policy"), &value)
		return value, err
	}
	tags := map[string]string{}
	for _, id := range []string{r1, r2, re} {
		tags[id], err = control.ForwardSegmentTag(id)
		if err != nil {
			t.Fatal(err)
		}
	}
	var before nativeForwardSnapshot
	wait("four normal reports and initial measured direct suffix", func() bool {
		if !refresh() {
			return false
		}
		a, okA := sample(f1, f2, 0)
		b, okB := sample(f1, exit, 0)
		c, okC := sample(f2, exit, 0)
		before, err = forward(f1)
		second, err2 := forward(f2)
		return okA && okB && okC && *b.RoundTripMS < *a.RoundTripMS+*c.RoundTripMS && err == nil && before.Revision != "" && before.first() == tags[re] && err2 == nil && second.first() == tags[re]
	})
	baselineGenerations := map[string]string{}
	for _, id := range ids {
		baselineGenerations[id] = current[id].NetworkGeneration
	}
	accessBefore := nativeMultiForwardAccess(t, ctx, nodes[access], configs[access])
	if accessBefore.Now != execution.Routes[0].ID || accessBefore.PolicyID != "demo-policy" || len(accessBefore.Choices) != 1 {
		t.Fatal("access API changed its fixed first hop")
	}
	echo, err := nodes[exit].ListenTCP(net.JoinHostPort(business.String(), "0"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { echo.Close() })
	go func() {
		for {
			connection, err := echo.AcceptTCP()
			if err != nil {
				return
			}
			if err := nodes[exit].retain(connection); err != nil {
				return
			}
			go func() { defer connection.Close(); _, _ = io.Copy(connection, connection) }()
		}
	}()
	port := strconv.Itoa(echo.Addr().(*net.TCPAddr).Port)
	dialer, err := proxy.SOCKS5("tcp", "127.0.0.1:1080", nil, nativeMultiForwardDialer{nodes[access]})
	if err != nil {
		t.Fatal(err)
	}
	connect := func() (net.Conn, *bufio.Reader) {
		t.Helper()
		attempt, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		connection, err := dialer.(proxy.ContextDialer).DialContext(attempt, "tcp", net.JoinHostPort("demo-forward.example", port))
		if err != nil {
			t.Fatal("ordinary multi-forward business connect failed", err)
		}
		t.Cleanup(func() { connection.Close() })
		return connection, bufio.NewReader(connection)
	}
	checkStream := func(connection net.Conn, reader *bufio.Reader) {
		t.Helper()
		_ = connection.SetDeadline(time.Now().Add(3 * time.Second))
		if _, err := io.WriteString(connection, "demo-multiforward-business\n"); err != nil {
			t.Fatal("ordinary existing stream write failed", err)
		}
		if value, err := reader.ReadString('\n'); err != nil || value != "demo-multiforward-business\n" {
			t.Fatal("ordinary stream did not return its application bytes", err)
		}
	}
	connections := func(id string) []nativeForwardConnection {
		var value struct {
			Connections []nativeForwardConnection `json:"connections"`
		}
		if nativeMultiForwardGet(ctx, nodes[id], configs[id], "/connections", &value) != nil {
			return nil
		}
		return slices.DeleteFunc(value.Connections, func(c nativeForwardConnection) bool {
			return c.Metadata.DestinationPort != port || !slices.Contains(c.Chains, "forward:demo-policy")
		})
	}
	old, oldReader := connect()
	checkStream(old, oldReader)
	oldID := ""
	wait("old direct business tracker", func() bool {
		for _, c := range connections(f1) {
			if slices.Contains(c.Chains, tags[re]) && !slices.Contains(c.Chains, tags[r2]) {
				oldID = c.ID
				return true
			}
		}
		return false
	})
	var remoteBefore, remoteAfter control.DeviceLinkObservation
	fetch := func(after int64) (control.DeviceLinkObservation, bool) {
		attempt, cancel := context.WithTimeout(ctx, 3*time.Second)
		defer cancel()
		delivery, err := deviceclient.FetchLinkObservations(control.WithEndpointDialer(attempt, nodes[f1].DialContext), stores[f1], nil)
		if err != nil {
			return control.DeviceLinkObservation{}, false
		}
		for _, item := range delivery.Observations {
			if item.DeviceID == f2 && item.Observation.LinkID == links[f2+"/"+exit].ID && item.Observation.ObservedAt > after && item.Observation.Result == "available" && item.Observation.RoundTripMS != nil {
				return item, true
			}
		}
		return control.DeviceLinkObservation{}, false
	}
	wait("formal F1 delivery of F2 signed slow suffix", func() bool { var ok bool; remoteBefore, ok = fetch(0); return ok })
	if err := writeNativeForwardEvidence(filepath.Join(evidence, "before.json"), map[string]any{"control": snapshot, "forward": before, "delivery": remoteBefore, "old_id": oldID, "access": accessBefore}); err != nil {
		t.Fatal(err)
	}
	flipped := time.Now().UnixMilli()
	delays[f2+"/"+exit].Store(int64(time.Millisecond))
	var after nativeForwardSnapshot
	lastKeep := time.Now()
	wait("remote-only real RTT reversal and actual F1 forward CAS", func() bool {
		if time.Since(lastKeep) > time.Second {
			checkStream(old, oldReader)
			lastKeep = time.Now()
		}
		if !refresh() {
			return false
		}
		a, okA := sample(f1, f2, 0)
		b, okB := sample(f1, exit, 0)
		c, okC := sample(f2, exit, flipped)
		after, err = forward(f1)
		second, err2 := forward(f2)
		return okA && okB && okC && *a.RoundTripMS+*c.RoundTripMS < *b.RoundTripMS && err == nil && after.Revision != before.Revision && after.first() == tags[r2] && err2 == nil && second.first() == tags[re]
	})
	wait("formal F1 delivery of F2 signed fast suffix", func() bool {
		var ok bool
		remoteAfter, ok = fetch(flipped)
		return ok && remoteAfter.ReportSequence > remoteBefore.ReportSequence
	})
	next, nextReader := connect()
	checkStream(next, nextReader)
	var f1Connections, f2Connections []nativeForwardConnection
	wait("old direct and new actual F1-F2-exit business chains", func() bool {
		f1Connections, f2Connections = connections(f1), connections(f2)
		oldPinned, newPinned, suffixPinned := false, false, false
		for _, c := range f1Connections {
			oldPinned = oldPinned || c.ID == oldID && slices.Contains(c.Chains, tags[re]) && !slices.Contains(c.Chains, tags[r2])
			newPinned = newPinned || c.ID != oldID && slices.Contains(c.Chains, tags[r2]) && !slices.Contains(c.Chains, tags[re])
		}
		for _, c := range f2Connections {
			suffixPinned = suffixPinned || slices.Contains(c.Chains, tags[re]) && !slices.Contains(c.Chains, tags[r1])
		}
		return oldPinned && newPinned && suffixPinned
	})
	checkStream(old, oldReader)
	checkStream(next, nextReader)
	accessAfter := nativeMultiForwardAccess(t, ctx, nodes[access], configs[access])
	if accessBefore.Now != accessAfter.Now || accessBefore.PolicyID != accessAfter.PolicyID || !reflect.DeepEqual(accessBefore.Choices, accessAfter.Choices) || !reflect.DeepEqual(accessBefore.Targets, accessAfter.Targets) {
		t.Fatal("remote suffix change altered access's sole first-hop decision")
	}
	for _, id := range ids {
		if current[id].NetworkGeneration != baselineGenerations[id] {
			t.Fatal("remote delay changed a node's network generation")
		}
		reloaded, err := deviceclient.Load(states[id])
		if err != nil || !reflect.DeepEqual(reloaded.LKG(), stores[id].LKG()) || reloaded.Preference().PolicyID != stores[id].Preference().PolicyID {
			t.Fatal("remote delay changed certified authorization or preference", id, err)
		}
	}
	if delays[f1+"/"+f2].Load() != int64(time.Millisecond) || delays[f1+"/"+exit].Load() != int64(20*time.Millisecond) || delays[f2+"/"+f1].Load() != int64(100*time.Millisecond) {
		t.Fatal("the local forwarding experiment inputs changed")
	}
	if err := writeNativeForwardEvidence(filepath.Join(evidence, "after.json"), map[string]any{"control": snapshot, "forward": after, "delivery": remoteAfter, "flipped_at": flipped, "f1_connections": f1Connections, "f2_connections": f2Connections, "access": accessAfter}); err != nil {
		t.Fatal(err)
	}
	for _, stop := range stops {
		stop()
	}
	authority.stop(t)
	reports := authority.offlineReports(t, "multiforward-originals")
	owners := map[string]bool{}
	for _, report := range reports {
		if _, ok := initial[report.DeviceID]; ok && report.Runtime.State == "running" {
			owners[report.DeviceID] = true
		}
		if report.DeviceID == f1 && slices.ContainsFunc(report.Observations, func(o control.Observation) bool { return o.LinkID == links[f2+"/"+exit].ID }) {
			t.Fatal("F1 re-reported another device's signed suffix as its own sample")
		}
	}
	if len(owners) != 4 {
		t.Fatal("control did not persist each actual CLI runtime's report")
	}
	for _, reference := range []control.DeviceLinkObservation{remoteBefore, remoteAfter} {
		found := false
		for _, report := range reports {
			body, err := control.CanonicalEncode(report)
			if err == nil && report.DeviceID == reference.DeviceID && report.ReportSequence == reference.ReportSequence && control.ReleaseDigest(body) == reference.ReportDigest && slices.ContainsFunc(report.Observations, func(o control.Observation) bool { return reflect.DeepEqual(o, reference.Observation) }) {
				found = true
			}
		}
		if !found {
			t.Fatal("formal delivery lost its exact original signed report reference")
		}
	}
	t.Log("four real runtimes, remote signed suffix delivery, new multi-hop flow and retained direct flow verified")
}

type nativeMultiForwardDialer struct{ node *nativeMultiForwardNS }

func (d nativeMultiForwardDialer) Dial(network, address string) (net.Conn, error) {
	return d.node.DialContext(context.Background(), network, address)
}

func (d nativeMultiForwardDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return d.node.DialContext(ctx, network, address)
}

func nativeMultiForwardGet(ctx context.Context, node *nativeMultiForwardNS, config, path string, value any) error {
	api, err := nativeForwardReadAPI(config)
	if err != nil || api.address != "127.0.0.1:61800" || api.secret == "" {
		return fmt.Errorf("node API is not ready")
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+api.address+path, nil)
	if err != nil {
		return err
	}
	request.Header.Set("Authorization", "Bearer "+api.secret)
	client := &http.Client{Timeout: time.Second, Transport: &http.Transport{Proxy: nil, DisableKeepAlives: true, DialContext: node.DialContext}}
	response, err := client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("node readback returned HTTP %d", response.StatusCode)
	}
	return json.NewDecoder(io.LimitReader(response.Body, 1<<20)).Decode(value)
}

type nativeMultiForwardAccessSnapshot struct {
	Now      string                     `json:"now"`
	PolicyID string                     `json:"policy_id"`
	Revision string                     `json:"revision"`
	Targets  map[string]string          `json:"targets"`
	Choices  map[string]json.RawMessage `json:"choices"`
}

func nativeMultiForwardAccess(t *testing.T, ctx context.Context, node *nativeMultiForwardNS, config string) nativeMultiForwardAccessSnapshot {
	t.Helper()
	var value nativeMultiForwardAccessSnapshot
	if err := nativeMultiForwardGet(ctx, node, config, "/proxies/access", &value); err != nil || value.Revision == "" || value.Now == "" || value.Targets == nil {
		t.Fatal("could not read normal access selection", err)
	}
	return value
}

func nativeMultiForwardDNS(t *testing.T, node *nativeMultiForwardNS, address [4]byte) {
	t.Helper()
	listener, err := node.ListenUDP("127.0.0.1:53")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })
	go func() {
		var buffer [2048]byte
		for {
			n, peer, err := listener.ReadFrom(buffer[:])
			if err != nil {
				return
			}
			var message dnsmessage.Message
			if message.Unpack(buffer[:n]) != nil || len(message.Questions) != 1 {
				continue
			}
			question := message.Questions[0]
			message.Response, message.RecursionAvailable = true, true
			if question.Name.String() != "demo-forward.example." {
				message.RCode = dnsmessage.RCodeNameError
			} else if question.Type == dnsmessage.TypeA {
				message.Answers = []dnsmessage.Resource{{Header: dnsmessage.ResourceHeader{Name: question.Name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 30}, Body: &dnsmessage.AResource{A: address}}}
			}
			if body, err := message.Pack(); err == nil {
				_, _ = listener.WriteTo(body, peer)
			}
		}
	}()
}

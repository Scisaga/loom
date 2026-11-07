package linuxclient

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"loom/internal/clientadapter"
	"loom/internal/control"
)

func TestProbeDebugConfigurationKeepsRuntimeProjection(t *testing.T) {
	source := `{"log":{"level":"warn"},"inbounds":[{"type":"mixed","tag":"demo-access"}],"route":{"rules":[]}}`
	result, err := withProbeDebugConfig(source)
	if err != nil {
		t.Fatal(err)
	}
	var before, after map[string]json.RawMessage
	_ = json.Unmarshal([]byte(source), &before)
	_ = json.Unmarshal([]byte(result), &after)
	delete(before, "log")
	delete(after, "log")
	want, _ := json.Marshal(before)
	got, _ := json.Marshal(after)
	if !bytes.Equal(want, got) || !strings.Contains(result, `"level":"debug"`) {
		t.Fatal("diagnostic configuration changed the runtime projection")
	}
	if got, err := withProbeDebugConfig(""); got != "" || err != nil {
		t.Fatal("empty server config became a runtime")
	}
	for _, invalid := range []string{"null", "[1]", "{"} {
		if _, err := withProbeDebugConfig(invalid); err == nil {
			t.Fatal("accepted a non-object config")
		}
	}
	var target bytes.Buffer
	options := Options{Log: &target}
	options.defaults()
	if options.Log != &target || probeNativeOutput(options) != &target {
		t.Fatal("default runtime logging changed")
	}
}

func TestProbeDebugReloadDoesNotReplaceNativeInstance(t *testing.T) {
	p, keys, input, at := nativeProjectionFixture(t)
	view, err := control.ProjectDeviceView(p, "demo-exit")
	if err != nil {
		t.Fatal(err)
	}
	executions, err := prepareResourceExecutions(view, input, at)
	if err != nil {
		t.Fatal(err)
	}
	wg, _, err := projectWireGuard(view, executions)
	if err != nil {
		t.Fatal(err)
	}
	options := Options{Capture: "mixed", DeviceState: filepath.Join(t.TempDir(), "demo-state.json"), WireGuardPrivateKey: keys["demo-exit"]}
	connected := []string{}
	before, _, err := rebuildReceivingConfigs(view, options, "demo-secret", nil, executions, clientadapter.WebsiteAccess{}, &connected, nil, wg, nil)
	if err != nil {
		t.Fatal(err)
	}
	before, err = withProbeDebugConfig(before)
	if err != nil {
		t.Fatal(err)
	}
	options.TraceProbes = true
	after, _, err := rebuildReceivingConfigs(view, options, "demo-secret", nil, executions, clientadapter.WebsiteAccess{}, &connected, nil, wg, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, hot, err := clientadapter.RuntimePermissionChanges(before, after); err != nil || !hot {
		t.Fatal("diagnostic log configuration forced native instance replacement", hot, err)
	}
}

func TestProbeDebugFiltersFragmentedBusinessLogs(t *testing.T) {
	var target bytes.Buffer
	options := Options{TraceProbes: true, Log: &target}
	options.defaults()
	writer := probeNativeOutput(options)
	id := strings.Repeat("a", 64)
	source := "DEBUG[0001] outbound/wireguard[demo-private]: connection to private.example:443\n" +
		"INFO[0001] inbound/mixed: request private.example:443\n" +
		"DEBUG[0001] [42 1ms] private.example: echo_id=" + id + " phase=local-connect-begin elapsed_ns=0 outcome=started error_type=<nil>\n" +
		"\x1b[37mDEBUG\x1b[0m[0001] [42 2ms] outbound/wireguard[demo-private]: WG stage=peer-prepare event=begin\n" +
		"DEBUG[0001] [42 2ms] WG stage=inner-dial event=end elapsed=10.2µs canceled=false error_type=*net.OpError\n" +
		"DEBUG[0001] [42 3ms] outbound/wireguard[demo-private]: WG stage=execution-confirm event=begin\n" +
		"DEBUG[0001] [42 8s] outbound/wireguard[demo-private]: WG stage=execution-confirm event=end elapsed=8.0001s canceled=true error_type=context.deadlineExceededError\n" +
		"DEBUG[0001] [42 8s] WG stage=execution-confirm event=end elapsed=8s canceled=true error_type=*net.OpError target=private.example\n" +
		"DEBUG[0001] echo_id=" + id + " phase=echo-read elapsed_ns=10 outcome=failed error_type=*net.OpError target=private.example\n" +
		"WARN[0001] existing warning\n"
	for i := 0; i < len(source); i += 7 {
		end := min(i+7, len(source))
		if n, err := io.WriteString(writer, source[i:end]); err != nil || n != end-i {
			t.Fatal("diagnostic stream interfered with process output", n, err)
		}
	}
	got := target.String()
	if strings.Contains(got, "private.example") || strings.Contains(got, "demo-private") || strings.Contains(got, "INFO") || strings.Contains(got, "phase=echo-read") {
		t.Fatal("business metadata entered diagnostic output", got)
	}
	if strings.Count(got, "native_id=42") != 5 || strings.Count(got, "echo_id="+id) != 1 || strings.Count(got, "WG stage=execution-confirm") != 2 || !strings.Contains(got, "event=end elapsed=8.0001s canceled=true error_type=context.deadlineExceededError") || !strings.Contains(got, "WARN[0001] existing warning") {
		t.Fatal("lost correlation or existing warning", got)
	}
	_, _ = io.WriteString(writer, strings.Repeat("x", 40<<10)+"\nWARN[0002] next warning\n")
	if strings.Contains(target.String(), strings.Repeat("x", 16)) || !strings.Contains(target.String(), "next warning") {
		t.Fatal("oversized log line leaked or suppressed a later line")
	}
}

type brokenProbeOutput struct{ panic bool }

func (output brokenProbeOutput) Write([]byte) (int, error) {
	if output.panic {
		panic("demo logger failure")
	}
	return 0, errors.New("demo logger failure")
}

func TestProbeDebugOutputCannotFailTransportOrMixChildLines(t *testing.T) {
	for _, target := range []io.Writer{brokenProbeOutput{}, brokenProbeOutput{panic: true}} {
		options := Options{TraceProbes: true, Log: target}
		options.defaults()
		if n, err := io.WriteString(probeNativeOutput(options), "WARN[0000] demo\n"); n != len("WARN[0000] demo\n") || err != nil {
			t.Fatal("log failure propagated", n, err)
		}
	}
	var target bytes.Buffer
	options := Options{TraceProbes: true, Log: &target}
	options.defaults()
	var group sync.WaitGroup
	for child := range 3 {
		group.Add(1)
		go func() {
			defer group.Done()
			writer := probeNativeOutput(options)
			for index := range 100 {
				_, _ = io.WriteString(writer, fmt.Sprintf("WARN[0000] child=%d ", child))
				_, _ = io.WriteString(writer, fmt.Sprintf("index=%d\n", index))
				_, _ = fmt.Fprintln(options.Log, "DEBUG Go callback")
			}
		}()
	}
	group.Wait()
	lines := strings.Split(strings.TrimSpace(target.String()), "\n")
	if len(lines) != 600 {
		t.Fatal("lost output lines", len(lines))
	}
	for _, line := range lines {
		if line != "DEBUG Go callback" && (!strings.HasPrefix(line, "WARN[0000] child=") || strings.Count(line, "index=") != 1) {
			t.Fatal("child output fragments interleaved", line)
		}
	}
}

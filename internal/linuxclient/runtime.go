package linuxclient

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"syscall"
	"time"

	"loom/internal/clientadapter"
	"loom/internal/clientmodel"
	"loom/internal/control"
	"loom/internal/deviceclient"
)

var errCertifiedViewChanged = errors.New("a newly accepted device view is available")
var errCertifiedPersistence = errors.New("device view persistence failed")
var errRuntimeCleanup = errors.New("runtime generation cleanup failed")

type Options struct {
	DeviceState         string
	LocalState          string
	Status              string
	Config              string
	SingBox             string
	WireGuard           string
	IP                  string
	WireGuardPrivateKey string
	Log                 io.Writer
	Now                 func() time.Time
	Generation          func() (string, error)
	Probe               Probe
	RefreshPoll         time.Duration
	Reload              <-chan os.Signal
	Capture             string
	ResourceInputs      string
	defaultProbe        bool
}

func (options *Options) defaults() {
	if options.Capture == "" {
		options.Capture = "mixed"
	}
	if options.Log == nil {
		options.Log = io.Discard
	}
	if options.Now == nil {
		options.Now = time.Now
	}
	if options.Generation == nil {
		options.Generation = NetworkGeneration
	}
	options.defaultProbe = options.Probe == nil
	if options.RefreshPoll <= 0 {
		options.RefreshPoll = 30 * time.Second
	}
	if options.WireGuard == "" {
		options.WireGuard = "/usr/bin/wg"
	}
	if options.IP == "" {
		options.IP = "/usr/sbin/ip"
	}
	if options.WireGuardPrivateKey == "" {
		options.WireGuardPrivateKey = "/etc/wireguard/node.key"
	}
}
func (options Options) probeForService(view control.DeviceView, scope string) Probe {
	if !options.defaultProbe {
		return options.Probe
	}
	for _, group := range view.BusinessProbeTargets {
		if scope != "service:"+group.ServiceID || len(group.Targets) != 1 {
			continue
		}
		if options.Capture == "mixed" {
			probe, err := clientadapter.HTTPSBusinessProbe("127.0.0.1:1080", group.Targets[0])
			if err != nil {
				return nil
			}
			return func(ctx context.Context) ProbeResult {
				value := probe(ctx)
				return ProbeResult{Available: value.Available, Metric: value.Metric, Description: value.Description, Action: "https_request"}
			}
		}
		if len(view.DNSServers) == 0 {
			return nil
		}
		return func(ctx context.Context) ProbeResult { return businessProbe(ctx, view.DNSServers[0], group.Targets[0]) }
	}
	return nil
}

// Each Service owns its probe and fallback. Testing one destination cannot
// colour another Service's selection or consume another Service's permission.
func activateServices(ctx context.Context, options Options, view control.DeviceView, selector Selector, routes []clientmodel.RouteCandidate, state LocalState) (Activation, error) {
	scopes, byScope, err := scopesFor(routes)
	if err != nil {
		return Activation{}, err
	}
	result := Activation{State: state, Selections: []SelectionStatus{}}
	var failures []error
	for _, scope := range scopes {
		value, err := Activate(ctx, selector, byScope[scope], result.State, options.probeForService(view, scope), options.Now)
		if value.State.Schema == 0 {
			return result, err
		}
		result.State = value.State
		result.Selections = append(result.Selections, value.Selections...)
		if err != nil {
			failures = append(failures, err)
		}
		if ctx.Err() != nil {
			break
		}
	}
	return result, errors.Join(failures...)
}
func accessView(envelope *control.DeviceViewEnvelope) (*control.DeviceViewEnvelope, error) {
	if envelope == nil || envelope.View.Platform != "linux" || envelope.Validate() != nil {
		return nil, errors.New("Linux device has no valid runtime view")
	}
	if envelope.View.RuntimeProfile == nil {
		server := false
		for _, role := range envelope.View.Responsibilities {
			server = server || role == "internet_egress" || role == "forward"
		}
		if !server {
			return nil, errors.New("Linux device has no execution responsibility")
		}
	}
	return envelope, nil
}
func runtimeView(store *deviceclient.Store) (*control.DeviceViewEnvelope, error) {
	return accessView(store.LKG())
}
func accessRuntimeConfigForCapture(view control.DeviceView, secret string, endpointExclusions []string, capture string) (string, error) {
	if err := requireCaptureBoundary(capture); err != nil {
		return "", err
	}
	config, err := clientadapter.ManagedRuntimeConfig(view, secret)
	if err != nil {
		return "", err
	}
	if capture == "mixed" {
		return deriveLinuxMixedRuntime(config)
	}
	for _, resource := range view.Resources {
		if resource.OwnerNodeID != view.DeviceID {
			ip, err := netip.ParseAddr(resource.DialHost)
			if err != nil {
				return "", errors.New("resource underlay address requires authenticated resolution")
			}
			endpointExclusions = append(endpointExclusions, netip.PrefixFrom(ip, ip.BitLen()).String())
		}
	}
	sort.Strings(endpointExclusions)
	return deriveLinuxAccessRuntime(config, endpointExclusions)
}

func nodeRuntimeConfig(view control.DeviceView, secret string, exclusions []string, capture string, executions []hy2Execution) (string, error) {
	config := `{"inbounds":[],"outbounds":[{"tag":"reject","type":"block"}],"route":{"final":"reject","rules":[]}}`
	if capture == "tun" && (view.RuntimeProfile == nil || len(executions) != 0) {
		return "", errors.New("server listeners cannot share the access TUN process")
	}
	if view.RuntimeProfile != nil {
		var err error
		config, err = accessRuntimeConfigForCapture(view, secret, exclusions, capture)
		if err != nil {
			return "", err
		}
	}
	if view.RuntimeProfile == nil {
		var err error
		config, err = clientadapter.WithManagedDNS(config, view.DNSServers, false)
		if err != nil {
			return "", err
		}
	}
	return appendHY2Runtime(config, view, executions)
}
func runtimeSecret() (string, error) {
	var value [32]byte
	if _, err := rand.Read(value[:]); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(value[:]), nil
}
func Preflight(state, executable string) error { return PreflightCapture(state, executable, "mixed") }
func PreflightCapture(state, executable, capture string) error {
	return PreflightResources(state, executable, capture, "")
}
func PreflightResources(state, executable, capture, inputPath string) error {
	if err := requireCaptureBoundary(capture); err != nil {
		return err
	}
	store, err := deviceclient.Load(state)
	if err != nil {
		return err
	}
	view, err := runtimeView(store)
	if err != nil {
		return err
	}
	secret, err := runtimeSecret()
	if err != nil {
		return err
	}
	executions, err := prepareHY2Executions(view.View, inputPath, time.Now())
	if err != nil {
		return err
	}
	config, err := nodeRuntimeConfig(view.View, secret, nil, capture, executions)
	if err != nil {
		return err
	}
	return preflightRuntimeConfig(executable, config)
}
func acceptCertifiedView(store deviceclient.IdentityStore, envelope control.DeviceViewEnvelope) (bool, error) {
	current := store.LKG()
	if current != nil && current.Signature == envelope.Signature {
		return false, nil
	}
	if err := store.SaveLKG(envelope); err != nil {
		return false, errors.Join(errCertifiedPersistence, err)
	}
	return current == nil || current.ViewDigest != envelope.ViewDigest, nil
}
func certifiedViewChanged(ctx context.Context, store *deviceclient.Store, log io.Writer) (bool, error) {
	before := store.LKG()
	sameView := func() bool {
		current := store.LKG()
		return before != nil && current != nil && before.ViewDigest == current.ViewDigest
	}
	if changed, err := store.Reload(); err != nil {
		return false, errors.Join(errCertifiedPersistence, err)
	} else if changed && !sameView() {
		return true, nil
	}
	pending, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	envelope, err := deviceclient.Fetch(pending, store)
	if changed, readErr := store.Reload(); readErr != nil {
		return false, errors.Join(errCertifiedPersistence, readErr)
	} else if changed {
		// A concurrent durable update wins over this in-flight response, even
		// when only its authenticated frontier advanced. Retry on the next poll.
		return !sameView(), nil
	}
	if err != nil {
		fmt.Fprintln(log, "private configuration refresh unavailable; retaining the accepted view")
		return false, nil
	}
	return acceptCertifiedView(store, envelope)
}
func executableDigest(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return "", errors.New("component is not a regular executable")
	}
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", err
	}
	return "sha256:" + hex.EncodeToString(hash.Sum(nil)), nil
}
func linuxComponentReadbacks(view control.DeviceView, singBox string) ([]control.ComponentReadback, error) {
	result := []control.ComponentReadback{}
	for _, expected := range view.ExpectedComponents {
		if expected.ComponentID != "sing-box" && expected.ComponentID != "sing_box" {
			continue
		}
		output, err := exec.Command(singBox, "version").Output()
		if err != nil {
			return nil, errors.New("sing-box version readback failed")
		}
		fields := strings.Fields(string(output))
		version := ""
		for i, field := range fields {
			if strings.EqualFold(field, "version") && i+1 < len(fields) {
				version = strings.TrimPrefix(fields[i+1], "v")
				break
			}
		}
		digest, err := executableDigest(singBox)
		if err != nil {
			return nil, err
		}
		if version == "" {
			return nil, errors.New("sing-box version output is invalid")
		}
		result = append(result, control.ComponentReadback{ComponentID: expected.ComponentID, Platform: expected.Platform, Version: version, ArtifactDigest: digest})
	}
	return result, nil
}
func reportSelection(ctx context.Context, store deviceclient.IdentityStore, lkg control.DeviceViewEnvelope, activation Activation, at time.Time, components []control.ComponentReadback, readback control.RuntimeReadback) error {
	selections := []control.ReportSelection{}
	observations := []control.Observation{}
	for _, selection := range activation.Selections {
		for _, route := range lkg.View.Routes {
			if route.ID == selection.CandidateID {
				selections = append(selections, control.ReportSelection{ServiceID: route.ServiceID, CandidateID: route.ID})
			}
		}
	}
	sort.Slice(selections, func(i, j int) bool { return selections[i].ServiceID < selections[j].ServiceID })
	// Only a real probe with a unique declared target can become a wire business
	// observation. Selector readback and custom local diagnostics grant no health.
	for _, group := range lkg.View.BusinessProbeTargets {
		if len(group.Targets) != 1 {
			continue
		}
		for _, value := range activation.State.Observations {
			for _, route := range lkg.View.Routes {
				if route.ID != value.CandidateID || route.ServiceID != group.ServiceID || value.Action != "https_request" {
					continue
				}
				observed, e1 := time.Parse(time.RFC3339, value.ObservedAt)
				until, e2 := time.Parse(time.RFC3339, value.ValidUntil)
				if e1 != nil || e2 != nil {
					continue
				}
				duration := value.MetricMillis
				observations = append(observations, control.Observation{Level: "service", ServiceID: route.ServiceID, CandidateID: route.ID, Target: group.Targets[0], Action: "https_request", SpecDigest: route.SpecDigest, NetworkGeneration: activation.State.NetworkGeneration, Result: value.Result, ObservedAt: observed.UnixMilli(), ValidUntil: until.UnixMilli(), DurationMS: &duration})
			}
		}
	}
	return deviceclient.Report(ctx, store, control.DeviceReport{ReportedAt: at.UnixMilli(), ViewDigest: lkg.ViewDigest, NetworkGeneration: activation.State.NetworkGeneration, Selections: selections, Observations: observations, Components: components, Runtime: readback})
}
func runtimeStatus(lkg *control.DeviceViewEnvelope, activation Activation, reported bool, readback control.RuntimeReadback) Status {
	value := Status{Schema: 3, DeviceID: lkg.View.DeviceID, ViewDigest: lkg.ViewDigest, FactFrontier: lkg.FactFrontier, Preference: activation.State.Preference, NetworkGeneration: activation.State.NetworkGeneration, Selections: activation.Selections, Observations: activation.State.Observations, Runtime: readback.State, Reported: reported}
	if readback.Resources != nil {
		value.Resources = *readback.Resources
	}
	return value
}
func runGeneration(ctx context.Context, options Options, store *deviceclient.Store) (retErr error) {
	options.defaults()
	defer func() {
		if err := os.Remove(options.Status); err != nil && !errors.Is(err, os.ErrNotExist) {
			retErr = errors.Join(retErr, errRuntimeCleanup, err)
		}
	}()
	lkg, err := runtimeView(store)
	if err != nil {
		return err
	}
	hasAccess := lkg.View.RuntimeProfile != nil
	var routes []clientmodel.RouteCandidate
	if hasAccess {
		routes, _, err = clientadapter.AccessProjection(lkg.View)
		if err != nil {
			return err
		}
	}
	generation, err := options.Generation()
	if err != nil {
		return err
	}
	local, err := loadLocalState(options.LocalState, generation, lkg.ViewDigest)
	if err != nil {
		return err
	}
	// Refuse an unsatisfied preference before opening the data listener. An
	// empty local-hop chain must not briefly serve a Direct-only preference.
	if _, err := selectAll(routes, local.Observations, local.Preference, nil, generation, options.Now()); err != nil {
		return err
	}
	secret, err := runtimeSecret()
	if err != nil {
		return err
	}
	exclusions := []string{}
	if options.Capture == "tun" {
		if err := requireCaptureBoundary(options.Capture); err != nil {
			return err
		}
		exclusions, err = deviceclient.EndpointRouteExclusions(ctx, lkg.View.Endpoints, lkg.View.DNSServers)
		if err != nil {
			return err
		}
	}
	executions, err := prepareHY2Executions(lkg.View, options.ResourceInputs, options.Now())
	if err != nil {
		return err
	}
	config, err := nodeRuntimeConfig(lkg.View, secret, exclusions, options.Capture, executions)
	if err != nil {
		return err
	}
	wg, identity, err := projectWireGuard(lkg.View)
	if err != nil {
		return err
	}
	if err := preflightRuntimeConfig(options.SingBox, config); err != nil && (hasAccess || len(executions) != 0) {
		return err
	}
	transaction, err := applyWireGuard(&wg, nil, identity, options)
	if err != nil {
		return err
	}
	defer func() {
		if err := transaction.Cleanup(); err != nil {
			retErr = errors.Join(retErr, errRuntimeCleanup, err)
		}
	}()
	var done chan error
	var selector Selector
	pid := 0
	if hasAccess || len(executions) != 0 {
		if err := writeConfig(options.Config, config); err != nil {
			return err
		}
		defer func() {
			if err := os.Remove(options.Config); err != nil && !errors.Is(err, os.ErrNotExist) {
				retErr = errors.Join(retErr, errRuntimeCleanup, err)
			}
		}()
		// Linux delivers Pdeathsig when the creating thread exits. Retain that
		// thread until Wait completes, including every error and reload path.
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		command := exec.Command(options.SingBox, "run", "-c", options.Config)
		command.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
		command.Stdout, command.Stderr = options.Log, options.Log
		if err := command.Start(); err != nil {
			return err
		}
		pid = command.Process.Pid
		done = make(chan error, 1)
		go func() { done <- command.Wait(); close(done) }()
		defer func() { retErr = errors.Join(retErr, stopProcess(command, done)) }()
		if hasAccess {
			selector, err = NewHTTPSelector(config)
			if err != nil {
				return err
			}
			scopes, _, err := scopesFor(routes)
			if err != nil {
				return err
			}
			if err := waitSelector(ctx, selector, scopes); err != nil {
				return err
			}
		}
		if err := waitHY2Resources(ctx, executions, pid, options.Now, done); err != nil {
			return err
		}
	}
	components := []control.ComponentReadback{}
	if pid != 0 {
		components, err = linuxComponentReadbacks(lkg.View, options.SingBox)
		if err != nil {
			components = []control.ComponentReadback{}
			fmt.Fprintln(options.Log, "component readback unavailable")
		}
	}
	update := func() error {
		// Frontier/proof progress with the same View is durable authentication
		// progress, not a reason to interrupt unchanged execution.
		if current := store.LKG(); current != nil && current.ViewDigest == lkg.ViewDigest {
			lkg = current
		}
		generation, err := options.Generation()
		if err != nil {
			return err
		}
		local, err := loadLocalState(options.LocalState, generation, lkg.ViewDigest)
		if err != nil {
			return err
		}
		activation := Activation{State: local, Selections: []SelectionStatus{}}
		if err := readbackWireGuard(wg, options); err != nil {
			return err
		}
		readback := control.RuntimeReadback{State: "stopped"}
		if pid != 0 {
			readback = control.RuntimeReadback{State: "running", AppliedViewDigest: lkg.ViewDigest}
			if hasAccess {
				activation, err = Activate(ctx, selector, routes, local, nil, options.Now)
				if err != nil {
					return err
				}
			}
			resources, err := readHY2Resources(ctx, executions, pid, options.Now())
			if err != nil {
				return err
			}
			if len(resources) != 0 {
				readback.Resources = &resources
			}
		}
		if err := WriteStatus(options.Status, runtimeStatus(lkg, activation, false, readback)); err != nil {
			return err
		}
		if len(routes) > 0 {
			activation, err = activateServices(ctx, options, lkg.View, selector, routes, local)
			if activation.State.Schema == 0 {
				return err
			}
		}
		saved, saveErr := SaveObservations(options.LocalState, activation.State)
		if saveErr != nil {
			return saveErr
		}
		activation.State = saved
		pending, cancel := context.WithTimeout(ctx, 20*time.Second)
		defer cancel()
		reportErr := reportSelection(pending, store, *lkg, activation, options.Now(), components, readback)
		if reportErr != nil {
			fmt.Fprintln(options.Log, "private runtime report unavailable")
		}
		return WriteStatus(options.Status, runtimeStatus(lkg, activation, reportErr == nil, readback))
	}
	if err := update(); err != nil {
		return err
	}
	ticker := time.NewTicker(options.RefreshPoll)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case err := <-done:
			if err == nil {
				return errors.New("sing-box exited unexpectedly")
			}
			return errors.New("sing-box process exited")
		case <-ticker.C:
		case <-options.Reload:
		}
		if changed, err := certifiedViewChanged(ctx, store, options.Log); err != nil {
			return err
		} else if changed {
			return errCertifiedViewChanged
		}
		if err := update(); err != nil {
			return err
		}
	}
}
func writeInactiveStatus(store *deviceclient.Store, options Options, state string) (Status, error) {
	lkg := store.LKG()
	if lkg == nil {
		return Status{}, errors.New("device has no accepted view")
	}
	generation, err := options.Generation()
	if err != nil {
		return Status{}, err
	}
	local, err := LoadLocalState(options.LocalState, generation)
	if err != nil {
		return Status{}, err
	}
	value := Status{Schema: 3, DeviceID: lkg.View.DeviceID, ViewDigest: lkg.ViewDigest, FactFrontier: lkg.FactFrontier, Preference: local.Preference, NetworkGeneration: generation, Selections: []SelectionStatus{}, Observations: []clientmodel.Observation{}, Runtime: state}
	return value, WriteStatus(options.Status, value)
}
func waitForRepair(ctx context.Context, store *deviceclient.Store, options Options) error {
	for {
		status, err := writeInactiveStatus(store, options, "error")
		if err != nil {
			return err
		}
		pending, cancel := context.WithTimeout(ctx, 20*time.Second)
		_ = deviceclient.Report(pending, store, control.DeviceReport{ReportedAt: options.Now().UnixMilli(), NetworkGeneration: status.NetworkGeneration, Selections: []control.ReportSelection{}, Observations: []control.Observation{}, Components: []control.ComponentReadback{}, Runtime: control.RuntimeReadback{State: "error", ErrorCode: "runtime_apply_failed"}})
		cancel()
		timer := time.NewTimer(options.RefreshPoll)
		reloadRequested := false
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil
		case <-options.Reload:
			timer.Stop()
			reloadRequested = true
		case <-timer.C:
		}
		changed, err := certifiedViewChanged(ctx, store, options.Log)
		if err != nil || changed || reloadRequested {
			return err
		}
	}
}

// Run persists accepted authority before execution. Failed application retains
// that authority and the authenticated repair channel; it cannot revive a grant.
func Run(ctx context.Context, options Options) (retErr error) {
	options.defaults()
	if err := requireCaptureBoundary(options.Capture); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	lock, err := runtimeNetworkLock(options)
	if err != nil {
		return err
	}
	if lock != nil {
		defer lock.Close()
	}
	if err := cleanupRecordedWireGuard(options); err != nil {
		return err
	}
	if err := os.Remove(options.Status); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	defer func() {
		if errors.Is(retErr, errCertifiedPersistence) {
			_ = os.Remove(options.Status)
		}
	}()
	store, err := deviceclient.Load(options.DeviceState)
	if err != nil {
		return err
	}
	if _, err := certifiedViewChanged(ctx, store, options.Log); err != nil {
		return err
	}
	for {
		err := runGeneration(ctx, options, store)
		if errors.Is(err, errCertifiedPersistence) {
			return err
		}
		if errors.Is(err, errRuntimeCleanup) || errors.Is(err, ErrWireGuardCleanup) || errors.Is(err, ErrWireGuardOwnership) {
			_, statusErr := writeInactiveStatus(store, options, "error")
			return errors.Join(err, statusErr)
		}
		if ctx.Err() != nil {
			_, err := writeInactiveStatus(store, options, "stopped")
			return err
		}
		if errors.Is(err, errCertifiedViewChanged) {
			continue
		}
		if err == nil {
			return nil
		}
		fmt.Fprintln(options.Log, "accepted configuration is saved; runtime application failed")
		if err := waitForRepair(ctx, store, options); err != nil {
			return err
		}
		if ctx.Err() != nil {
			return nil
		}
	}
}

func deriveLinuxAccessRuntime(config string, endpointExclusions []string) (string, error) {
	var document map[string]any
	if err := json.Unmarshal([]byte(config), &document); err != nil {
		return "", errors.New("access runtime is invalid")
	}
	inbounds, ok := document["inbounds"].([]any)
	if !ok {
		return "", errors.New("access runtime inbounds are invalid")
	}
	managed := 0
	for _, raw := range inbounds {
		inbound, ok := raw.(map[string]any)
		if !ok || inbound["type"] != "tun" {
			continue
		}
		if inbound["tag"] != "tun-in" || inbound["auto_route"] != true {
			return "", errors.New("access runtime TUN contract is invalid")
		}
		if existing, found := inbound["address"]; found {
			values, ok := existing.([]any)
			if !ok || len(values) != 1 || values[0] != "172.19.0.1/30" {
				return "", errors.New("access runtime TUN address conflicts with the Linux platform boundary")
			}
		}
		if existing, found := inbound["stack"]; found && existing != "system" {
			return "", errors.New("access runtime TUN stack conflicts with the Linux platform boundary")
		}
		if _, found := inbound["route_exclude_address"]; found {
			return "", errors.New("signed access runtime cannot define local endpoint route exclusions")
		}
		inbound["address"] = []string{"172.19.0.1/30"}
		inbound["stack"] = "system"
		if len(endpointExclusions) != 0 {
			inbound["route_exclude_address"] = append([]string(nil), endpointExclusions...)
		}
		managed++
	}
	if managed != 1 {
		return "", errors.New("access runtime must contain exactly one managed TUN")
	}
	route, found := document["route"].(map[string]any)
	if document["route"] != nil && !found {
		return "", errors.New("access runtime route is invalid")
	}
	if !found {
		route = map[string]any{}
		document["route"] = route
	}
	if existing, found := route["auto_detect_interface"]; found && existing != true {
		return "", errors.New("access runtime interface detection conflicts with the Linux platform boundary")
	}
	route["auto_detect_interface"] = true
	body, err := json.Marshal(document)
	return string(body), err
}

func writeConfig(path, config string) error {
	return atomicJSONBytes(path, []byte(config))
}

func atomicJSONBytes(path string, body []byte) (retErr error) {
	if len(body) == 0 {
		return errors.New("runtime config is empty")
	}
	directory := filepath.Dir(path)
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return err
	}
	file, err := os.CreateTemp(directory, ".runtime-config-*")
	if err != nil {
		return err
	}
	temporary := file.Name()
	defer func() {
		_ = file.Close()
		if retErr != nil {
			_ = os.Remove(temporary)
		}
	}()
	if err = file.Chmod(0o600); err == nil {
		_, err = file.Write(body)
	}
	if err == nil {
		err = file.Sync()
	}
	if closeErr := file.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	return os.Rename(temporary, path)
}

func checkRuntime(singBox, config string) error {
	command := exec.Command(singBox, "check", "-c", config)
	if output, err := command.CombinedOutput(); err != nil {
		return fmt.Errorf("sing-box preflight failed: %w: %s", err, string(output))
	}
	return nil
}

func preflightRuntimeConfig(singBox, config string) error {
	directory, err := os.MkdirTemp("", "loom-runtime-preflight-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(directory)
	if err := os.Chmod(directory, 0o700); err != nil {
		return err
	}
	path := filepath.Join(directory, "config.json")
	if err := writeConfig(path, config); err != nil {
		return err
	}
	return checkRuntime(singBox, path)
}

func stopProcess(command *exec.Cmd, done <-chan error) error {
	// Wait completion, including a nonzero process exit, proves termination.
	// Signal delivery alone does not.
	select {
	case <-done:
		return nil
	default:
	}
	if command.Process == nil {
		return errors.Join(errRuntimeCleanup, errors.New("runtime process handle is absent"))
	}
	_ = command.Process.Signal(os.Interrupt)
	timer := time.NewTimer(10 * time.Second)
	defer timer.Stop()
	select {
	case <-done:
		return nil
	case <-timer.C:
	}
	killErr := command.Process.Kill()
	timer.Reset(3 * time.Second)
	select {
	case <-done:
		return nil
	case <-timer.C:
		return errors.Join(errRuntimeCleanup, errors.New("runtime termination could not be verified"), killErr)
	}
}

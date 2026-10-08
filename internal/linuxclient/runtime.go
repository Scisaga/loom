package linuxclient

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"slices"
	"sort"
	"syscall"
	"time"

	"loom/internal/clientadapter"
	"loom/internal/clientmodel"
	"loom/internal/clientruntime"
	"loom/internal/control"
	"loom/internal/deviceclient"
)

var errCertifiedViewChanged = errors.New("a newly accepted device view is available")
var errCertifiedPersistence = errors.New("device view persistence failed")
var errRuntimeCleanup = errors.New("runtime generation cleanup failed")
var errRuntimeAddressChanged = errors.New("authenticated runtime hostname resolved to a new address")

type Options struct {
	DeviceState         string
	LocalState          string
	Status              string
	Config              string
	SingBox             string
	WireGuard           string
	IP                  string
	NFT                 string
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
	captureNamespace    *os.File
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
	if options.NFT == "" {
		options.NFT = "/usr/sbin/nft"
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
		if options.captureNamespace != nil {
			return func(ctx context.Context) ProbeResult {
				return namespaceBusinessProbe(ctx, options.captureNamespace, group.Targets[0])
			}
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
			return Activation{}, err
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
			server = server || role == "internet_egress" || role == "forward" || role == "control"
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
func accessRuntimeConfigForCapture(view control.DeviceView, secret string, endpointExclusions []string, capture string, websites ...clientadapter.WebsiteAccess) (string, error) {
	if err := validateCapture(capture); err != nil {
		return "", err
	}
	config, err := clientadapter.ManagedRuntimeConfig(view, secret, websites...)
	if err != nil {
		return "", err
	}
	config, err = withBlockedSelectors(config)
	if err != nil {
		return "", err
	}
	if capture == "mixed" {
		return deriveLinuxMixedRuntime(config)
	}
	// Resource DNS and transport sockets use the pinned underlay namespace.
	// Keep their certified names: a TUN route exclusion cannot provide underlay
	// connectivity and must not require a pure projection to resolve a name.
	sort.Strings(endpointExclusions)
	config, err = deriveLinuxAccessRuntime(config, endpointExclusions)
	if err != nil {
		return "", err
	}
	if len(websites) == 1 && websites[0].Port != 0 {
		config, err = withIsolatedWebsiteProxy(config)
		if err != nil {
			return "", err
		}
	}
	return clientadapter.WithTUNDomainDNS(config)
}

// The workload namespace has no physical NIC. Its private website addresses
// stay outside TUN; an explicit loopback proxy reaches the pinned underlay.
func withIsolatedWebsiteProxy(config string) (string, error) {
	var document map[string]json.RawMessage
	if err := json.Unmarshal([]byte(config), &document); err != nil {
		return "", err
	}
	var inbounds []json.RawMessage
	if err := json.Unmarshal(document["inbounds"], &inbounds); err != nil || len(inbounds) != 1 {
		return "", errors.New("isolated website proxy requires one managed TUN")
	}
	inbounds = append(inbounds, json.RawMessage(`{"type":"mixed","tag":"website-proxy","listen":"127.0.0.1","listen_port":1080}`))
	document["inbounds"], _ = json.Marshal(inbounds)
	body, err := json.Marshal(document)
	return string(body), err
}

func nodeRuntimeConfig(view control.DeviceView, secret string, exclusions []string, capture string, executions []hy2Execution, websites ...clientadapter.WebsiteAccess) (string, error) {
	if capture == "tun" && len(executions) != 0 {
		return "", errors.New("server listeners require the separate host projection")
	}
	return projectNodeRuntime(view, secret, exclusions, capture, executions, slices.Contains(view.Responsibilities, "access"), websites...)
}
func projectNodeRuntime(view control.DeviceView, secret string, exclusions []string, capture string, executions []hy2Execution, access bool, websites ...clientadapter.WebsiteAccess) (string, error) {
	if err := clientadapter.ValidateOverlayUnderlay(view); err != nil {
		return "", err
	}
	config := `{"inbounds":[],"outbounds":[{"tag":"reject","type":"block"}],"route":{"final":"reject","rules":[]}}`
	var err error
	if access {
		config, err = accessRuntimeConfigForCapture(view, secret, exclusions, capture, websites...)
	} else if view.RuntimeProfile != nil {
		config, err = clientadapter.RuntimeSource(view, secret, false)
		if err == nil {
			config, err = clientadapter.WithManagedDNS(config, view.DNSServers, false)
		}
		if err == nil {
			config, err = clientadapter.WithOverlayDNS(config, view.DNSRecords, false)
		}
	}
	if err != nil {
		return "", err
	}
	config, err = appendHY2Runtime(config, view, executions)
	if err != nil {
		return "", err
	}
	config, err = clientadapter.WithRuntimeDNSCache(config)
	if err != nil {
		return "", err
	}
	return clientadapter.WithNativeProbe(config, secret)
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
	if err := validateCapture(capture); err != nil {
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
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	addresses, err := deviceclient.WebsiteAddresses(ctx, view.View.WebEndpoints, view.View.DNSServers)
	if err != nil {
		return err
	}
	website, err := clientadapter.WebsiteAccessFor(view.View, addresses)
	if err != nil {
		return err
	}
	config, serverConfig, err := generationConfigs(view.View, secret, nil, capture, executions, website)
	if err != nil {
		return err
	}
	profile, _, err := projectWireGuard(view.View)
	if err != nil {
		return err
	}
	if serverConfig != "" {
		serverConfig, err = appendNativeReceivers(serverConfig, view.View, profile, nil, "/etc/wireguard/node.key")
	} else {
		config, err = appendNativeReceivers(config, view.View, profile, nil, "/etc/wireguard/node.key")
	}
	if err != nil {
		return err
	}
	if serverConfig != "" {
		if err := preflightRuntimeConfig(executable, serverConfig); err != nil {
			return err
		}
	}
	return preflightRuntimeConfig(executable, config)
}

func generationConfigs(view control.DeviceView, secret string, exclusions []string, capture string, executions []hy2Execution, websites ...clientadapter.WebsiteAccess) (string, string, error) {
	if len(websites) > 1 {
		return "", "", errors.New("generation requires one website execution input")
	}
	if len(websites) == 1 {
		prefixes, err := websites[0].Exclusions()
		if err != nil {
			return "", "", err
		}
		unique := map[string]bool{}
		for _, prefix := range append(append([]string{}, exclusions...), prefixes...) {
			unique[prefix] = true
		}
		exclusions = nil
		for prefix := range unique {
			exclusions = append(exclusions, prefix)
		}
		sort.Strings(exclusions)
	}
	if !slices.Contains(view.Responsibilities, "access") {
		capture = "mixed" // No access role means no capture process at all.
	}
	if capture != "tun" {
		config, err := nodeRuntimeConfig(view, secret, exclusions, capture, executions, websites...)
		return config, "", err
	}
	config, err := nodeRuntimeConfig(view, secret, exclusions, capture, nil, websites...)
	if err != nil {
		return "", "", err
	}
	server := ""
	ownsResources := false
	for _, resource := range view.Resources {
		ownsResources = ownsResources || resource.OwnerNodeID == view.DeviceID
	}
	if ownsResources {
		server, err = projectNodeRuntime(view, secret, nil, "mixed", executions, false)
		if err != nil {
			return "", "", err
		}
		config, server, err = bridgeHybridCapture(config, server, view, secret)
		if err != nil {
			return "", "", err
		}
	}
	config, err = withTUNUnderlay(config)
	return config, server, err
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
func reportSelection(ctx context.Context, store deviceclient.IdentityStore, lkg control.DeviceViewEnvelope, activation Activation, at time.Time, components []control.ComponentReadback, readback control.RuntimeReadback, links []control.Observation) error {
	preference, err := clientadapter.ReportedPreference(lkg.View, activation.State.Preference)
	if err != nil {
		return err
	}
	selections := []control.ReportSelection{}
	observations := append([]control.Observation{}, links...)
	observations = append(observations, activation.State.ResourceObservations...)
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
	return deviceclient.Report(ctx, store, control.DeviceReport{ReportedAt: at.UnixMilli(), ViewDigest: lkg.ViewDigest, NetworkGeneration: activation.State.NetworkGeneration, Preference: preference, Selections: selections, Observations: observations, Components: components, Runtime: readback})
}
func runtimeStatus(lkg *control.DeviceViewEnvelope, activation Activation, reported bool, readback control.RuntimeReadback) Status {
	value := Status{Schema: 3, DeviceID: lkg.View.DeviceID, ViewDigest: lkg.ViewDigest, FactFrontier: lkg.FactFrontier, Preference: activation.State.Preference, NetworkGeneration: activation.State.NetworkGeneration, Selections: activation.Selections, Observations: activation.State.Observations, Runtime: readback.State, Reported: reported}
	value.ResourceObservations = append([]control.Observation(nil), activation.State.ResourceObservations...)
	if readback.Resources != nil {
		value.Resources = *readback.Resources
	}
	return value
}
func runGeneration(ctx context.Context, options Options, store *deviceclient.Store, previous *control.DeviceViewEnvelope, transaction **wireGuardTransaction) (retErr error) {
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
	hasAccess := slices.Contains(lkg.View.Responsibilities, "access")
	hasRuntime := lkg.View.RuntimeProfile != nil
	if !hasAccess {
		options.Capture = "mixed"
	}
	var routes []clientmodel.RouteCandidate
	if hasAccess {
		routes, _, err = clientadapter.AccessProjection(lkg.View)
		if err != nil {
			return err
		}
	}
	// Every local selector starts at reject. A missing usable candidate closes
	// only its Service; it cannot briefly serve a different Preference.
	secret, err := runtimeSecret()
	if err != nil {
		return err
	}
	exclusions := []string{}
	if options.Capture == "tun" {
		exclusions, err = deviceclient.EndpointRouteExclusions(ctx, lkg.View.Endpoints, lkg.View.DNSServers)
		if err != nil {
			return err
		}
	}
	executions, err := prepareHY2Executions(lkg.View, options.ResourceInputs, options.Now())
	if err != nil {
		return err
	}
	websiteGeneration := ""
	if len(lkg.View.WebEndpoints) > 0 {
		websiteGeneration, err = options.Generation()
		if err != nil {
			return err
		}
	}
	addresses, err := deviceclient.WebsiteAddresses(ctx, lkg.View.WebEndpoints, lkg.View.DNSServers)
	if err != nil {
		return err
	}
	website, err := clientadapter.WebsiteAccessFor(lkg.View, addresses)
	if err != nil {
		return err
	}
	config, serverConfig, err := generationConfigs(lkg.View, secret, exclusions, options.Capture, executions, website)
	if err != nil {
		return err
	}
	desiredWG, _, err := projectWireGuard(lkg.View)
	if err != nil {
		return err
	}
	previousWG := (*transaction).execution()
	if *transaction == nil {
		// After a restart no accepted DNS answer survives as execution truth.
		// A hostname-to-address projection must invalidate its old samples.
		previousWG = desiredWG
	}
	wg, err := resolveWireGuardEndpoints(ctx, desiredWG, previousWG, lkg.View.DNSServers, nil)
	if err != nil {
		return err
	}
	if err := (*transaction).Cleanup(); err != nil {
		return err
	}
	*transaction = nil
	prepared, err := prepareNativeWireGuard(lkg.View, wg, options)
	if err != nil {
		return err
	}
	if serverConfig != "" {
		serverConfig, err = appendNativeReceivers(serverConfig, lkg.View, wg, prepared, options.WireGuardPrivateKey)
	} else {
		config, err = appendNativeReceivers(config, lkg.View, wg, prepared, options.WireGuardPrivateKey)
	}
	if err != nil {
		return err
	}
	if err := preflightRuntimeConfig(options.SingBox, config); err != nil && hasRuntime {
		return err
	}
	if serverConfig != "" {
		if err := preflightRuntimeConfig(options.SingBox, serverConfig); err != nil {
			return err
		}
	}
	if err := prepared.saveOwnership(); err != nil {
		return err
	}
	*transaction = prepared

	generation, err := options.Generation()
	if err != nil {
		return err
	}
	if website.Port != 0 && generation != websiteGeneration {
		return errRuntimeAddressChanged
	}
	if !options.defaultProbe {
		// An injected diagnostic may use a target outside the View's probe
		// contract, so it cannot prove cross-view sample equivalence.
		previous = nil
	}
	local, err := loadLocalStateForView(options.LocalState, generation, lkg, previous)
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(previousWG, wg) {
		local = invalidateWireGuardObservations(local, lkg.View, previousWG, wg)
		if _, err := SaveObservations(options.LocalState, local); err != nil {
			return err
		}
	}
	var done chan error
	var serverDone chan error
	var selector Selector
	pid := 0
	resourcePID := 0
	if hasRuntime {
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
		if serverConfig != "" {
			serverPath := options.Config + ".server"
			if err := writeConfig(serverPath, serverConfig); err != nil {
				return err
			}
			defer func() {
				if err := os.Remove(serverPath); err != nil && !errors.Is(err, os.ErrNotExist) {
					retErr = errors.Join(retErr, errRuntimeCleanup, err)
				}
			}()
			server := exec.Command(options.SingBox, "run", "-c", serverPath)
			server.Dir = filepath.Dir(options.Config)
			server.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
			server.Stdout, server.Stderr = options.Log, options.Log
			if err := server.Start(); err != nil {
				return err
			}
			resourcePID = server.Process.Pid
			serverDone = make(chan error, 1)
			go func() { serverDone <- server.Wait(); close(serverDone) }()
			defer func() { retErr = errors.Join(retErr, stopProcess(server, serverDone)) }()
			if err := (*transaction).activateNative(ctx, resourcePID, serverDone); err != nil {
				return err
			}
			if err := waitTransportResources(ctx, lkg.View, executions, resourcePID, options.Now, serverDone); err != nil {
				return err
			}
		}
		command := exec.Command(options.SingBox, "run", "-c", options.Config)
		command.Dir = filepath.Dir(options.Config)
		command.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
		if options.Capture == "tun" {
			command, err = tunCommand(options, false)
			if err != nil {
				return err
			}
			for _, file := range command.ExtraFiles {
				defer file.Close()
			}
		}
		command.Stdout, command.Stderr = options.Log, options.Log
		if err := command.Start(); err != nil {
			return err
		}
		pid = command.Process.Pid
		done = make(chan error, 1)
		go func() { done <- command.Wait(); close(done) }()
		defer func() { retErr = errors.Join(retErr, stopProcess(command, done)) }()
		if options.Capture == "tun" {
			options.captureNamespace, err = captureNamespace(ctx, command, options.SingBox, command.ExtraFiles[2], done)
			if err != nil {
				return err
			}
			defer options.captureNamespace.Close()
		}
		if hasAccess {
			selector, err = NewHTTPSelector(config)
			if err != nil {
				return err
			}
			if options.captureNamespace != nil {
				httpSelector := selector.(*HTTPSelector)
				httpSelector.client.Transport.(*http.Transport).DialContext = namespaceDialer(options.captureNamespace)
			}
			scopes, _, err := scopesFor(routes)
			if err != nil {
				return err
			}
			if err := waitSelector(ctx, selector, scopes); err != nil {
				return err
			}
		}
		if serverConfig == "" {
			resourcePID = pid
			if err := (*transaction).activateNative(ctx, pid, done); err != nil {
				return err
			}
			if err := waitTransportResources(ctx, lkg.View, executions, pid, options.Now, done); err != nil {
				return err
			}
		}
	}
	diagnosticContext := ctx
	if hasRuntime {
		diagnosticConfig := config
		var diagnosticDial func(context.Context, string, string) (net.Conn, error)
		if serverConfig != "" {
			diagnosticConfig = serverConfig
		} else if options.captureNamespace != nil {
			diagnosticDial = namespaceDialer(options.captureNamespace)
		}
		diagnosticContext, err = clientadapter.WithNativeDiagnostic(ctx, diagnosticConfig, diagnosticDial)
		if err != nil {
			return err
		}
	}
	components, componentErr := linuxComponentReadbacks(ctx, pid)
	if componentErr != nil {
		fmt.Fprintln(options.Log, "some component readbacks unavailable")
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
		if website.Port != 0 && generation != websiteGeneration {
			return errRuntimeAddressChanged
		}
		local, err := loadLocalState(options.LocalState, generation, lkg.ViewDigest)
		if err != nil {
			return err
		}
		activation := Activation{State: local, Selections: []SelectionStatus{}}
		if err := (*transaction).readbackNative(); err != nil {
			return err
		}
		readback := control.RuntimeReadback{State: "stopped"}
		if pid != 0 || len(wg.WireGuard) != 0 {
			readback = control.RuntimeReadback{State: "running", AppliedViewDigest: lkg.ViewDigest}
		}
		if pid != 0 {
			if hasAccess {
				activation, err = Activate(ctx, selector, routes, local, nil, options.Now)
				if err != nil && !errors.Is(err, clientmodel.ErrNoUsableCandidate) {
					return err
				}
			}
			resources, err := readTransportResources(ctx, lkg.View, executions, resourcePID, options.Now())
			if err != nil {
				return err
			}
			if len(resources) != 0 {
				readback.Resources = &resources
			}
		}
		status := runtimeStatus(lkg, activation, false, readback)
		status.PossiblePermissionRestoration = store.PossiblePermissionRestoration()
		if err := WriteStatus(options.Status, status); err != nil {
			return err
		}
		// Keep the actual first attempt even if its Service probe subsequently
		// blocks the selector. Authentication and business failure are distinct.
		selected := make([]string, 0, len(activation.Selections))
		for _, selection := range activation.Selections {
			selected = append(selected, selection.CandidateID)
		}
		if len(routes) > 0 {
			activation, err = activateServices(ctx, options, lkg.View, selector, routes, local)
			if activation.State.Schema == 0 {
				return err
			}
		}
		for _, selection := range activation.Selections {
			selected = append(selected, selection.CandidateID)
		}
		resourceObservations, err := clientadapter.ObserveFirstHops(diagnosticContext, lkg.View, selected, activation.State.ResourceObservations, generation, options.Now)
		if err != nil {
			return err
		}
		activation.State.ResourceObservations = append([]control.Observation(nil), resourceObservations...)
		saved, saveErr := SaveObservations(options.LocalState, activation.State)
		if saveErr != nil {
			return saveErr
		}
		activation.State = saved
		linkObservations, err := observeLinks(diagnosticContext, lkg.View, wg, generation, options.RefreshPoll, options.Now)
		if err != nil {
			return err
		}
		pending, cancel := context.WithTimeout(ctx, 20*time.Second)
		defer cancel()
		reportErr := reportSelection(pending, store, *lkg, activation, options.Now(), components, readback, linkObservations)
		if reportErr != nil {
			fmt.Fprintln(options.Log, "private runtime report unavailable")
		}
		status = runtimeStatus(lkg, activation, reportErr == nil, readback)
		status.PossiblePermissionRestoration = store.PossiblePermissionRestoration()
		return WriteStatus(options.Status, status)
	}
	if err := update(); err != nil {
		return err
	}
	if options.captureNamespace != nil {
		workloads, err := serveCaptureWorkloads(ctx, options.Config, options.captureNamespace)
		if err != nil {
			return err
		}
		defer func() {
			if err := workloads.Close(); err != nil {
				retErr = errors.Join(retErr, errRuntimeCleanup, err)
			}
		}()
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
		case <-serverDone:
			return errors.New("server sing-box process exited")
		case <-ticker.C:
		case <-options.Reload:
		}
		if changed, err := certifiedViewChanged(ctx, store, options.Log); err != nil {
			return err
		} else if changed {
			return errCertifiedViewChanged
		}
		resolved, err := resolveWireGuardEndpoints(ctx, desiredWG, wg, lkg.View.DNSServers, nil)
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			fmt.Fprintln(options.Log, "authenticated WireGuard DNS refresh failed; retaining this generation's peer address")
		} else if !reflect.DeepEqual(wg, resolved) {
			currentGeneration, err := options.Generation()
			if err != nil {
				return err
			}
			state, err := loadLocalState(options.LocalState, currentGeneration, lkg.ViewDigest)
			if err != nil {
				return err
			}
			if _, err := SaveObservations(options.LocalState, invalidateWireGuardObservations(state, lkg.View, wg, resolved)); err != nil {
				return err
			}
			return errRuntimeAddressChanged
		}
		if err := update(); err != nil {
			return err
		}
	}
}

// This runtime-only block never becomes an authorized candidate or Selection.
// The original signed profile and its candidate order remain unchanged.
func withBlockedSelectors(config string) (string, error) {
	var document map[string]any
	if err := json.Unmarshal([]byte(config), &document); err != nil {
		return "", err
	}
	outbounds, ok := document["outbounds"].([]any)
	if !ok {
		return "", errors.New("runtime outbounds are invalid")
	}
	block := false
	for _, raw := range outbounds {
		value, ok := raw.(map[string]any)
		if !ok {
			return "", errors.New("runtime outbound is invalid")
		}
		if value["tag"] == blockedSelection {
			if value["type"] != "block" {
				return "", errors.New("runtime rejection outbound is invalid")
			}
			block = true
		}
		if value["type"] == "selector" {
			members, ok := value["outbounds"].([]any)
			if !ok {
				return "", errors.New("runtime selector is invalid")
			}
			value["outbounds"] = append(members, blockedSelection)
			value["default"] = blockedSelection
		}
	}
	if !block {
		return "", errors.New("runtime rejection outbound is missing")
	}
	body, err := json.Marshal(document)
	return string(body), err
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
	value.PossiblePermissionRestoration = store.PossiblePermissionRestoration()
	return value, WriteStatus(options.Status, value)
}
func waitForRepair(ctx context.Context, store *deviceclient.Store, options Options) error {
	components, _ := linuxComponentReadbacks(ctx, 0)
	for {
		status, err := writeInactiveStatus(store, options, "error")
		if err != nil {
			return err
		}
		pending, cancel := context.WithTimeout(ctx, 20*time.Second)
		preference, prefErr := clientadapter.ReportedPreference(store.LKG().View, status.Preference)
		if prefErr == nil {
			_ = deviceclient.Report(pending, store, control.DeviceReport{ReportedAt: options.Now().UnixMilli(), NetworkGeneration: status.NetworkGeneration, Preference: preference, Selections: []control.ReportSelection{}, Observations: []control.Observation{}, Components: components, Runtime: control.RuntimeReadback{State: "error", ErrorCode: "runtime_apply_failed"}})
		}
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
	if err := validateCapture(options.Capture); err != nil {
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
	var transaction *wireGuardTransaction
	var previous *control.DeviceViewEnvelope
	for {
		before := store.LKG()
		err := runGeneration(ctx, options, store, previous, &transaction)
		if errors.Is(err, errCertifiedViewChanged) && !errors.Is(err, errRuntimeCleanup) && ctx.Err() == nil {
			previous = before
			continue
		}
		// Every stop or failed application closes owned resources before any
		// inactive status. A failed cleanup must not be retried by this loop.
		if !errors.Is(err, ErrWireGuardCleanup) {
			if cleanupErr := transaction.Cleanup(); cleanupErr != nil {
				err = errors.Join(err, errRuntimeCleanup, cleanupErr)
			} else {
				transaction = nil
			}
		}
		previous = nil
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
		if errors.Is(err, errRuntimeAddressChanged) {
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
		inbound["address"] = []string{"172.19.0.1/30", "2001:db8::1/126"}
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
	if err := clientruntime.RequireTUNDNSExecutor(context.Background(), singBox, []byte(config)); err != nil {
		return err
	}
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

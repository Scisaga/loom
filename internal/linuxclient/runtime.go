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
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
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
	RefreshPoll         time.Duration
	Reload              <-chan os.Signal
	Capture             string
	ResourceInputs      string
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
	if options.RefreshPoll <= 0 {
		options.RefreshPoll = 15 * time.Second
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
func selectedProbeURLs(view control.DeviceView, preference clientmodel.Preference) []string {
	id := clientmodel.SelectedServiceID(view, preference)
	for _, service := range view.Services {
		if service.ID == id {
			return service.ProbeURLs
		}
	}
	return nil
}

func activateServices(ctx context.Context, options Options, view control.DeviceView, selector Selector, routes []clientmodel.RouteCandidate, state LocalState, _ bool) (Activation, error) {
	return activateServicesWithLinkSamples(ctx, options, view, selector, routes, state, nil, nil, false)
}
func activateServicesWithLinkSamples(ctx context.Context, options Options, view control.DeviceView, selector Selector, routes []clientmodel.RouteCandidate, state LocalState, local []control.Observation, remote []control.DeviceLinkObservation, _ bool, onlyScopes ...string) (Activation, error) {
	graphs, err := clientadapter.PolicyGraphs(view, clientmodel.MeasurementPolicies(state.Preference))
	if err != nil {
		return Activation{}, err
	}
	state.graphs = graphs
	state.NativeExecutionSpec, err = clientadapter.NativeExecutionSpec(view, routes, graphs, state.Preference.PolicyID)
	if err != nil {
		return Activation{}, err
	}
	return activateWithLinkSamples(ctx, selector, routes, state, local, remote, selectedProbeURLs(view, state.Preference), options.Now, clientmodel.SelectorScopes(view)...)
}

func accessView(envelope *control.DeviceViewEnvelope) (*control.DeviceViewEnvelope, error) {
	if envelope == nil || envelope.View.Platform != "linux" || envelope.Validate() != nil {
		return nil, errors.New("Linux device has no valid runtime view")
	}
	if !control.HasRuntime(envelope.View) {
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
	config, err = clientadapter.WithBlockedSelectors(config)
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
	return config, nil
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

func nodeRuntimeConfig(view control.DeviceView, secret string, exclusions []string, capture string, executions []resourceExecution, websites ...clientadapter.WebsiteAccess) (string, error) {
	if capture == "tun" && len(executions) != 0 {
		return "", errors.New("server listeners require the separate host projection")
	}
	return projectNodeRuntime(view, secret, exclusions, capture, executions, slices.Contains(view.Responsibilities, "access"), websites...)
}
func projectNodeRuntime(view control.DeviceView, secret string, exclusions []string, capture string, executions []resourceExecution, access bool, websites ...clientadapter.WebsiteAccess) (string, error) {
	if err := clientadapter.ValidateOverlayUnderlay(view); err != nil {
		return "", err
	}
	config := `{"inbounds":[],"outbounds":[{"tag":"reject","type":"block"}],"route":{"final":"reject","rules":[]}}`
	var err error
	if access {
		config, err = accessRuntimeConfigForCapture(view, secret, exclusions, capture, websites...)
	} else if control.HasRuntime(view) {
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
	return config, nil
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
	return PreflightResources(state, executable, capture, "", "/etc/wireguard/node.key")
}
func PreflightResources(state, executable, capture, inputPath, keyPath string) error {
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
	executions, err := prepareResourceExecutions(view.View, inputPath, time.Now())
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
	config, serverConfig, err := preflightProjectedConfigs(view.View, secret, capture, executions, website, keyPath)
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

// Preflight keeps sender descriptions and certified DNS inputs intact. Only
// the bounded native resource worker resolves requested transport peers.
func preflightProjectedConfigs(view control.DeviceView, secret, capture string, executions []resourceExecution, website clientadapter.WebsiteAccess, keyPath string) (string, string, error) {
	config, serverConfig, err := generationConfigs(view, secret, nil, capture, executions, website)
	if err != nil {
		return "", "", err
	}
	profile, _, err := projectWireGuard(view, executions)
	if err != nil {
		return "", "", err
	}
	if serverConfig != "" {
		serverConfig, err = appendNativeWireGuard(serverConfig, view, profile, nil, keyPath)
	} else {
		config, err = appendNativeWireGuard(config, view, profile, nil, keyPath)
	}
	return config, serverConfig, err
}

func generationConfigs(view control.DeviceView, secret string, exclusions []string, capture string, executions []resourceExecution, websites ...clientadapter.WebsiteAccess) (string, string, error) {
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
	config, err = clientadapter.WithTUNDomainDNS(config)
	if err != nil {
		return "", "", err
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
	pending, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	changed, _, err := refreshCertifiedView(pending, store, log, deviceclient.Fetch)
	return changed, err
}

func refreshCertifiedView(ctx context.Context, store *deviceclient.Store, log io.Writer,
	fetch func(context.Context, deviceclient.IdentityStore) (control.DeviceViewEnvelope, error)) (bool, bool, error) {
	before := store.LKG()
	sameView := func() bool {
		current := store.LKG()
		return before != nil && current != nil && before.ViewDigest == current.ViewDigest
	}
	if changed, err := store.Reload(); err != nil {
		return false, false, errors.Join(errCertifiedPersistence, err)
	} else if changed && !sameView() {
		return true, true, nil
	}
	envelope, err := fetch(ctx, store)
	if changed, readErr := store.Reload(); readErr != nil {
		return false, false, errors.Join(errCertifiedPersistence, readErr)
	} else if current := store.LKG(); changed || before != nil && current != nil && before.Signature != current.Signature {
		// A concurrent durable update wins over this in-flight response, even
		// when only its authenticated frontier advanced. Follow again using it.
		return !sameView(), true, nil
	}
	if err != nil {
		if ctx.Err() == nil {
			fmt.Fprintln(log, "private configuration refresh unavailable; retaining the accepted view")
		}
		return false, false, nil
	}
	changed, err := acceptCertifiedView(store, envelope)
	return changed, true, err
}
func selectionReport(ctx context.Context, lkg control.DeviceViewEnvelope, activation Activation, at time.Time, components []control.ComponentReadback, readback control.RuntimeReadback, links []control.Observation, counters *control.WireGuardCounters) (control.DeviceReport, error) {
	preference, err := clientadapter.ReportedPolicyID(lkg.View, activation.State.Preference)
	if err != nil {
		return control.DeviceReport{}, err
	}
	selections := []control.ReportSelection{}
	complete := readback.State == "running" && readback.AppliedViewDigest == lkg.ViewDigest
	if complete {
		selections, err = clientadapter.ReportSelections(lkg.View, activation.State.Preference, activation.Selections)
		if err != nil {
			return control.DeviceReport{}, err
		}
	}
	observations := append([]control.Observation{}, links...)
	observations = append(observations, activation.State.ResourceObservations...)
	if !readback.HasCurrentPermissions(lkg.ViewDigest) {
		observations = []control.Observation{}
	}
	// Only an actual authenticated target sample becomes a wire observation.
	// Targetless old caches and custom diagnostics grant no business health.
	execution, err := control.ProjectDeviceCandidates(lkg.View, clientmodel.MeasurementPolicies(activation.State.Preference))
	if err != nil {
		return control.DeviceReport{}, err
	}
	for _, group := range execution.BusinessProbeTargets {
		if !complete {
			break
		}
		for _, value := range activation.State.Observations {
			if !slices.Contains(group.Targets, value.Target) || value.NetworkGeneration != activation.State.NetworkGeneration {
				continue
			}
			for _, route := range execution.Routes {
				if route.ID != value.CandidateID || route.ServiceID != group.ServiceID || value.Scope != control.AccessSelectorScope || value.Action != "https_request" {
					continue
				}
				observed, e1 := time.Parse(time.RFC3339, value.ObservedAt)
				until, e2 := time.Parse(time.RFC3339, value.ValidUntil)
				if e1 != nil || e2 != nil {
					continue
				}
				duration := value.MetricMillis
				observations = append(observations, control.Observation{Level: "service", ServiceID: route.ServiceID, CandidateID: route.ID, Target: value.Target, Action: "https_request", SpecDigest: route.SpecDigest, NetworkGeneration: activation.State.NetworkGeneration, Result: value.Result, ObservedAt: observed.UnixMilli(), ValidUntil: until.UnixMilli(), DurationMS: &duration})
			}
		}
	}
	order := func(value control.Observation) string {
		return strings.Join([]string{value.Level, value.ServiceID, value.CandidateID, value.ResourceID, value.LinkID, value.Target, value.Action, value.SpecDigest}, "\x00")
	}
	sort.Slice(observations, func(i, j int) bool { return order(observations[i]) < order(observations[j]) })
	observations, err = clientadapter.CurrentReportObservations(observations, activation.State.NetworkGeneration, at.UnixMilli())
	if err != nil {
		return control.DeviceReport{}, err
	}
	localNetworks, _ := collectLocalNetworks(ctx, lkg.View)
	lanChoices, err := clientadapter.ReportedLANPolicyIDs(lkg.View, activation.State.Preference)
	if err != nil {
		return control.DeviceReport{}, err
	}
	return control.DeviceReport{LANPolicyIDs: lanChoices, ReportedAt: at.UnixMilli(), ViewDigest: lkg.ViewDigest, NetworkGeneration: activation.State.NetworkGeneration, PolicyID: preference, LocalNetworks: localNetworks, WireGuardCounters: counters, Selections: selections, Observations: observations, Components: components, Runtime: readback}, nil
}
func runtimeStatus(lkg *control.DeviceViewEnvelope, activation Activation, reported bool, readback control.RuntimeReadback) Status {
	value := Status{Schema: 3, DeviceID: lkg.View.DeviceID, ViewDigest: lkg.ViewDigest, FactFrontier: lkg.FactFrontier, Preference: activation.State.Preference, NetworkGeneration: activation.State.NetworkGeneration, Selections: activation.Selections, Observations: activation.State.Observations, Runtime: readback.State, Reported: reported}
	value.ResourceObservations = append([]control.Observation(nil), activation.State.ResourceObservations...)
	if readback.State != "running" {
		value.Selections, value.Observations = []SelectionStatus{}, []clientmodel.Observation{}
		value.ResourceObservations = nil
		return value
	}
	if readback.Resources != nil {
		value.Resources = *readback.Resources
	}
	return value
}

var errWGListenerUnconfirmed = errors.New("WG listener application is not confirmed")

func resourceRuntimeReadback(ctx context.Context, lkg *control.DeviceViewEnvelope, executions []resourceExecution, pid int, now time.Time,
	periodic bool, transaction *wireGuardTransaction) (control.RuntimeReadback, error) {
	resources, err := readTransportResources(ctx, lkg.View, executions, pid, now)
	if err != nil {
		if ctx.Err() != nil || !periodic || !errors.Is(err, errResourceReadbackTimeout) {
			return control.RuntimeReadback{}, err
		}
		if err := transaction.readbackNative(); err != nil {
			return control.RuntimeReadback{}, err
		}
		return control.RuntimeReadback{State: "unknown", ErrorCode: "resource_readback_timeout"}, nil
	}
	readback := control.RuntimeReadback{State: "running", AppliedViewDigest: lkg.ViewDigest}
	if len(resources) != 0 {
		readback.Resources = &resources
	}
	return readback, nil
}

func runGeneration(ctx context.Context, options Options, store *deviceclient.Store, previous *control.DeviceViewEnvelope, transaction **wireGuardTransaction) (retErr error) {
	options.defaults()
	ctx, cancelGeneration := context.WithCancel(ctx)
	defer cancelGeneration()
	defer func() {
		if err := os.Remove(options.Status); err != nil && !errors.Is(err, os.ErrNotExist) {
			retErr = errors.Join(retErr, errRuntimeCleanup, err)
		}
	}()
	lkg, err := runtimeView(store)
	if err != nil {
		return err
	}
	executionDigest, err := control.RuntimeExecutionDigest(lkg.View)
	if err != nil {
		return err
	}
	sameExecution := func(current *control.DeviceViewEnvelope) bool {
		if current == nil {
			return false
		}
		digest, err := control.RuntimeExecutionDigest(current.View)
		return err == nil && digest == executionDigest
	}
	hasAccess := slices.Contains(lkg.View.Responsibilities, "access")
	hasRuntime := control.HasRuntime(lkg.View)
	if !hasAccess {
		options.Capture = "mixed"
	}
	var routes []clientmodel.RouteCandidate
	if hasAccess {
		routes, _, err = clientadapter.AccessProjection(lkg.View, clientmodel.MeasurementPolicies(store.Preference()))
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
	executions, err := prepareResourceExecutions(lkg.View, options.ResourceInputs, options.Now())
	if err != nil {
		return err
	}
	localInputsDigest, err := resourceInputsDigest(appliedResourceInputs(executions))
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
	connected, _ := clientadapter.ConnectedIPv4Prefixes()
	var localNetworks []control.LocalNetworkPrefix
	for _, service := range lkg.View.Services {
		mapping := service.LocalNetwork
		if mapping != nil && mapping.GatewayNodeID == lkg.View.DeviceID && mapping.LocalPrefix == mapping.VirtualPrefix {
			if networks, err := collectLocalNetworks(ctx, lkg.View); err == nil && networks != nil {
				localNetworks = *networks
			}
			break
		}
	}
	config, err = clientadapter.WithLocalNetworkBoundary(config, connected, localNetworks...)
	if err != nil {
		return err
	}
	if serverConfig != "" {
		serverConfig, err = clientadapter.WithLocalNetworkBoundary(serverConfig, connected, localNetworks...)
		if err != nil {
			return err
		}
	}
	desiredWG, _, err := projectWireGuard(lkg.View, executions)
	if err != nil {
		return err
	}
	previousWG := (*transaction).execution()
	if *transaction == nil {
		// After a restart no accepted DNS answer survives as execution truth.
		// A hostname-to-address projection must invalidate its old samples.
		previousWG = desiredWG
	}
	wg := desiredWG
	if err := (*transaction).Cleanup(); err != nil {
		return err
	}
	*transaction = nil
	prepared, err := prepareNativeWireGuard(lkg.View, wg, options)
	if err != nil {
		return err
	}
	if serverConfig != "" {
		serverConfig, err = appendNativeWireGuard(serverConfig, lkg.View, wg, prepared, options.WireGuardPrivateKey)
	} else {
		config, err = appendNativeWireGuard(config, lkg.View, wg, prepared, options.WireGuardPrivateKey)
	}
	if err != nil {
		return err
	}
	config, err = withPersistentDNSCache(config, options.DeviceState)
	if err != nil {
		return err
	}
	if serverConfig != "" {
		serverConfig, err = withPersistentDNSCache(serverConfig, options.DeviceState)
		if err != nil {
			return err
		}
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
	local, err := loadLocalStateForView(options.LocalState, generation, lkg, previous, store.Preference())
	if err != nil {
		return err
	}
	local.Preference = store.Preference()
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
		if err := writeNativeResourceConfig(options.Config, config); err != nil {
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
			if err := writeNativeResourceConfig(serverPath, serverConfig); err != nil {
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
			if err := waitTransportResources(ctx, lkg.View, executions, resourcePID, options.Now, serverDone); err != nil {
				return err
			}
			if err := (*transaction).activateNative(ctx, resourcePID, serverDone); err != nil {
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
			selectorConfig := config
			if serverConfig != "" {
				selectorConfig = serverConfig
			}
			selector, err = NewHTTPSelector(selectorConfig)
			if err != nil {
				return err
			}
			if options.captureNamespace != nil && serverConfig == "" {
				httpSelector := selector.(*HTTPSelector)
				httpSelector.SetDialer(namespaceDialer(options.captureNamespace))
			}
			scopes, _, err := scopesFor(routes, clientmodel.SelectorScopes(lkg.View)...)
			if err != nil {
				return err
			}
			if err := waitSelector(ctx, selector, scopes); err != nil {
				return err
			}
		}
		if serverConfig == "" {
			resourcePID = pid
			if err := waitTransportResources(ctx, lkg.View, executions, pid, options.Now, done); err != nil {
				return err
			}
			if err := (*transaction).activateNative(ctx, pid, done); err != nil {
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
	var forwardSelector *clientadapter.HTTPSelector
	var forwardMemory map[string]clientmodel.SelectionMemory
	needsSharedMeasurements := hasAccess || slices.Contains(lkg.View.Responsibilities, "forward")
	if hasRuntime && slices.Contains(lkg.View.Responsibilities, "forward") {
		forwardConfig := config
		if serverConfig != "" {
			forwardConfig = serverConfig
		}
		forwardSelector, err = clientadapter.NewHTTPSelector(forwardConfig)
		if err != nil {
			return err
		}
		if serverConfig == "" && options.captureNamespace != nil {
			forwardSelector.SetDialer(namespaceDialer(options.captureNamespace))
		}
	}
	components, componentErr := linuxComponentReadbacks(ctx, pid)
	if componentErr != nil {
		fmt.Fprintln(options.Log, "some component readbacks unavailable")
	}
	refreshRequests := make(chan struct{}, 1)
	refreshNotices := make(chan string, 1)
	privateFailures := make(chan error, 1)
	linkRequests := make(chan struct{}, 1)
	linkResults := make(chan control.DeviceLinkObservations, 1)
	var remoteLinks []control.DeviceLinkObservation
	reportRequests := make(chan *runtimeReportAttempt, 1)
	reportResults := make(chan runtimeReportResult, 1)
	var pendingReport *runtimeReportAttempt
	var nodeMeasurements []control.Observation
	var workMu sync.Mutex
	var cancelWork context.CancelFunc
	interruptWork := func() {
		workMu.Lock()
		defer workMu.Unlock()
		if cancelWork != nil {
			cancelWork()
		}
	}
	var privateWorkers sync.WaitGroup
	privateWorkers.Add(3)
	go func() {
		defer privateWorkers.Done()
		refreshPrivateLinkObservations(ctx, store, linkRequests, linkResults)
	}()
	go func() {
		defer privateWorkers.Done()
		refreshPrivateConfiguration(ctx, store, refreshRequests, refreshNotices, privateFailures, cancelGeneration, interruptWork)
	}()
	go func() {
		defer privateWorkers.Done()
		uploadRuntimeReports(ctx, reportRequests, reportResults, func(ctx context.Context, report control.DeviceReport) error {
			pending, cancel := context.WithTimeout(ctx, 20*time.Second)
			defer cancel()
			return deviceclient.Report(pending, store, report)
		})
	}()
	defer func() {
		cancelGeneration()
		privateWorkers.Wait()
		select {
		case err := <-privateFailures:
			retErr = errors.Join(retErr, err)
		default:
		}
	}()
	offerLatest(refreshRequests, struct{}{})
	if needsSharedMeasurements {
		offerLatest(linkRequests, struct{}{})
	}
	lastPreference := clientmodel.Preference{}
	var selectionMemory map[string]clientmodel.SelectionMemory
	var nativeObservations []clientmodel.Observation
	var nativeActivation Activation
	invalidateNativeWG := func() {
		for _, route := range routes {
			if route.PolicyID == store.Preference().PolicyID && (route.Transport == "wireguard" || route.Transport == "forward") {
				if memory, exists := selectionMemory[control.AccessSelectorScope]; exists {
					memory.NativeBinding = nil
					selectionMemory[control.AccessSelectorScope] = memory
				}
				nativeObservations = nil
				return
			}
		}
	}
	wgListenerConfirmed := true
	permissionCurrent := !hasRuntime
	resourcesReady := !hasRuntime
	permissionReadback := func(current *control.DeviceViewEnvelope, value control.RuntimeReadback) control.RuntimeReadback {
		if permissionCurrent && sameExecution(current) && (value.State == "running" || value.State == "unknown") {
			value.PermissionViewDigest = current.ViewDigest
		}
		return value
	}
	resourceSource := func() string {
		if serverConfig != "" {
			return serverConfig
		}
		return config
	}
	reconcileResources := func(ctx context.Context) (bool, error) {
		if !hasRuntime {
			return true, nil
		}
		current, err := clientadapter.NativeDiagnosticSelector(diagnosticContext)
		if err != nil {
			return false, err
		}
		ready, resourceErr := current.ReconcileRuntimeResources(ctx, resourceSource())
		if ctx.Err() != nil {
			return false, ctx.Err()
		}
		return ready && resourceErr == nil, nil
	}
	applyReceivingView := func(current *control.DeviceViewEnvelope) (bool, error) {
		if current == nil {
			return false, nil
		}
		nextDigest, err := control.RuntimeExecutionDigest(current.View)
		if err != nil {
			return false, err
		}
		nextExecutions, err := prepareResourceExecutions(current.View, options.ResourceInputs, options.Now())
		if err != nil {
			return false, err
		}
		desired, _, err := projectWireGuard(current.View, nextExecutions)
		if err != nil {
			return false, err
		}
		if !sameWireGuardHostInputs(desired, desiredWG) {
			return false, nil
		}
		nextWG := desired
		if nextWG.ListenPort != wg.ListenPort {
			invalidateNativeWG()
		}
		// Confirm permissions independently of a requested local port change.
		// On an uncertain retry never move a socket back to an old port just
		// to replay permissions that are already current.
		if !sameExecution(current) || wgListenerConfirmed {
			authWG := nextWG
			authExecutions := append([]resourceExecution{}, nextExecutions...)
			if wgListenerConfirmed && wg.ListenPort != 0 {
				authWG.ListenPort = wg.ListenPort
				authWG.WireGuard = append([]wireGuardExecutionLink{}, nextWG.WireGuard...)
				for i := range authWG.WireGuard {
					authWG.WireGuard[i].ListenPort = wg.ListenPort
				}
				for i := range authExecutions {
					if authExecutions[i].resource.Kind == "wireguard" {
						authExecutions[i].input.ListenPort = wg.ListenPort
					}
				}
			}
			authConfig, authServer, err := rebuildReceivingConfigs(current.View, options, secret, exclusions, authExecutions, website, connected, localNetworks, authWG, prepared)
			if err != nil {
				return false, err
			}
			applied, err := applyReceivingConfigs(ctx, options, config, authConfig, serverConfig, authServer)
			if err != nil || !applied.Supported || !applied.PermissionCurrent {
				return applied.Supported && applied.PermissionCurrent, err
			}
			resourcesReady = applied.ResourcesReady
			permissionCurrent = true
			if err := prepared.updateNativeExecution(authWG); err != nil {
				return false, errors.Join(errRuntimeCleanup, err)
			}
			config, serverConfig, executions = authConfig, authServer, authExecutions
			desiredWG, wg = authWG, authWG
			executionDigest = nextDigest
			localInputsDigest, err = resourceInputsDigest(appliedResourceInputs(authExecutions))
			if err != nil {
				return false, err
			}
		}
		nextConfig, nextServer, err := rebuildReceivingConfigs(current.View, options, secret, exclusions, nextExecutions, website, connected, localNetworks, nextWG, prepared)
		if err != nil {
			return false, err
		}
		if nextConfig != config || nextServer != serverConfig || !wgListenerConfirmed {
			source := nextConfig
			if nextServer != "" {
				source = nextServer
			}
			projections, err := clientadapter.ReceivingProjections(source)
			if err != nil {
				return false, err
			}
			listeners := []clientadapter.ReceiverChange{}
			for _, value := range projections {
				if value.Projection["wireguard_listener"] != nil {
					// The accepted permission is already current. A port CAS
					// must not eagerly reinstall all authorized sender peers.
					delete(value.Projection, "wireguard_peers")
					listeners = append(listeners, value)
				}
			}
			if len(listeners) == 0 {
				return false, errors.New("local update changed an unsupported receiving facility")
			}
			selector, err := clientadapter.NewHTTPSelector(source)
			if err != nil {
				return false, err
			}
			if nextServer == "" && options.captureNamespace != nil {
				selector.SetDialer(namespaceDialer(options.captureNamespace))
			}
			wgListenerConfirmed = false
			// Invalidate the prior ACK before any socket mutation. This is the
			// existing running projection becoming unknown, not a new phase.
			pendingReport = nil
			generation, err := options.Generation()
			if err != nil {
				return false, err
			}
			unknownActivation := Activation{State: LocalState{Preference: store.Preference(), NetworkGeneration: generation}}
			unknownReadback := permissionReadback(current, control.RuntimeReadback{State: "unknown", ErrorCode: "resource_ownership"})
			unknownStatus := runtimeStatus(current, unknownActivation, false, unknownReadback)
			unknownStatus.PossiblePermissionRestoration = store.PossiblePermissionRestoration()
			if err := WriteStatus(options.Status, unknownStatus); err != nil {
				return false, errors.Join(errRuntimeCleanup, err)
			}
			unknownReport, err := selectionReport(ctx, *current, unknownActivation, options.Now(), components, unknownReadback, nil, nil)
			if err != nil {
				return false, err
			}
			pendingReport = &runtimeReportAttempt{report: unknownReport, status: unknownStatus}
			offerLatest(reportRequests, pendingReport)
			// A full read can confirm a PUT whose response was interrupted.
			confirmErr := selector.ConfirmReceiverChanges(ctx, listeners)
			_, ownershipErr := readTransportOwnership(current.View, nextExecutions, resourcePID)
			if confirmErr != nil || ownershipErr != nil {
				// A once-confirmed hash can outlive a failed underlay rebind.
				// Retry the desired port if the actual socket is absent too.
				if err = selector.ApplyReceiverChanges(ctx, listeners); err != nil {
					if confirmErr := selector.ConfirmReceiverChanges(ctx, listeners); confirmErr != nil {
						return false, errors.Join(errWGListenerUnconfirmed, err, confirmErr)
					}
				}
			}
			if _, err := readTransportOwnership(current.View, nextExecutions, resourcePID); err != nil {
				return false, errors.Join(errWGListenerUnconfirmed, err)
			}
			if nextServer != "" && nextServer != serverConfig {
				if err := writeNativeResourceConfig(options.Config+".server", nextServer); err != nil {
					return false, errors.Join(errRuntimeCleanup, err)
				}
			}
			if nextConfig != config {
				if err := writeNativeResourceConfig(options.Config, nextConfig); err != nil {
					return false, errors.Join(errRuntimeCleanup, err)
				}
			}
		}
		if err := prepared.updateNativeExecution(nextWG); err != nil {
			return false, errors.Join(errRuntimeCleanup, err)
		}
		config, serverConfig, executions = nextConfig, nextServer, nextExecutions
		desiredWG, wg = desired, nextWG
		executionDigest = nextDigest
		localInputsDigest, err = resourceInputsDigest(appliedResourceInputs(nextExecutions))
		wgListenerConfirmed = true
		return true, err
	}

	applyRuntimeInputs := func(current *control.DeviceViewEnvelope) (bool, error) {
		if current == nil {
			return false, errCertifiedViewChanged
		}
		authorizationChanged := !sameExecution(current)
		if authorizationChanged {
			permissionCurrent, resourcesReady = false, false
		}
		inputs, err := resourceListenerInputs(current.View, options.ResourceInputs)
		if err != nil && !authorizationChanged {
			if wgListenerConfirmed {
				fmt.Fprintln(options.Log, "local resource inputs rejected before application; current confirmed listeners retained")
			} else {
				fmt.Fprintln(options.Log, "local resource inputs rejected; WG execution remains unconfirmed")
			}
			return true, nil
		}
		digest, digestErr := resourceInputsDigest(inputs)
		// The accepted View and local file are separate existing inputs.
		// Reload after reading both so a newer sync cannot be paired with an
		// older authorization snapshot by this work round.
		if _, err := store.Reload(); err != nil {
			return false, errors.Join(errCertifiedPersistence, err)
		}
		if latest := store.LKG(); latest == nil || latest.ViewDigest != current.ViewDigest {
			return false, clientadapter.ErrSelectionSuperseded
		}
		if !authorizationChanged && err == nil && digestErr == nil && digest == localInputsDigest && wgListenerConfirmed && permissionCurrent {
			// A successful past CAS does not prove that a later underlay
			// rebind still owns its socket. Only WG belongs to this retry path;
			// a separate Hy2 failure must not manufacture a WG port change.
			for _, execution := range executions {
				if execution.resource.Kind != "wireguard" {
					continue
				}
				owned := false
				for _, host := range []string{"::", "0.0.0.0"} {
					if processOwnsUDP(resourcePID, net.JoinHostPort(host, strconv.Itoa(execution.input.ListenPort))) {
						owned = true
						break
					}
				}
				if !owned {
					wgListenerConfirmed = false
					break
				}
			}
			if wgListenerConfirmed {
				if !resourcesReady {
					resourcesReady, err = reconcileResources(ctx)
				}
				return true, err
			}
		}
		applied, err := applyReceivingView(current)
		if errors.Is(err, errWGListenerUnconfirmed) && sameExecution(current) {
			fmt.Fprintln(options.Log, "WG listener update is unconfirmed; resource proof cleared and the existing check will reread/retry it")
			return true, nil
		}
		if !authorizationChanged && !errors.Is(err, errRuntimeCleanup) && (err != nil || !applied) {
			// A local socket change cannot authorize stopping unrelated Hy2,
			// WG sessions or capture. Address changes need an explicit restart.
			if wgListenerConfirmed {
				fmt.Fprintln(options.Log, "local resource update rejected before transport application; current confirmed listeners retained (address changes require an explicit restart)")
			} else {
				fmt.Fprintln(options.Log, "WG listener remains unconfirmed; no running resource proof is published")
			}
			return true, nil
		}
		return applied, err
	}
	generationContext := ctx
	update := func(periodic bool) (retErr error) {
		workContext, stopWork := context.WithCancel(diagnosticContext)
		workMu.Lock()
		cancelWork = stopWork
		workMu.Unlock()
		defer func() {
			workMu.Lock()
			cancelWork = nil
			workMu.Unlock()
			if workContext.Err() != nil && generationContext.Err() == nil && !errors.Is(retErr, errCertifiedPersistence) && !errors.Is(retErr, errCertifiedViewChanged) {
				retErr = nil
			}
			stopWork()
		}()
		ctx, diagnosticContext := workContext, workContext
		if _, err := store.Reload(); err != nil {
			return errors.Join(errCertifiedPersistence, err)
		}
		// Frontier/proof progress with the same View is durable authentication
		// progress, not a reason to interrupt unchanged execution.
		current := store.LKG()
		// Existing checks consume both accepted authorization and local
		// execution inputs; no independent file watcher or authority is added.
		if applied, err := applyRuntimeInputs(current); err != nil || !applied {
			if errors.Is(err, clientadapter.ErrSelectionSuperseded) {
				return nil
			}
			return errors.Join(errCertifiedViewChanged, err)
		}
		if current.ViewDigest != lkg.ViewDigest {
			generation, err := options.Generation()
			if err != nil {
				return err
			}
			if _, err := loadLocalStateForView(options.LocalState, generation, current, lkg, store.Preference()); err != nil {
				return err
			}
		}
		lkg = current
		generation, err := options.Generation()
		if err != nil {
			return err
		}
		diagnosticContext = clientadapter.WithMeasurementNetwork(diagnosticContext, generation)
		if website.Port != 0 && generation != websiteGeneration {
			return errRuntimeAddressChanged
		}
		if runtimeHasLocalNetwork(lkg.View) {
			current, _ := clientadapter.ConnectedIPv4Prefixes()
			if !reflect.DeepEqual(current, connected) {
				return errRuntimeAddressChanged
			}
		}
		local, err := loadLocalState(options.LocalState, generation, lkg.ViewDigest)
		if err != nil {
			return err
		}
		local.Preference = store.Preference()
		local.SelectionMemory = selectionMemory
		local.NativeObservations = nativeObservations
		var onlyScopes []string
		if lastPreference.Schema == 3 && !lastPreference.Equal(local.Preference) {
			onlyScopes = clientmodel.ChangedSelectorScopes(lastPreference, local.Preference)
			if _, err := clientadapter.RejectSelections(ctx, selector, onlyScopes); err != nil {
				return err
			}
		}
		activation := Activation{State: local, Selections: []SelectionStatus{}}
		select {
		case delivery := <-linkResults:
			if delivery.ValidateForView(lkg.View) == nil {
				remoteLinks = append([]control.DeviceLinkObservation{}, delivery.Observations...)
			} else {
				remoteLinks = nil
			}
		default:
		}
		linkObservations := []control.Observation{}
		for _, sample := range nodeMeasurements {
			if sample.Level == "link" || sample.Level == "egress" {
				linkObservations = append(linkObservations, sample)
			}
		}
		currentIDs := []string{}
		execution, err := control.ProjectDeviceCandidates(lkg.View, clientmodel.MeasurementPolicies(local.Preference))
		if err != nil {
			return err
		}
		if hasAccess {
			routes, err = clientadapter.AccessCandidates(lkg.View, clientmodel.MeasurementPolicies(local.Preference))
			if err != nil {
				return err
			}
			// New connections may run immediately, before background coverage.
			activation, err = activateServicesWithLinkSamples(diagnosticContext, options, lkg.View, selector, routes, local, linkObservations, remoteLinks, false, onlyScopes...)
			if errors.Is(err, clientadapter.ErrSelectionSuperseded) {
				return nil
			}
			if errors.Is(err, clientadapter.ErrResourcesNotReady) {
				resourcesReady = false
			} else if err != nil && !errors.Is(err, clientmodel.ErrNoUsableCandidate) {
				return err
			}
			local = activation.State
			selectionMemory = activation.State.SelectionMemory
			nativeActivation, nativeObservations = activation, activation.State.NativeObservations
			currentIDs = clientadapter.MeasurementCandidates(activation.Selections, selectionMemory, generation)
			readback := control.RuntimeReadback{State: "running", AppliedViewDigest: lkg.ViewDigest}
			if !wgListenerConfirmed {
				readback = control.RuntimeReadback{State: "unknown", ErrorCode: "resource_ownership"}
			} else if !resourcesReady {
				readback = control.RuntimeReadback{State: "unknown", ErrorCode: "resources_pending"}
			}
			readback = permissionReadback(lkg, readback)
			if err := WriteStatus(options.Status, runtimeStatus(lkg, activation, false, readback)); err != nil {
				return err
			}
		}
		firstHops := map[clientmodel.ResourceSampleRef]bool{}
		for _, route := range routes {
			if route.FirstHop != nil {
				firstHops[*route.FirstHop] = true
			}
		}
		previousSamples := []control.Observation{}
		for _, value := range append(append([]control.Observation{}, nodeMeasurements...), local.ResourceObservations...) {
			ref := clientmodel.ResourceSampleRef{ResourceID: value.ResourceID, Target: value.Target, Action: value.Action, SpecDigest: value.SpecDigest}
			if value.NetworkGeneration == generation && (value.Level != "resource" || firstHops[ref]) {
				previousSamples = append(previousSamples, value)
			}
		}
		progress := func(batch []control.Observation) error {
			changedResource, changedLink := false, false
			for _, value := range batch {
				changedResource = changedResource || value.Level == "resource"
				changedLink = changedLink || value.Level == "link"
			}
			// Egress URL results are reported together at round completion.
			// They do not rerender the local access/forward graph per URL.
			if !changedResource && !changedLink {
				return nil
			}
			if err := ctx.Err(); err != nil {
				return err
			}
			// UI/CLI changes can arrive while probes run. Reuse the store's
			// authenticated-byte cache, but never apply an old preference.
			if _, err := store.Reload(); err != nil {
				return errors.Join(errCertifiedPersistence, err)
			}
			currentGeneration, err := options.Generation()
			if err != nil {
				return err
			}
			current := store.LKG()
			if current == nil || current.ViewDigest != lkg.ViewDigest || currentGeneration != generation || !store.Preference().Equal(local.Preference) {
				return clientadapter.ErrSelectionSuperseded
			}
			nodeMeasurements = clientadapter.MergeNodeMeasurements(previousSamples, batch)
			previousSamples = nodeMeasurements
			resources, links := []control.Observation{}, []control.Observation{}
			for _, value := range nodeMeasurements {
				if value.Level == "resource" {
					resources = append(resources, value)
				} else if value.Level == "link" || value.Level == "egress" {
					links = append(links, value)
				}
			}
			if changedLink && forwardSelector != nil {
				nextMemory, forwardErr := forwardSelector.OptimizeForwarding(diagnosticContext, lkg.View, nodeMeasurements, remoteLinks, generation, options.Now(), forwardMemory)
				if errors.Is(forwardErr, clientadapter.ErrResourcesNotReady) {
					resourcesReady = false
				} else if forwardErr != nil {
					return forwardErr
				} else {
					forwardMemory = nextMemory
				}
			}
			if !hasAccess || !changedResource && !changedLink {
				return nil
			}
			local.ResourceObservations = resources
			// The initial activation already built the graph for this View.
			activation, err = activateWithLinkSamples(diagnosticContext, selector, routes, local, links, remoteLinks, selectedProbeURLs(lkg.View, local.Preference), options.Now, clientmodel.SelectorScopes(lkg.View)...)
			if errors.Is(err, clientadapter.ErrResourcesNotReady) {
				resourcesReady = false
				return nil
			}
			if err != nil && !errors.Is(err, clientmodel.ErrNoUsableCandidate) {
				return err
			}
			local = activation.State
			selectionMemory = local.SelectionMemory
			nativeActivation, nativeObservations = activation, local.NativeObservations
			if !resourcesReady {
				resourcesReady, err = reconcileResources(ctx)
				if err != nil {
					return err
				}
			}
			readback := control.RuntimeReadback{State: "running", AppliedViewDigest: lkg.ViewDigest}
			if !wgListenerConfirmed {
				readback = control.RuntimeReadback{State: "unknown", ErrorCode: "resource_ownership"}
			} else if !resourcesReady {
				readback = control.RuntimeReadback{State: "unknown", ErrorCode: "resources_pending"}
			}
			readback = permissionReadback(lkg, readback)
			return WriteStatus(options.Status, runtimeStatus(lkg, activation, false, readback))
		}
		forwardPriorities, err := clientadapter.ForwardMeasurementLinks(execution, forwardMemory, generation)
		if err != nil {
			return err
		}
		currentIDs = append(currentIDs, forwardPriorities...)
		var recovery *clientadapter.TCPRecoveryInput
		if nativeSelector, ok := selector.(*clientadapter.HTTPSelector); ok && hasAccess {
			recovery = &clientadapter.TCPRecoveryInput{Selector: nativeSelector, Routes: routes, State: adapterState(local, linkObservations, remoteLinks)}
			recovery.Progress = func(batch []clientmodel.Observation) error {
				if err := ctx.Err(); err != nil {
					return err
				}
				if _, err := store.Reload(); err != nil {
					return err
				}
				currentGeneration, err := options.Generation()
				if err != nil {
					return err
				}
				current := store.LKG()
				if current == nil || current.ViewDigest != lkg.ViewDigest || currentGeneration != generation || !store.Preference().Equal(local.Preference) {
					return clientadapter.ErrSelectionSuperseded
				}
				local.NativeObservations, err = clientadapter.AcceptTCPRecovery(diagnosticContext, selector, recovery.State, adapterState(local, linkObservations, remoteLinks), routes, batch, options.Now)
				if err != nil {
					return err
				}
				activation, err = activateWithLinkSamples(diagnosticContext, selector, routes, local, linkObservations, remoteLinks, selectedProbeURLs(lkg.View, local.Preference), options.Now, clientmodel.SelectorScopes(lkg.View)...)
				if errors.Is(err, clientadapter.ErrResourcesNotReady) {
					resourcesReady = false
					return nil
				}
				if err != nil && !errors.Is(err, clientmodel.ErrNoUsableCandidate) {
					return err
				}
				local = activation.State
				selectionMemory, nativeObservations, nativeActivation = local.SelectionMemory, local.NativeObservations, activation
				return nil
			}
		}
		samples, err := clientadapter.ObserveNodeMeasurements(diagnosticContext, execution, currentIDs, previousSamples, generation, options.Now, clientadapter.DefaultMeasurementTiming, progress, recovery)
		if errors.Is(err, clientadapter.ErrSelectionSuperseded) {
			return nil
		}
		if err != nil {
			return err
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		nodeMeasurements = samples
		if forwardSelector != nil {
			nextMemory, forwardErr := forwardSelector.OptimizeForwarding(diagnosticContext, lkg.View, samples, remoteLinks, generation, options.Now(), forwardMemory)
			if errors.Is(forwardErr, clientadapter.ErrResourcesNotReady) {
				resourcesReady = false
			} else if forwardErr != nil {
				return forwardErr
			} else {
				forwardMemory = nextMemory
			}
		}

		linkObservations = []control.Observation{}
		reportMeasurements := []control.Observation{}
		local.ResourceObservations = nil
		for _, sample := range samples {
			if sample.Level == "resource" {
				local.ResourceObservations = append(local.ResourceObservations, sample)
			} else {
				reportMeasurements = append(reportMeasurements, sample)
			}
			if sample.Level == "link" || sample.Level == "egress" {
				linkObservations = append(linkObservations, sample)
			}
		}
		if err := (*transaction).readbackNative(); err != nil {
			return err
		}
		readback := control.RuntimeReadback{State: "stopped"}
		if pid != 0 || len(wg.WireGuard) != 0 {
			readback = control.RuntimeReadback{State: "running", AppliedViewDigest: lkg.ViewDigest}
		}
		if pid != 0 {
			if hasAccess {
				activation, err = activateServicesWithLinkSamples(diagnosticContext, options, lkg.View, selector, routes, local, linkObservations, remoteLinks, false, onlyScopes...)
				if errors.Is(err, clientadapter.ErrSelectionSuperseded) {
					return nil
				}
				selectionMemory = activation.State.SelectionMemory
				nativeActivation, nativeObservations = activation, activation.State.NativeObservations
				pendingResources := errors.Is(err, clientadapter.ErrResourcesNotReady)
				if pendingResources {
					resourcesReady = false
				}
				if activation.State.Schema == 0 {
					return err
				}
				if !pendingResources && len(activation.Selections)+len(activation.BlockedScopes) != len(clientmodel.SelectorScopes(lkg.View)) {
					return errors.Join(err, errors.New("Service rejection could not be confirmed"))
				}
				if !pendingResources && err != nil && !errors.Is(err, clientmodel.ErrNoUsableCandidate) {
					fmt.Fprintln(options.Log, "a Service selector failed; affected traffic remains rejected")
				}
			}
			resourcesReady, err = reconcileResources(ctx)
			if err != nil {
				return err
			}
			if hasAccess && len(activation.Selections)+len(activation.BlockedScopes) != len(clientmodel.SelectorScopes(lkg.View)) {
				resourcesReady = false
			}
			if !wgListenerConfirmed {
				// A local rebind may have closed the old socket or completed
				// without its ACK. Neither old config nor inode reuse proves it.
				_, _ = readTransportResources(ctx, lkg.View, executions, resourcePID, options.Now())
				readback = control.RuntimeReadback{State: "unknown", ErrorCode: "resource_ownership"}
			} else {
				readback, err = resourceRuntimeReadback(ctx, lkg, executions, resourcePID, options.Now(), periodic, *transaction)
				if err != nil {
					return err
				}
			}
			if readback.State == "unknown" && readback.ErrorCode == "resource_readback_timeout" {
				fmt.Fprintln(options.Log, executionFailure("resource_readback", "network_timeout", errResourceReadbackTimeout))
			}
			if !resourcesReady && wgListenerConfirmed {
				readback = control.RuntimeReadback{State: "unknown", ErrorCode: "resources_pending"}
			}
		}
		readback = permissionReadback(lkg, readback)
		status := runtimeStatus(lkg, activation, false, readback)
		status.PossiblePermissionRestoration = store.PossiblePermissionRestoration()
		if err := WriteStatus(options.Status, status); err != nil {
			return err
		}

		saved, saveErr := SaveObservations(options.LocalState, activation.State)
		if saveErr != nil {
			return saveErr
		}
		saved.SelectionMemory = selectionMemory
		activation.State = saved
		nativeObservations = activation.State.NativeObservations
		nativeActivation = activation
		var counters *control.WireGuardCounters
		if readback.State == "running" {
			counters, _ = clientadapter.ObserveWireGuardCounters(diagnosticContext, lkg.View, options.Now)
		}
		report, err := selectionReport(ctx, *lkg, activation, options.Now(), components, readback, reportMeasurements, counters)
		if err != nil {
			return err
		}
		status = runtimeStatus(lkg, activation, false, readback)
		status.PossiblePermissionRestoration = store.PossiblePermissionRestoration()
		if err := WriteStatus(options.Status, status); err != nil {
			return err
		}
		pendingReport = &runtimeReportAttempt{report: report, status: status}
		offerLatest(reportRequests, pendingReport)
		lastPreference = activation.State.Preference
		return nil
	}
	if err := update(false); err != nil {
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
	nativeTicker := time.NewTicker(5 * time.Second)
	defer nativeTicker.Stop()
	for {
		if ctx.Err() != nil {
			return nil
		}
		refreshAgain := true
		select {
		case <-ctx.Done():
			return nil
		case err := <-done:
			return processFailure("access_process", err)
		case err := <-serverDone:
			return processFailure("resource_process", err)
		case notice := <-refreshNotices:
			fmt.Fprint(options.Log, notice)
			refreshAgain = false
		case result := <-reportResults:
			if result.err != nil {
				fmt.Fprintln(options.Log, "private runtime report unavailable")
			}
			if ctx.Err() == nil {
				if err := writeReportConfirmation(options.Status, pendingReport, result); err != nil {
					return err
				}
			}
			continue
		case <-ticker.C:
		case <-nativeTicker.C:
			if !hasAccess || nativeActivation.State.NativeExecutionSpec == "" {
				continue
			}
			current := store.LKG()
			generation, genErr := options.Generation()
			if genErr != nil {
				return genErr
			}
			if current == nil || current.ViewDigest != lkg.ViewDigest || generation != nativeActivation.State.NetworkGeneration || !store.Preference().Equal(nativeActivation.State.Preference) {
				if err := update(false); err != nil {
					return err
				}
				continue
			}
			workContext, cancel := context.WithCancel(ctx)
			workMu.Lock()
			cancelWork = cancel
			workMu.Unlock()
			// The configuration worker may have accepted a replacement before
			// registration. Never bind that old snapshot to the new authority.
			if current := store.LKG(); current == nil || current.ViewDigest != lkg.ViewDigest {
				cancel()
			}
			refreshed, needsRouting, refreshErr := clientadapter.RefreshNativeObservations(workContext, selector, routes, adapterState(nativeActivation.State, nodeMeasurements, remoteLinks), options.Now)
			local := nativeActivation.State
			local.NativeObservations = refreshed.NativeObservations
			local.SelectionMemory = refreshed.SelectionMemory
			next, nextErr := nativeActivation, refreshErr
			if refreshErr == nil && needsRouting {
				next, nextErr = activateWithLinkSamples(workContext, selector, routes, local, nodeMeasurements, remoteLinks, selectedProbeURLs(lkg.View, local.Preference), options.Now, clientmodel.SelectorScopes(lkg.View)...)
			} else {
				next.State = local
			}
			cancel()
			workMu.Lock()
			cancelWork = nil
			workMu.Unlock()
			if nextErr != nil && !errors.Is(nextErr, clientmodel.ErrNoUsableCandidate) {
				if ctx.Err() != nil {
					return nil
				}
				continue
			}
			if current := store.LKG(); current == nil || current.ViewDigest != lkg.ViewDigest {
				continue
			}
			currentGeneration, generationErr := options.Generation()
			if generationErr != nil {
				return generationErr
			}
			if currentGeneration != generation || !store.Preference().Equal(next.State.Preference) {
				continue
			}
			nativeActivation = next
			selectionMemory, nativeObservations = next.State.SelectionMemory, next.State.NativeObservations
			if !needsRouting {
				continue
			}
			status, statusErr := ReadStatus(options.Status)
			if statusErr != nil {
				return statusErr
			}
			if status.ViewDigest == lkg.ViewDigest && status.NetworkGeneration == generation && status.Preference.Equal(next.State.Preference) && status.Runtime == "running" {
				status.Selections = next.Selections
				status.Reported = false
				if err := WriteStatus(options.Status, status); err != nil {
					return err
				}
			}
			continue
		case <-options.Reload:
		}
		if _, err := store.Reload(); err != nil {
			return errors.Join(errCertifiedPersistence, err)
		}
		current := store.LKG()
		{
			applied, err := applyRuntimeInputs(current)
			if errors.Is(err, clientadapter.ErrSelectionSuperseded) {
				continue
			}
			if err != nil {
				return err
			}
			if !applied {
				return errCertifiedViewChanged
			}
		}
		if current != nil && current.ViewDigest != lkg.ViewDigest {
			generation, err := options.Generation()
			if err != nil {
				return err
			}
			if _, err := loadLocalStateForView(options.LocalState, generation, current, lkg, store.Preference()); err != nil {
				return err
			}
			lkg = current
		}
		if refreshAgain {
			offerLatest(refreshRequests, struct{}{})
		}
		if needsSharedMeasurements {
			offerLatest(linkRequests, struct{}{})
		}
		if !wgListenerConfirmed {
			if err := update(true); err != nil {
				return err
			}
			continue
		}

		if err := update(true); err != nil {
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
	value := Status{Schema: 3, DeviceID: lkg.View.DeviceID, ViewDigest: lkg.ViewDigest, FactFrontier: lkg.FactFrontier, Preference: store.Preference(), NetworkGeneration: generation, Selections: []SelectionStatus{}, Observations: []clientmodel.Observation{}, Runtime: state}
	value.PossiblePermissionRestoration = store.PossiblePermissionRestoration()
	return value, WriteStatus(options.Status, value)
}
func waitForRepair(ctx context.Context, store *deviceclient.Store, options Options, failure error) error {
	components, _ := linuxComponentReadbacks(ctx, 0)
	for {
		status, err := writeInactiveStatus(store, options, "error")
		if err != nil {
			return err
		}
		pending, cancel := context.WithTimeout(ctx, 20*time.Second)
		preference, prefErr := clientadapter.ReportedPolicyID(store.LKG().View, status.Preference)
		if prefErr == nil {
			diagnostic := safeRuntimeFailure(failure)
			_ = deviceclient.Report(pending, store, control.DeviceReport{ReportedAt: options.Now().UnixMilli(), NetworkGeneration: status.NetworkGeneration, PolicyID: preference, Selections: []control.ReportSelection{}, Observations: []control.Observation{}, Components: components, Runtime: control.RuntimeReadback{State: "error", ErrorCode: diagnostic.operation + "_" + diagnostic.class}})
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
	if store.LKG() == nil {
		if _, err := certifiedViewChanged(ctx, store, options.Log); err != nil {
			return err
		}
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
		if err != nil && ctx.Err() == nil {
			err = safeRuntimeFailure(err)
			fmt.Fprintln(options.Log, err)
		}
		if errors.Is(err, errCertifiedPersistence) {
			return err
		}
		// Cancellation can close the data plane's TUN while a refresh is reading
		// its ownership. The exact cleanup above must still succeed before this
		// becomes a normal stop; unknown replacements remain cleanup failures.
		if errors.Is(err, errRuntimeCleanup) || errors.Is(err, ErrWireGuardCleanup) || errors.Is(err, ErrWireGuardOwnership) && ctx.Err() == nil {
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
		if err := waitForRepair(ctx, store, options, err); err != nil {
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
	if _, err := command.CombinedOutput(); err != nil {
		return executionFailure("runtime_preflight", "rejected", err)
	}
	return nil
}

func preflightRuntimeConfig(singBox, config string) error {
	base, err := clientadapter.NativeResourceBase(config)
	if err != nil {
		return err
	}
	config = base
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

func writeNativeResourceConfig(path, source string) error {
	base, err := clientadapter.NativeResourceBase(source)
	if err != nil {
		return err
	}
	return writeConfig(path, base)
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

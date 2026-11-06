//go:build windows

package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/eventlog"

	"loom/internal/clientadapter"
	"loom/internal/clientcomponent"
	"loom/internal/clientmodel"
	"loom/internal/clientruntime"
	"loom/internal/clientsecret"
	"loom/internal/control"
	"loom/internal/deviceclient"
	"loom/internal/version"
)

const serviceName = "LoomClient"

func main() {
	edition, err := configuredEdition()
	if err != nil {
		log.Fatal(err)
	}
	if len(os.Args) == 2 && (os.Args[1] == "--build-info" || os.Args[1] == "--version") {
		if err := json.NewEncoder(os.Stdout).Encode(struct {
			Edition    clientEdition      `json:"edition"`
			Coordinate version.Coordinate `json:"coordinate"`
		}{Edition: edition, Coordinate: version.Self()}); err != nil {
			log.Fatalf("write build information: %v", err)
		}
		return
	}
	if len(os.Args) > 1 && os.Args[1] == "migrate-policy-selection" {
		if err := migrateWindowsPolicySelection(os.Args[2:], edition); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		return
	}
	if len(os.Args) > 1 && os.Args[1] == "migrate-transport" {
		if err := migrateWindowsTransport(os.Args[2:], edition); err != nil {
			log.Fatal(err)
		}
		return
	}
	if edition == editionInstalled {
		isService, serviceErr := svc.IsWindowsService()
		if serviceErr != nil {
			log.Fatalf("detect Windows service session: %v", serviceErr)
		}
		if isService {
			handler := &loomService{prepare: prepareInstalledService}
			if err := svc.Run(serviceName, handler); err != nil {
				log.Fatalf("run %s: %v", serviceName, err)
			}
			return
		}
	}
	if len(os.Args) != 1 {
		showWindowsError("Loom", errors.New("请直接启动 Loom 客户端，并在窗口中导入二维码"))
		return
	}
	if err := runWindowsGUI(edition); err != nil {
		showWindowsError("Loom", err)
	}
}

func requirePortableTUNElevation(edition clientEdition) error {
	if edition == editionPortableTUN && !windows.GetCurrentProcessToken().IsElevated() {
		return errors.New("已保存加入状态；启用 Portable TUN 需要通过 UAC 以管理员身份重新启动，Portable Mixed 不需要")
	}
	return nil
}

type loomService struct {
	prepare func() (func(context.Context) error, error)
}

func (s *loomService) Execute(_ []string, requests <-chan svc.ChangeRequest, statuses chan<- svc.Status) (bool, uint32) {
	statuses <- svc.Status{State: svc.StartPending}
	workload, err := s.prepare()
	if err != nil {
		log.Printf("client initialization failed: %v", err)
		if events, openErr := eventlog.Open(serviceName); openErr == nil {
			_ = events.Error(1, "Loom Client 初始化失败："+err.Error())
			events.Close()
		}
		return false, 1
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- workload(ctx) }()

	running := svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}
	statuses <- running
	for {
		select {
		case err := <-done:
			if err != nil {
				log.Printf("client workload failed: %v", err)
				return false, 1
			}
			return false, 0
		case request, ok := <-requests:
			if !ok {
				cancel()
				if err := <-done; err != nil {
					return false, 1
				}
				return false, 0
			}
			switch request.Cmd {
			case svc.Interrogate:
				statuses <- running
			case svc.Stop, svc.Shutdown:
				statuses <- svc.Status{State: svc.StopPending}
				cancel()
				if err := <-done; err != nil {
					log.Printf("client shutdown failed: %v", err)
					return false, 1
				}
				return false, 0
			default:
				// The accepted-command mask intentionally excludes pause,
				// continue, and arbitrary control codes.
			}
		}
	}
}

// prepareClient performs durable initialization before SCM sees Running.
// Configuration download starts only after the user imports a control-issued
// join QR. A missing join is a valid disconnected state; malformed or partial
// state fails initialization.
func prepareClient() (func(context.Context) error, error) {
	root, err := programDataRoot()
	if err != nil {
		return nil, err
	}
	return prepareClientAt(root, clientsecret.MachineProtector{}, editionInstalled)
}

func preparePortableClient(edition clientEdition) (func(context.Context) error, error) {
	if edition != editionPortableMixed && edition != editionPortableTUN {
		return nil, fmt.Errorf("edition %q is not portable", edition)
	}
	root, err := localAppDataRoot()
	if err != nil {
		return nil, err
	}
	return prepareClientAt(root, clientsecret.UserProtector{}, edition)
}

func prepareClientAt(root string, protector clientsecret.Protector, edition clientEdition, _ ...*http.Client) (func(context.Context) error, error) {
	profile, err := runtimeProfile(edition)
	if err != nil {
		return nil, err
	}
	store, err := deviceclient.LoadProtected(windowsProfileStatePath(root), protector)
	if errors.Is(err, os.ErrNotExist) {
		log.Printf("client has not joined a Loom network: waiting for QR import")
		return waitForJoinedClient(root, protector, edition), nil
	}
	if err != nil {
		return nil, err
	}
	lkg := store.LKG()
	if lkg == nil || lkg.View.Platform != "windows" {
		return nil, errors.New("Windows profile has no complete certified LKG")
	}

	if err := os.Remove(windowsRuntimeStatusPath(root)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("remove stale Windows runtime status: %w", err)
	}
	return func(ctx context.Context) error {
		dataPlaneLock, err := acquireWindowsDataPlaneLock()
		if err != nil {
			return err
		}
		defer dataPlaneLock.close()
		return runWindowsCertifiedProfile(ctx, root, store, profile)
	}, nil
}

func loadWindowsRuntimeComponents(root string) (clientcomponent.RuntimePaths, error) {
	// The exact bundle is selected by the installed application. Install performs
	// signature, payload, native driver and monotonic generation checks before use.
	return installBundledWindowsComponent(root)
}

func runtimeProfile(edition clientEdition) (clientruntime.WindowsRuntimeProfile, error) {
	switch edition {
	case editionInstalled:
		return clientruntime.WindowsInstalledProfile, nil
	case editionPortableMixed:
		return clientruntime.WindowsPortableMixedProfile, nil
	case editionPortableTUN:
		return clientruntime.WindowsPortableTUNProfile, nil
	default:
		return "", fmt.Errorf("unsupported Windows client edition %q", edition)
	}
}

func waitForJoinedClient(root string, protector clientsecret.Protector, edition clientEdition) func(context.Context) error {
	return func(ctx context.Context) error {
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return nil
			case <-ticker.C:
				if store, err := deviceclient.LoadProtected(windowsProfileStatePath(root), protector); errors.Is(err, os.ErrNotExist) {
					continue
				} else if err != nil {
					return fmt.Errorf("load joined-device state: %w", err)
				} else if store.LKG() == nil {
					continue
				}
				workload, err := prepareClientAt(root, protector, edition)
				if err != nil {
					return err
				}
				return workload(ctx)
			}
		}
	}
}

type windowsRuntimeStatus struct {
	NetworkGeneration    string                          `json:"network_generation"`
	Schema               int                             `json:"schema"`
	DeviceID             string                          `json:"device_id"`
	ViewDigest           string                          `json:"view_digest"`
	RuntimeState         string                          `json:"runtime_state"`
	Preference           clientmodel.Preference          `json:"preference"`
	Selections           []clientadapter.SelectionStatus `json:"selections"`
	BlockedScopes        []string                        `json:"blocked_scopes,omitempty"`
	Observations         []clientmodel.Observation       `json:"observations"`
	ResourceObservations []control.Observation           `json:"resource_observations,omitempty"`
	Reported             bool                            `json:"reported"`
	SelectorReadAt       string                          `json:"selector_read_at"`
}

func windowsRuntimeStatusPath(root string) string {
	return filepath.Join(root, "runtime", "status.json")
}

func writeWindowsRuntimeStatus(root string, lkg *control.DeviceViewEnvelope, activation clientadapter.Activation, reported bool, selectorReadAt time.Time, runtime ...control.RuntimeReadback) error {
	status := windowsRuntimeStatus{Schema: 3, NetworkGeneration: activation.State.NetworkGeneration, DeviceID: lkg.View.DeviceID, ViewDigest: lkg.ViewDigest, RuntimeState: "running",
		Preference: activation.State.Preference, Selections: activation.Selections, BlockedScopes: activation.BlockedScopes,
		Observations: activation.State.Observations, ResourceObservations: activation.State.ResourceObservations, Reported: reported,
		SelectorReadAt: selectorReadAt.UTC().Format(time.RFC3339Nano)}
	if len(runtime) != 0 {
		status.RuntimeState = runtime[0].State
	}
	if status.RuntimeState != "running" {
		status.Selections, status.BlockedScopes = []clientadapter.SelectionStatus{}, nil
		status.Observations, status.ResourceObservations = []clientmodel.Observation{}, nil
	}
	body, err := json.MarshalIndent(status, "", "  ")
	if err != nil {
		return err
	}
	return writeWindowsRuntimeStatusFile(windowsRuntimeStatusPath(root), append(body, '\n'))
}

func windowsProbeTargets(view control.DeviceView, policyID string) (string, []string) {
	for _, service := range view.Services {
		if service.ID == clientmodel.SelectedServiceID(view, clientmodel.Preference{Schema: 3, PolicyID: policyID}) {
			return service.ID, service.ProbeURLs
		}
	}
	return "", nil
}
func activateWindowsServices(ctx context.Context, selector clientadapter.Selector, view control.DeviceView,
	routes []clientmodel.RouteCandidate, state clientadapter.State, _ bool) (clientadapter.Activation, error) {
	graphs, err := clientadapter.PolicyGraphs(view, clientmodel.MeasurementPolicies(state.Preference))
	if err != nil {
		return clientadapter.Activation{}, err
	}
	state.Graphs = graphs
	state.NativeExecutionSpec, err = clientadapter.NativeExecutionSpec(view, routes, graphs, state.Preference.PolicyID)
	if err != nil {
		return clientadapter.Activation{}, err
	}
	_, targets := windowsProbeTargets(view, state.Preference.PolicyID)
	return clientadapter.Activate(ctx, selector, routes, state, targets, time.Now, clientmodel.SelectorScopes(view)...)
}

func windowsNetworkGeneration() (string, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return "", err
	}
	parts := make([]string, 0, len(interfaces))
	for _, current := range interfaces {
		addresses, err := current.Addrs()
		if err != nil {
			return "", err
		}
		values := make([]string, 0, len(addresses))
		for _, address := range addresses {
			values = append(values, address.String())
		}
		sort.Strings(values)
		parts = append(parts, fmt.Sprintf("%d\x00%s\x00%s\x00%v", current.Index, current.Name, current.HardwareAddr, values))
	}
	sort.Strings(parts)
	digest := sha256.Sum256([]byte(strings.Join(parts, "\n")))
	return "network-" + hex.EncodeToString(digest[:]), nil
}

func windowsDeviceReport(lkg *control.DeviceViewEnvelope, activation clientadapter.Activation,
	components []control.ComponentReadback, reportedAt time.Time, runtime ...control.RuntimeReadback) (control.DeviceReport, error) {
	preference, err := clientadapter.ReportedPolicyID(lkg.View, activation.State.Preference)
	if err != nil {
		return control.DeviceReport{}, err
	}
	connected, _ := clientadapter.ConnectedIPv4Prefixes()
	lanChoices, err := clientadapter.ReportedLANPolicyIDs(lkg.View, activation.State.Preference)
	if err != nil {
		return control.DeviceReport{}, err
	}
	report := control.DeviceReport{LANPolicyIDs: lanChoices, LocalNetworks: clientadapter.UnderlayNetworkReport(connected), ViewDigest: lkg.ViewDigest, NetworkGeneration: activation.State.NetworkGeneration, ReportedAt: reportedAt.UnixMilli(),
		PolicyID: preference, Selections: []control.ReportSelection{}, Observations: []control.Observation{}, Components: append([]control.ComponentReadback{}, components...),
		Runtime: control.RuntimeReadback{State: "running", AppliedViewDigest: lkg.ViewDigest}}
	if len(runtime) != 0 {
		report.Runtime = runtime[0]
	}
	execution, err := control.ProjectDeviceCandidates(lkg.View, clientmodel.MeasurementPolicies(activation.State.Preference))
	if err != nil {
		return control.DeviceReport{}, err
	}
	routes := map[string]control.RouteCandidate{}
	for _, route := range execution.Routes {
		routes[route.ID] = route
	}
	complete := report.Runtime.State == "running" && report.Runtime.AppliedViewDigest == lkg.ViewDigest
	if complete {
		report.Selections, err = clientadapter.ReportSelections(lkg.View, activation.State.Preference, activation.Selections)
		if err != nil {
			return control.DeviceReport{}, err
		}
	}

	for _, observation := range activation.State.ResourceObservations {
		if !report.Runtime.HasCurrentPermissions(lkg.ViewDigest) {
			break
		}
		if observation.Validate() != nil || observation.Level != "resource" || observation.NetworkGeneration != report.NetworkGeneration {
			return control.DeviceReport{}, errors.New("resource sample does not belong to this Windows runtime")
		}
		report.Observations = append(report.Observations, observation)
	}
	for _, observation := range activation.State.Observations {
		if !complete {
			break
		}
		route, ok := routes[observation.CandidateID]
		service, targets := windowsProbeTargets(lkg.View, route.PolicyID)
		target := observation.Target
		if target == "" || !slices.Contains(targets, target) || observation.Action != "https_request" || !ok || route.ServiceID != service || observation.Scope != control.AccessSelectorScope || observation.NetworkGeneration != report.NetworkGeneration {
			continue
		}
		observed, err := time.Parse(time.RFC3339, observation.ObservedAt)
		if err != nil {
			return control.DeviceReport{}, err
		}
		valid, err := time.Parse(time.RFC3339, observation.ValidUntil)
		if err != nil {
			return control.DeviceReport{}, err
		}
		duration := observation.MetricMillis
		report.Observations = append(report.Observations, control.Observation{Level: "service", ServiceID: service, CandidateID: route.ID, Target: target, Action: "https_request", SpecDigest: route.SpecDigest, NetworkGeneration: report.NetworkGeneration, Result: observation.Result, ObservedAt: observed.UnixMilli(), ValidUntil: valid.UnixMilli(), DurationMS: &duration})
	}
	order := func(value control.Observation) string {
		return strings.Join([]string{value.Level, value.ServiceID, value.CandidateID, value.ResourceID, value.LinkID, value.Target, value.Action, value.SpecDigest}, "\x00")
	}
	sort.Slice(report.Observations, func(i, j int) bool { return order(report.Observations[i]) < order(report.Observations[j]) })
	report.Observations, err = clientadapter.CurrentReportObservations(report.Observations, report.NetworkGeneration, report.ReportedAt)
	if err != nil {
		return control.DeviceReport{}, err
	}
	return report, nil
}

func windowsActivationApplied(activation clientadapter.Activation, routes []clientmodel.RouteCandidate, scopeIDs ...string) bool {
	scopes, byScope, err := clientadapter.Scopes(routes, scopeIDs...)
	if err != nil || activation.State.NetworkGeneration == "" || len(activation.Selections)+len(activation.BlockedScopes) != len(scopes) {
		return false
	}
	seen := map[string]bool{}
	for _, scope := range activation.BlockedScopes {
		if _, exists := byScope[scope]; seen[scope] || !exists {
			return false
		}
		seen[scope] = true
	}
	for _, selection := range activation.Selections {
		if seen[selection.Scope] {
			return false
		}
		seen[selection.Scope] = true
		found := false
		for _, route := range byScope[selection.Scope] {
			found = found || route.ID == selection.CandidateID
		}
		if !found {
			return false
		}
	}
	return true
}

var errWindowsRuntimeInputsChanged = errors.New("Windows runtime inputs have changed")
var errWindowsConfigurationPending = errors.New("accepted Windows configuration is awaiting runtime application")

func refreshWindowsCertifiedView(ctx context.Context, store *deviceclient.ProtectedStore,
	fetch func(context.Context, deviceclient.IdentityStore) (control.DeviceViewEnvelope, error)) (bool, error) {
	current := store.LKG()
	digest := ""
	if current != nil {
		digest = current.ViewDigest
	}
	changed := func() bool { next := store.LKG(); return next == nil || next.ViewDigest != digest }
	if _, err := store.Reload(); err != nil {
		return false, err
	}
	if changed() {
		return true, nil
	}
	previous := store.LKG()
	// AwaitConfiguration already bounds the private request and closes its
	// sockets on cancellation. Do not truncate its healthy long-poll wait.
	envelope, err := fetch(ctx, store)
	if _, readErr := store.Reload(); readErr != nil {
		return false, readErr
	}
	current = store.LKG()
	if previous != nil && current != nil && current.Signature != previous.Signature && err == nil {
		// Only a newer accepted envelope can supersede this response. A report
		// reservation or a UI Preference write must not discard fresh authority.
		if control.CheckDeviceViewAdvance(envelope, *current, current.FactFrontier) != nil {
			return changed(), nil
		}
	}
	if ctx.Err() != nil {
		return false, ctx.Err()
	}
	if err != nil {
		log.Printf("private Windows view refresh unavailable; keeping certified LKG: %v", err)
		// Reload may have accepted another handle's revocation while this
		// request failed. Its runtime cancellation cannot depend on network success.
		return changed(), nil
	}
	// Every authenticated envelope advances the durable proof/frontier. Only
	// changed execution inputs stop the current data-plane generation.
	if err = store.SaveLKG(envelope); err != nil {
		// Another protected handle may advance authority after the read above.
		// Its accepted progress wins over this stale response, without turning
		// ordinary GUI/report concurrency into a data-plane restart.
		if _, reloadErr := store.Reload(); reloadErr != nil {
			return false, fmt.Errorf("accept certified Windows configuration: %w", errors.Join(err, reloadErr))
		}
		accepted := store.LKG()
		if current != nil && accepted != nil && accepted.Signature != current.Signature &&
			control.CheckDeviceViewAdvance(envelope, *accepted, accepted.FactFrontier) != nil {
			return changed(), nil
		}
		return false, fmt.Errorf("accept certified Windows configuration: %w", err)
	}
	return changed(), nil
}

func runWindowsGeneration(ctx context.Context, root string, store *deviceclient.ProtectedStore,
	profile clientruntime.WindowsRuntimeProfile,
	fetch func(context.Context, deviceclient.IdentityStore) (control.DeviceViewEnvelope, error)) (retErr error) {
	statusPath := windowsRuntimeStatusPath(root)
	if err := os.Remove(statusPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("remove stale Windows runtime status: %w", err)
	}
	defer os.Remove(statusPath) //nolint:errcheck
	// The authenticated LKG is sufficient for local startup. A slow/offline
	// control must not precede runtime application with a blocking fetch.
	if _, err := store.Reload(); err != nil {
		return err
	}
	lkg := store.LKG()
	if lkg == nil || !control.HasRuntime(lkg.View) {
		return errors.New("Windows profile lost its certified LKG")
	}
	if _, _, err := clientadapter.AccessProjection(lkg.View, clientmodel.MeasurementPolicies(store.Preference())); err != nil {
		return err
	}
	// Authentication is already durable. Component verification and runtime
	// application may fail, but cannot put the previous authorization back.
	components, err := loadWindowsRuntimeComponents(root)
	if err != nil {
		return fmt.Errorf("load signed Windows runtime components: %w", err)
	}
	heldComponents, err := pinWindowsRuntimeComponents(components)
	if err != nil {
		return err
	}
	defer func() {
		for _, file := range heldComponents {
			file.Close()
		}
	}()
	localSecret := make([]byte, 32)
	if _, err := rand.Read(localSecret); err != nil {
		return err
	}
	selectorSecret := hex.EncodeToString(localSecret)
	clear(localSecret)
	websiteGeneration := ""
	if len(lkg.View.WebEndpoints) > 0 {
		websiteGeneration, err = windowsNetworkGeneration()
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
	connected, err := clientadapter.ConnectedIPv4Prefixes()
	if err != nil {
		return err
	}
	projection, err := clientruntime.DeriveWindowsRuntimeConfig(lkg.View, profile, selectorSecret, website, connected)
	if err != nil {
		return err
	}
	defer projection.Clear()
	config := projection.Bytes()
	nativeProjection, err := projection.NativeResourceBase()
	if err != nil {
		return err
	}
	defer nativeProjection.Clear()
	if website.Port != 0 {
		current, err := windowsNetworkGeneration()
		if err != nil {
			return err
		}
		if current != websiteGeneration {
			return errWindowsRuntimeInputsChanged
		}
	}
	defer func() { clear(config) }()
	generationContext, stopGeneration := context.WithCancel(ctx)
	defer stopGeneration()
	ctx = generationContext
	planeDone := make(chan error, 1)
	started := make(chan int, 1)
	go func() {
		base := root
		if filepath.Base(filepath.Dir(root)) == "profiles" && validConnectionProfileID(filepath.Base(root)) {
			base = filepath.Dir(filepath.Dir(root))
		}
		planeDone <- clientruntime.RunWindowsDataPlane(ctx, components.SingBox, nativeProjection,
			filepath.Join(root, "runtime"), filepath.Join(base, "dataplane-cache"), func(pid int) { started <- pid })
	}()
	var dataPlanePID int
	select {
	case <-ctx.Done():
		return <-planeDone
	case err := <-planeDone:
		return err
	case dataPlanePID = <-started:
	}
	planeStopped := false
	defer func() {
		stopGeneration()
		if !planeStopped {
			if err := <-planeDone; err != nil {
				// Cleanup failure must not start another generation. The newly
				// accepted configuration remains the only protected authority.
				retErr = fmt.Errorf("stop Windows data plane: %w", err)
			}
		}
	}()
	selector, err := clientadapter.NewHTTPSelector(string(config))
	if err != nil {
		return err
	}
	routes, _, err := clientadapter.AccessProjection(lkg.View, clientmodel.MeasurementPolicies(store.Preference()))
	if err != nil {
		return err
	}
	scopes, _, err := clientadapter.Scopes(routes, clientmodel.SelectorScopes(lkg.View)...)
	if err != nil {
		return err
	}
	if err := clientadapter.WaitSelector(ctx, selector, scopes); err != nil {
		return err
	}
	authorization, err := selector.ApplyRuntimeAuthorization(ctx, string(config), string(config), string(config))
	if err != nil || !authorization.Supported || !authorization.PermissionCurrent {
		return errors.Join(err, errors.New("Windows runtime authorization was not confirmed"))
	}
	resourcesReady, resourceErr := selector.ReconcileRuntimeResources(ctx, string(config))
	if ctx.Err() != nil {
		return ctx.Err()
	}
	resourcesReady = resourcesReady && resourceErr == nil
	permissionCurrent := authorization.PermissionCurrent
	readback := func() control.RuntimeReadback {
		return windowsResourceReadback(lkg.ViewDigest, permissionCurrent, resourcesReady)
	}
	generation, err := windowsNetworkGeneration()
	if err != nil {
		return err
	}
	// The running fingerprint includes the newly created TUN. Establish its
	// observation baseline here; comparing it to pre-capture interfaces would
	// mistake our own successful startup for an underlay change forever.
	// The resolved website input was checked immediately before capture.
	resourceSamples, cacheErr := readWindowsResourceCache(root, *lkg, generation, clientmodel.MeasurementPolicies(store.Preference()))
	if cacheErr != nil {
		log.Printf("first-hop observation cache unavailable; resource samples remain unknown: %v", cacheErr)
	}
	activation, activationErr := activateWindowsServices(ctx, selector, lkg.View, routes, clientadapter.State{
		Preference: store.Preference(), NetworkGeneration: generation, ResourceObservations: resourceSamples}, false)
	selectorReadAt := time.Now()
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if errors.Is(activationErr, clientadapter.ErrResourcesNotReady) {
		resourcesReady = false
	} else if !windowsActivationApplied(activation, routes, clientmodel.SelectorScopes(lkg.View)...) {
		return activationErr
	}
	if err := writeWindowsRuntimeStatus(root, lkg, activation, false, selectorReadAt, readback()); err != nil {
		return err
	}
	diagnosticContext, err := clientadapter.WithNativeDiagnostic(ctx, string(config), nil)
	if err != nil {
		return err
	}
	var measurements *control.DeviceLinkObservations

	measureFirstHops := func(workContext context.Context, active *clientadapter.Activation, initial []string) error {
		ctx, diagnosticContext := workContext, workContext
		preference, network := active.State.Preference, active.State.NetworkGeneration
		_, targets := windowsProbeTargets(lkg.View, preference.PolicyID)
		progress := func() error {
			if err := ctx.Err(); err != nil {
				return err
			}
			if _, err := store.Reload(); err != nil {
				return err
			}
			generation, err := windowsNetworkGeneration()
			if err != nil {
				return err
			}
			current := store.LKG()
			if current == nil || current.ViewDigest != lkg.ViewDigest || !store.Preference().Equal(preference) || generation != network {
				return clientadapter.ErrSelectionSuperseded
			}
			// Reuse the graph already built by activation for this View.
			next, err := clientadapter.Activate(diagnosticContext, selector, routes, active.State, targets, time.Now, clientmodel.SelectorScopes(lkg.View)...)
			if errors.Is(err, clientadapter.ErrResourcesNotReady) {
				resourcesReady = false
				return writeWindowsRuntimeStatus(root, lkg, *active, false, selectorReadAt, readback())
			}
			if !windowsActivationApplied(next, routes, clientmodel.SelectorScopes(lkg.View)...) {
				return errors.Join(err, errors.New("Windows progressive selector application was not confirmed"))
			}
			if err != nil && !errors.Is(err, clientmodel.ErrNoUsableCandidate) {
				return err
			}
			*active = next
			selectorReadAt = time.Now()
			if !resourcesReady {
				ready, resourceErr := selector.ReconcileRuntimeResources(ctx, string(config))
				if ctx.Err() != nil {
					return ctx.Err()
				}
				resourcesReady = ready && resourceErr == nil
			}
			return writeWindowsRuntimeStatus(root, lkg, *active, false, selectorReadAt, readback())
		}
		recovery := &clientadapter.TCPRecoveryInput{Selector: selector, Routes: routes, State: active.State}
		recovery.Progress = func(batch []clientmodel.Observation) error {
			if _, err := store.Reload(); err != nil {
				return err
			}
			currentGeneration, err := windowsNetworkGeneration()
			if err != nil {
				return err
			}
			current := store.LKG()
			if ctx.Err() != nil {
				return ctx.Err()
			}
			if current == nil || current.ViewDigest != lkg.ViewDigest || currentGeneration != network || !store.Preference().Equal(preference) {
				return clientadapter.ErrSelectionSuperseded
			}
			active.State.NativeObservations, err = clientadapter.AcceptTCPRecovery(ctx, selector, recovery.State, active.State, routes, batch, time.Now)
			if err != nil {
				return err
			}
			return progress()
		}
		err := observeWindowsFirstHops(diagnosticContext, root, *lkg, active, initial, progress, recovery)
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if !errors.Is(err, clientadapter.ErrSelectionSuperseded) {
			return err
		}
		// A UI choice can replace the preference during sampling. Discard the
		// old work and reconcile immediately without restarting the data plane.
		current := store.LKG()
		if current == nil || current.ViewDigest != lkg.ViewDigest {
			return errWindowsConfigurationPending
		}
		generation, err := windowsNetworkGeneration()
		if err != nil {
			return err
		}
		if generation != network {
			if website.Port != 0 || windowsHasLocalNetwork(lkg.View) {
				return errWindowsRuntimeInputsChanged
			}
			active.State.NetworkGeneration = generation
			active.State.Observations, active.State.ResourceObservations = nil, nil
			active.State.SelectionMemory = nil
		}
		active.State.Preference = store.Preference()
		routes, err = clientadapter.AccessCandidates(lkg.View, clientmodel.MeasurementPolicies(active.State.Preference))
		if err != nil {
			return err
		}
		next, err := activateWindowsServices(diagnosticContext, selector, lkg.View, routes, active.State, false)
		if errors.Is(err, clientadapter.ErrResourcesNotReady) {
			resourcesReady = false
			return writeWindowsRuntimeStatus(root, lkg, *active, false, selectorReadAt, readback())
		}
		if !windowsActivationApplied(next, routes, clientmodel.SelectorScopes(lkg.View)...) {
			return errors.Join(err, errors.New("Windows replacement selection was not confirmed"))
		}
		*active = next
		selectorReadAt = time.Now()
		return writeWindowsRuntimeStatus(root, lkg, *active, false, selectorReadAt, readback())
	}
	// Only this goroutine applies runtime changes. Private workers accept
	// authentication and send temporary notifications/snapshots, never selectors.
	var workMu sync.Mutex
	var cancelWork, cancelReport context.CancelFunc
	interruptWork := func() {
		workMu.Lock()
		defer workMu.Unlock()
		if cancelWork != nil {
			cancelWork()
		}
		if cancelReport != nil {
			cancelReport()
		}
	}
	wake := make(chan struct{}, 1)
	requestWork := func() {
		select {
		case wake <- struct{}{}:
		default:
		}
	}
	privateContext, stopPrivate := context.WithCancel(diagnosticContext)
	configurationDone := make(chan error, 1)
	reportDone := make(chan struct{})
	reportRequests := make(chan *windowsReportAttempt, 1)
	reportResults := make(chan windowsReportResult, 1)
	go func() {
		configurationDone <- followWindowsConfiguration(privateContext, 5*time.Second, func(request context.Context) (bool, error) {
			before := store.LKG()
			reachable := true
			changed, err := refreshWindowsCertifiedView(request, store, func(attempt context.Context, identity deviceclient.IdentityStore) (control.DeviceViewEnvelope, error) {
				value, err := fetch(attempt, identity)
				reachable = err == nil
				return value, err
			})
			after := store.LKG()
			if changed || err != nil {
				interruptWork()
			}
			if changed || before != nil && after != nil && before.Signature != after.Signature {
				requestWork()
			}
			return reachable, err
		})
	}()
	go func() {
		defer close(reportDone)
		uploadWindowsReports(privateContext, reportRequests, reportResults, func(reportContext context.Context, report control.DeviceReport) error {
			attempt, cancel := context.WithTimeout(reportContext, 20*time.Second)
			workMu.Lock()
			cancelReport = cancel
			workMu.Unlock()
			defer func() {
				cancel()
				workMu.Lock()
				cancelReport = nil
				workMu.Unlock()
			}()
			current := store.LKG()
			if current == nil || current.ViewDigest != report.ViewDigest {
				return errWindowsConfigurationPending
			}
			report.WireGuardCounters, _ = clientadapter.ObserveWireGuardCounters(attempt, current.View, time.Now)
			return deviceclient.Report(attempt, store, report)
		})
	}()
	configurationStopped := false
	defer func() {
		stopPrivate()
		interruptWork()
		if !configurationStopped {
			<-configurationDone
		}
		<-reportDone
	}()

	componentReadbacks, componentErr := windowsComponentReadbacks(dataPlanePID, components, heldComponents)
	if componentErr != nil {
		log.Printf("actual Windows component readback incomplete: %v", componentErr)
	}
	var pendingReport *windowsReportAttempt
	lastReportAt := time.Time{}
	lastFacts, lastReportedView := "", ""
	queueReport := func() error {
		now := time.Now()
		facts := windowsRuntimeFactsDigest(activation, componentReadbacks, readback())
		if facts == lastFacts && lastReportedView == lkg.ViewDigest && now.Sub(lastReportAt) < 60*time.Second ||
			windowsReportMatches(pendingReport, lkg.ViewDigest, facts) {
			return nil
		}
		report, err := windowsDeviceReport(lkg, activation, componentReadbacks, now, readback())
		if err != nil {
			return err
		}
		pendingReport = &windowsReportAttempt{report: report, facts: facts}
		offerLatestWindows(reportRequests, pendingReport)
		return nil
	}
	// Publish the locally applied selector before any full sampling round or
	// report acknowledgement. Business success remains a separate observation.
	if err := queueReport(); err != nil {
		return err
	}
	if activationErr != nil {
		log.Printf("Windows candidate activation completed with unavailable outcome: %v", activationErr)
	}
	refresh := time.NewTicker(30 * time.Second)
	defer refresh.Stop()
	nativeRefresh := time.NewTicker(5 * time.Second)
	defer nativeRefresh.Stop()
	requestWork()
	for {
		select {
		case <-ctx.Done():
			planeStopped = true
			return <-planeDone
		case err := <-planeDone:
			planeStopped = true
			return err
		case err := <-configurationDone:
			configurationStopped = true
			return err
		case result := <-reportResults:
			if result.attempt != pendingReport {
				continue
			}
			pendingReport = nil
			if result.err != nil {
				if !errors.Is(result.err, context.Canceled) && !errors.Is(result.err, errWindowsConfigurationPending) {
					log.Printf("private signed Windows report unavailable: %v", result.err)
				}
				continue
			}
			if windowsReportMatches(result.attempt, lkg.ViewDigest, windowsRuntimeFactsDigest(activation, componentReadbacks, readback())) {
				lastReportAt, lastFacts, lastReportedView = time.Now(), result.attempt.facts, result.attempt.report.ViewDigest
				if err := writeWindowsRuntimeStatus(root, lkg, activation, true, selectorReadAt, readback()); err != nil {
					return err
				}
			}
			continue
		case <-refresh.C:
		case <-nativeRefresh.C:
			if !resourcesReady {
				requestWork()
				continue
			}
			current := store.LKG()
			generation, genErr := windowsNetworkGeneration()
			if genErr != nil {
				return genErr
			}
			if current == nil || current.ViewDigest != lkg.ViewDigest || generation != activation.State.NetworkGeneration || !store.Preference().Equal(activation.State.Preference) {
				requestWork()
				continue
			}
			workContext, cancel := context.WithCancel(diagnosticContext)
			workMu.Lock()
			cancelWork = cancel
			workMu.Unlock()
			if current := store.LKG(); current == nil || current.ViewDigest != lkg.ViewDigest {
				cancel()
			}
			refreshed, needsRouting, refreshErr := clientadapter.RefreshNativeObservations(workContext, selector, routes, activation.State, time.Now)
			next, nextErr := activation, refreshErr
			if refreshErr == nil && needsRouting {
				_, targets := windowsProbeTargets(lkg.View, activation.State.Preference.PolicyID)
				next, nextErr = clientadapter.Activate(workContext, selector, routes, refreshed, targets, time.Now, clientmodel.SelectorScopes(lkg.View)...)
			} else {
				next.State = refreshed
			}
			cancel()
			workMu.Lock()
			cancelWork = nil
			workMu.Unlock()
			if errors.Is(nextErr, clientadapter.ErrResourcesNotReady) {
				resourcesReady = false
				requestWork()
				continue
			}
			if nextErr != nil && !errors.Is(nextErr, clientmodel.ErrNoUsableCandidate) {
				if ctx.Err() != nil {
					continue
				}
				continue
			}
			if current := store.LKG(); current == nil || current.ViewDigest != lkg.ViewDigest {
				continue
			}
			currentGeneration, generationErr := windowsNetworkGeneration()
			if generationErr != nil {
				return generationErr
			}
			if currentGeneration != generation || !store.Preference().Equal(next.State.Preference) {
				continue
			}
			activation = next
			if !needsRouting {
				continue
			}
			selectorReadAt = time.Now()
			if err := writeWindowsRuntimeStatus(root, lkg, activation, false, selectorReadAt, readback()); err != nil {
				return err
			}
			continue
		case <-wake:
		}
		if _, err := store.Reload(); err != nil {
			return err
		}
		nextLKG := store.LKG()
		if nextLKG == nil || !control.HasRuntime(nextLKG.View) {
			return errWindowsRuntimeInputsChanged
		}
		changed := nextLKG.ViewDigest != lkg.ViewDigest
		if changed {
			permissionCurrent, resourcesReady = false, false
			if !reflect.DeepEqual(lkg.View.WebEndpoints, nextLKG.View.WebEndpoints) {
				return errWindowsRuntimeInputsChanged
			}
			source, err := clientadapter.AccessRuntimeSource(lkg.View, selectorSecret)
			if err != nil {
				return err
			}
			source, err = clientadapter.WithBlockedSelectors(source)
			if err != nil {
				return err
			}
			nextSource, err := clientadapter.AccessRuntimeSource(nextLKG.View, selectorSecret)
			if err != nil {
				return err
			}
			nextSource, err = clientadapter.WithBlockedSelectors(nextSource)
			if err != nil {
				return err
			}
			application, err := selector.ApplyRuntimeAuthorization(ctx, source, nextSource, string(config))
			if err != nil {
				return err
			}
			if !application.Supported {
				return errWindowsRuntimeInputsChanged
			}
			if !application.PermissionCurrent {
				return errors.New("Windows accepted authorization was not confirmed")
			}
			permissionCurrent = true
			// Keep the complete current source template in RAM. Only the
			// constructor input given to the supervised child is stripped.
			clear(config)
			config = []byte(application.Config)
			resourcesReady = false
		}
		lkg = nextLKG
		workContext, workCancel := context.WithCancel(diagnosticContext)
		workMu.Lock()
		cancelWork = workCancel
		workMu.Unlock()
		// Close the accept-before-registration race as well as the normal
		// registration-before-accept cancellation path.
		if current := store.LKG(); current == nil || current.ViewDigest != lkg.ViewDigest {
			workCancel()
		}
		workErr := func() error {
			ready, resourceErr := selector.ReconcileRuntimeResources(workContext, string(config))
			if workContext.Err() != nil {
				return workContext.Err()
			}
			resourcesReady = ready && resourceErr == nil && windowsActivationApplied(activation, routes, clientmodel.SelectorScopes(lkg.View)...)
			nextGeneration, err := windowsNetworkGeneration()
			if err != nil {
				log.Printf("Windows network generation refresh unavailable: %v", err)
				return nil
			}
			nextState := activation.State
			nextState.Preference = store.Preference()
			selectionChanged := changed || !nextState.Preference.Equal(activation.State.Preference) || nextGeneration != nextState.NetworkGeneration
			routes, err = clientadapter.AccessCandidates(lkg.View, clientmodel.MeasurementPolicies(nextState.Preference))
			if err != nil {
				return err
			}
			if nextGeneration != nextState.NetworkGeneration {
				if website.Port != 0 || windowsHasLocalNetwork(lkg.View) {
					return errWindowsRuntimeInputsChanged
				}
				nextState.NetworkGeneration = nextGeneration
				nextState.Observations, nextState.ResourceObservations = nil, nil
				nextState.SelectionMemory = nil
			} else if changed {
				execution, err := control.ProjectDeviceCandidates(lkg.View, clientmodel.MeasurementPolicies(nextState.Preference))
				if err != nil {
					return err
				}
				probes, err := control.FirstHopProbes(execution)
				if err != nil {
					return err
				}
				nextState.ResourceObservations = clientadapter.RetainResourceObservations(probes, nextState.ResourceObservations, nextGeneration)
			}
			// Apply accepted authorization and UI choices before private sample
			// retrieval. Neither retrieval nor a full probe round is an apply gate.
			if selectionChanged || !resourcesReady {
				next, nextErr := activateWindowsServices(workContext, selector, lkg.View, routes, nextState, false)
				if workContext.Err() != nil {
					return workContext.Err()
				}
				if errors.Is(nextErr, clientadapter.ErrResourcesNotReady) {
					resourcesReady = false
					activation = next
				} else if !windowsActivationApplied(next, routes, clientmodel.SelectorScopes(lkg.View)...) {
					return fmt.Errorf("Windows selector application failed: %w", nextErr)
				} else {
					activation = next
				}
				selectorReadAt = time.Now()
				if err := writeWindowsRuntimeStatus(root, lkg, activation, false, selectorReadAt, readback()); err != nil {
					return err
				}
			}
			measurements = refreshWindowsLinkObservations(workContext, store, lkg, &activation.State, measurements)
			if workContext.Err() != nil {
				return workContext.Err()
			}
			next, nextErr := activateWindowsServices(workContext, selector, lkg.View, routes, activation.State, true)
			if workContext.Err() != nil {
				return workContext.Err()
			}
			if errors.Is(nextErr, clientadapter.ErrSelectionSuperseded) {
				return nil
			}
			if errors.Is(nextErr, clientadapter.ErrResourcesNotReady) {
				resourcesReady = false
			} else if !windowsActivationApplied(next, routes, clientmodel.SelectorScopes(lkg.View)...) {
				return fmt.Errorf("Windows sampled selector application failed: %w", nextErr)
			}
			activation = next
			selectorReadAt = time.Now()
			if err := measureFirstHops(workContext, &activation, nil); err != nil {
				return err
			}
			ready, resourceErr = selector.ReconcileRuntimeResources(workContext, string(config))
			if workContext.Err() != nil {
				return workContext.Err()
			}
			resourcesReady = ready && resourceErr == nil && windowsActivationApplied(activation, routes, clientmodel.SelectorScopes(lkg.View)...)
			if err := queueReport(); err != nil {
				return err
			}
			if nextErr != nil {
				log.Printf("Windows candidate refresh completed with unavailable outcome: %v", nextErr)
			}
			return writeWindowsRuntimeStatus(root, lkg, activation, time.Since(lastReportAt) < 60*time.Second && lastReportedView == lkg.ViewDigest && lastFacts == windowsRuntimeFactsDigest(activation, componentReadbacks, readback()), selectorReadAt, readback())
		}()
		workCancel()
		workMu.Lock()
		cancelWork = nil
		workMu.Unlock()
		if errors.Is(workErr, errWindowsConfigurationPending) {
			requestWork()
			continue
		}
		if errors.Is(workErr, context.Canceled) && ctx.Err() == nil {
			continue
		}
		if workErr != nil {
			return workErr
		}
	}
}

func runWindowsCertifiedProfile(ctx context.Context, root string, store *deviceclient.ProtectedStore,
	profile clientruntime.WindowsRuntimeProfile) error {
	var round uint64
	for {
		err := runWindowsGeneration(ctx, root, store, profile, func(ctx context.Context, identity deviceclient.IdentityStore) (control.DeviceViewEnvelope, error) {
			value, err := deviceclient.AwaitConfiguration(ctx, identity, round)
			round++
			return value, err
		})
		if ctx.Err() != nil {
			return err
		}
		if errors.Is(err, errWindowsRuntimeInputsChanged) {
			continue
		}
		return err
	}
}

func programDataRoot() (string, error) {
	base := os.Getenv("ProgramData")
	if base == "" || !filepath.IsAbs(base) {
		return "", fmt.Errorf("ProgramData is missing or not absolute")
	}
	return filepath.Join(base, "Loom"), nil
}

func localAppDataRoot() (string, error) {
	base := os.Getenv("LocalAppData")
	if base == "" || !filepath.IsAbs(base) {
		return "", fmt.Errorf("LocalAppData is missing or not absolute")
	}
	return filepath.Join(base, "LoomPortable"), nil
}

func portableStateDescription() string {
	root, err := localAppDataRoot()
	if err != nil {
		return "unavailable"
	}
	return root
}

func windowsHasLocalNetwork(view control.DeviceView) bool {
	for _, service := range view.Services {
		if service.LocalNetwork != nil {
			return true
		}
	}
	return false
}

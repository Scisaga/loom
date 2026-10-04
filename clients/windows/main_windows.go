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
	"runtime"
	"sort"
	"strings"
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
	Schema       int                             `json:"schema"`
	DeviceID     string                          `json:"device_id"`
	ViewDigest   string                          `json:"view_digest"`
	RuntimeState string                          `json:"runtime_state"`
	Preference   clientmodel.Preference          `json:"preference"`
	Selections   []clientadapter.SelectionStatus `json:"selections"`
	Observations []clientmodel.Observation       `json:"observations"`
	Reported     bool                            `json:"reported"`
}

func windowsRuntimeStatusPath(root string) string {
	return filepath.Join(root, "runtime", "status.json")
}

func writeWindowsRuntimeStatus(root string, lkg *control.DeviceViewEnvelope, activation clientadapter.Activation, reported bool) error {
	status := windowsRuntimeStatus{Schema: 3, DeviceID: lkg.View.DeviceID, ViewDigest: lkg.ViewDigest, RuntimeState: "running",
		Preference: activation.State.Preference, Selections: activation.Selections,
		Observations: activation.State.Observations, Reported: reported}
	body, err := json.MarshalIndent(status, "", "  ")
	if err != nil {
		return err
	}
	return writeWindowsJoinFile(windowsRuntimeStatusPath(root), append(body, '\n'))
}

func windowsProbeTarget(view control.DeviceView) (string, string) {
	if len(view.BusinessProbeTargets) != 1 || len(view.BusinessProbeTargets[0].Targets) != 1 || len(view.DNSServers) == 0 {
		return "", ""
	}
	group := view.BusinessProbeTargets[0]
	for _, route := range view.Routes {
		if route.ServiceID != group.ServiceID {
			return "", ""
		}
	}
	if len(view.Routes) == 0 {
		return "", ""
	}
	return group.ServiceID, group.Targets[0]
}
func windowsBusinessProbe(view control.DeviceView) (clientadapter.Probe, error) {
	_, target := windowsProbeTarget(view)
	if target == "" {
		return nil, nil
	}
	return clientadapter.BusinessProbe("127.0.0.1:1080", view.DNSServers[0], target)
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

func windowsComponentReadbacks(view control.DeviceView, components clientcomponent.RuntimePaths) []control.ComponentReadback {
	coordinate := version.Self()
	componentVersion := coordinate.Tag
	if componentVersion == "" {
		componentVersion = coordinate.Commit
	}
	actual := map[string]control.ComponentReadback{
		"sing-box": {ComponentID: "sing-box", Platform: "windows-" + runtime.GOARCH, Version: strings.TrimPrefix(components.Manifest.SingBox.Version, "v"), ArtifactDigest: "sha256:" + components.Manifest.SingBox.SHA256},
		"wintun":   {ComponentID: "wintun", Platform: "windows-" + runtime.GOARCH, Version: strings.TrimPrefix(components.Manifest.Wintun.Version, "v"), ArtifactDigest: "sha256:" + components.Manifest.Wintun.SHA256},
		"agent":    {ComponentID: "agent", Platform: "windows-" + runtime.GOARCH, Version: componentVersion, ArtifactDigest: "sha256:" + coordinate.Binary},
	}
	result := []control.ComponentReadback{}
	for _, expected := range view.ExpectedComponents {
		if value, ok := actual[expected.ComponentID]; ok && value.Platform == expected.Platform && value.Version != "" && value.Validate() == nil {
			result = append(result, value)
		}
	}
	return result
}

func windowsDeviceReport(lkg *control.DeviceViewEnvelope, activation clientadapter.Activation,
	components []control.ComponentReadback, reportedAt time.Time) (control.DeviceReport, error) {
	report := control.DeviceReport{ViewDigest: lkg.ViewDigest, NetworkGeneration: activation.State.NetworkGeneration, ReportedAt: reportedAt.UnixMilli(),
		Selections: []control.ReportSelection{}, Observations: []control.Observation{}, Components: append([]control.ComponentReadback{}, components...),
		Runtime: control.RuntimeReadback{State: "running", AppliedViewDigest: lkg.ViewDigest}}
	routes := map[string]control.RouteCandidate{}
	for _, route := range lkg.View.Routes {
		routes[route.ID] = route
	}
	for _, selection := range activation.Selections {
		route, ok := routes[selection.CandidateID]
		if !ok || route.Scope != selection.Scope {
			return control.DeviceReport{}, errors.New("selection is not in the accepted View")
		}
		report.Selections = append(report.Selections, control.ReportSelection{ServiceID: route.ServiceID, CandidateID: route.ID})
	}
	sort.Slice(report.Selections, func(i, j int) bool { return report.Selections[i].ServiceID < report.Selections[j].ServiceID })
	service, target := windowsProbeTarget(lkg.View)
	for _, observation := range activation.State.Observations {
		route, ok := routes[observation.CandidateID]
		if target == "" || !ok || route.ServiceID != service || route.Scope != observation.Scope || observation.NetworkGeneration != report.NetworkGeneration {
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
	sort.Slice(report.Observations, func(i, j int) bool { return report.Observations[i].CandidateID < report.Observations[j].CandidateID })
	return report, nil
}

func windowsActivationApplied(activation clientadapter.Activation, routes []clientmodel.RouteCandidate) bool {
	scopes, byScope, err := clientadapter.Scopes(routes)
	if err != nil || activation.State.NetworkGeneration == "" || len(activation.Selections) != len(scopes) {
		return false
	}
	seen := map[string]bool{}
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

func windowsRuntimeFactsDigest(activation clientadapter.Activation, components []control.ComponentReadback) string {
	body, _ := json.Marshal(struct {
		Selections   []clientadapter.SelectionStatus `json:"selections"`
		Observations []clientmodel.Observation       `json:"observations"`
		Components   []control.ComponentReadback     `json:"components"`
	}{activation.Selections, activation.State.Observations, components})
	digest := sha256.Sum256(body)
	return hex.EncodeToString(digest[:])
}

var errWindowsCertifiedViewChanged = errors.New("a newer certified Windows device view is available")

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
	refreshContext, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	envelope, err := fetch(refreshContext, store)
	if reloaded, readErr := store.Reload(); readErr != nil {
		return false, readErr
	} else if reloaded {
		return changed(), nil
	}
	if ctx.Err() != nil {
		return false, ctx.Err()
	}
	if err != nil {
		log.Printf("private Windows view refresh unavailable; keeping certified LKG: %v", err)
		return false, nil
	}
	// Every authenticated envelope advances the durable proof/frontier. Only
	// changed execution inputs stop the current data-plane generation.
	if err = store.SaveLKG(envelope); err != nil {
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
	if _, err := refreshWindowsCertifiedView(ctx, store, fetch); err != nil {
		return err
	}
	lkg := store.LKG()
	if lkg == nil || lkg.View.RuntimeProfile == nil {
		return errors.New("Windows profile lost its certified LKG")
	}
	if _, _, err := clientadapter.AccessProjection(lkg.View); err != nil {
		return err
	}
	// Authentication is already durable. Component verification and runtime
	// application may fail, but cannot put the previous authorization back.
	components, err := loadWindowsRuntimeComponents(root)
	if err != nil {
		return err
	}
	localSecret := make([]byte, 32)
	if _, err := rand.Read(localSecret); err != nil {
		return err
	}
	source, err := clientadapter.AccessRuntimeSource(lkg.View, hex.EncodeToString(localSecret))
	clear(localSecret)
	if err != nil {
		return err
	}
	config, err := clientruntime.DeriveWindowsRuntimeConfig([]byte(source), profile, lkg.View.DNSServers)
	if err != nil {
		return err
	}
	defer clear(config)
	generationContext, stopGeneration := context.WithCancel(ctx)
	defer stopGeneration()
	ctx = generationContext
	planeDone := make(chan error, 1)
	started := make(chan struct{})
	go func() {
		base := root
		if filepath.Base(filepath.Dir(root)) == "profiles" && validConnectionProfileID(filepath.Base(root)) {
			base = filepath.Dir(filepath.Dir(root))
		}
		planeDone <- clientruntime.RunWindowsDataPlaneProfileStarted(ctx, components.SingBox, config,
			filepath.Join(root, "runtime"), filepath.Join(base, "dataplane-cache"), profile, func() { close(started) })
	}()
	select {
	case <-ctx.Done():
		return <-planeDone
	case err := <-planeDone:
		return err
	case <-started:
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
	routes, _, err := clientadapter.AccessProjection(lkg.View)
	if err != nil {
		return err
	}
	scopes, _, err := clientadapter.Scopes(routes)
	if err != nil {
		return err
	}
	if err := clientadapter.WaitSelector(ctx, selector, scopes); err != nil {
		return err
	}
	generation, err := windowsNetworkGeneration()
	if err != nil {
		return err
	}
	activation, activationErr := clientadapter.Activate(ctx, selector, routes, clientadapter.State{
		Preference: store.Preference(), NetworkGeneration: generation}, nil, time.Now)
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if !windowsActivationApplied(activation, routes) {
		return activationErr
	}
	if err := writeWindowsRuntimeStatus(root, lkg, activation, false); err != nil {
		return err
	}
	probe, probeErr := windowsBusinessProbe(lkg.View)
	if probeErr != nil {
		log.Printf("certified Windows business probe unavailable; keeping unknown: %v", probeErr)
	}
	if probe != nil {
		activation, activationErr = clientadapter.Activate(ctx, selector, routes, activation.State, probe, time.Now)
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if !windowsActivationApplied(activation, routes) {
			return activationErr
		}
	}
	componentReadbacks := windowsComponentReadbacks(lkg.View, components)
	report, err := windowsDeviceReport(lkg, activation, componentReadbacks, time.Now())
	if err != nil {
		return err
	}
	reportContext, reportCancel := context.WithTimeout(ctx, 20*time.Second)
	reportErr := deviceclient.Report(reportContext, store, report)
	reportCancel()
	lastReportAt := time.Time{}
	if reportErr == nil {
		lastReportAt = time.Now()
	}
	lastFacts := windowsRuntimeFactsDigest(activation, componentReadbacks)
	if err := writeWindowsRuntimeStatus(root, lkg, activation, reportErr == nil); err != nil {
		return err
	}
	if reportErr != nil {
		log.Printf("private signed report unavailable: %v", reportErr)
	}
	if activationErr != nil {
		log.Printf("Windows candidate activation completed with unavailable outcome: %v", activationErr)
	}
	refresh := time.NewTicker(30 * time.Second)
	defer refresh.Stop()
	for {
		select {
		case <-ctx.Done():
			planeStopped = true
			return <-planeDone
		case err := <-planeDone:
			planeStopped = true
			return err
		case <-refresh.C:
			changed, err := refreshWindowsCertifiedView(ctx, store, fetch)
			if err != nil {
				return err
			}
			if changed {
				return errWindowsCertifiedViewChanged
			}
			lkg = store.LKG()
			now := time.Now()
			nextGeneration, generationErr := windowsNetworkGeneration()
			if generationErr != nil {
				log.Printf("Windows network generation refresh unavailable: %v", generationErr)
				continue
			}
			nextState := activation.State
			nextState.Preference = store.Preference()
			if nextGeneration != nextState.NetworkGeneration {
				nextState.NetworkGeneration = nextGeneration
				nextState.Observations = nil
			}
			next, nextErr := clientadapter.Activate(ctx, selector, routes, nextState,
				probe, time.Now)
			if ctx.Err() != nil {
				return ctx.Err()
			}
			if !windowsActivationApplied(next, routes) {
				return fmt.Errorf("Windows selector application failed: %w", nextErr)
			}
			facts := windowsRuntimeFactsDigest(next, componentReadbacks)
			if facts != lastFacts || now.Sub(lastReportAt) >= 60*time.Second {
				nextReport, buildErr := windowsDeviceReport(lkg, next, componentReadbacks, now)
				if buildErr != nil {
					return buildErr
				}
				reportContext, reportCancel := context.WithTimeout(ctx, 20*time.Second)
				reportErr := deviceclient.Report(reportContext, store, nextReport)
				reportCancel()
				if reportErr != nil {
					log.Printf("private signed report refresh unavailable: %v", reportErr)
				} else {
					lastReportAt, lastFacts = now, facts
				}
			}
			activation = next
			if writeErr := writeWindowsRuntimeStatus(root, lkg, activation, now.Sub(lastReportAt) < 60*time.Second); writeErr != nil {
				return writeErr
			}
			if nextErr != nil {
				log.Printf("Windows candidate refresh completed with unavailable outcome: %v", nextErr)
			}
		}
	}
}

func runWindowsCertifiedProfile(ctx context.Context, root string, store *deviceclient.ProtectedStore,
	profile clientruntime.WindowsRuntimeProfile) error {
	for {
		err := runWindowsGeneration(ctx, root, store, profile, deviceclient.Fetch)
		if ctx.Err() != nil {
			return err
		}
		if errors.Is(err, errWindowsCertifiedViewChanged) {
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

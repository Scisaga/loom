//go:build windows

package main

import (
	"context"
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
	caPath := windowsClientCAPath(root, edition)
	store, err := deviceclient.LoadProtected(windowsProfileStatePath(root), protector)
	if errors.Is(err, os.ErrNotExist) {
		log.Printf("client has not joined a Loom network: waiting for QR import")
		return waitForJoinedClient(root, protector, edition), nil
	}
	if err != nil {
		return nil, err
	}
	lkg := store.LKG()
	if lkg == nil || lkg.View.Platform != "windows" || lkg.View.Runtime == nil {
		return nil, errors.New("Windows profile has no complete certified LKG")
	}
	if _, err := clientmodel.ProjectRuntimeCandidates(lkg.View.Routes, *lkg.View.Runtime); err != nil {
		return nil, fmt.Errorf("project certified Windows candidates: %w", err)
	}
	publicKey, err := embeddedWindowsPlatformKey()
	if err != nil {
		return nil, err
	}
	componentState, err := clientcomponent.ReadState(root)
	if err != nil {
		return nil, fmt.Errorf("read signed component state: %w", err)
	}
	if componentState == nil {
		return nil, errors.New("signed Windows component is not installed")
	}
	components, err := clientcomponent.LoadWindows(root, publicKey, runtime.GOARCH, componentState.Current.SingBoxVersion)
	if err != nil {
		return nil, fmt.Errorf("load signed Windows component: %w", err)
	}
	preflight := func(ctx context.Context, envelope control.DeviceViewEnvelope) error {
		if envelope.View.Runtime == nil {
			return errors.New("certified Windows view has no runtime profile")
		}
		derived, err := clientruntime.DeriveWindowsRuntimeConfig([]byte(envelope.View.Runtime.Config), profile, caPath)
		if err != nil {
			return err
		}
		defer clear(derived)
		return clientruntime.PreflightWindowsRuntime(ctx, components.SingBox, derived,
			filepath.Join(root, "runtime"), profile, caPath)
	}
	checkContext, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	err = preflight(checkContext, *lkg)
	cancel()
	if err != nil {
		return nil, fmt.Errorf("preflight certified Windows LKG: %w", err)
	}
	store.SetLKGPreflight(func(envelope control.DeviceViewEnvelope) error {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		return preflight(ctx, envelope)
	})
	return func(ctx context.Context) error {
		dataPlaneLock, err := acquireWindowsDataPlaneLock()
		if err != nil {
			return err
		}
		defer dataPlaneLock.close()
		return runWindowsCertifiedProfile(ctx, root, store, components, profile, caPath)
	}, nil
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

func windowsClientCAPath(root string, edition clientEdition) string {
	// §13.5：每份连接配置读取自己的 CA；运行预检限定机器根和已登记目录形状。
	return filepath.Join(root, "tls", "ca.crt")
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
	Head         string                          `json:"head"`
	Preference   clientmodel.Preference          `json:"preference"`
	Selections   []clientadapter.SelectionStatus `json:"selections"`
	Observations []clientmodel.Observation       `json:"observations"`
	Reported     bool                            `json:"reported"`
}

func windowsRuntimeStatusPath(root string) string {
	return filepath.Join(root, "runtime", "status.json")
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
	return "sha256:" + hex.EncodeToString(digest[:]), nil
}

func runWindowsCertifiedProfile(ctx context.Context, root string, store *deviceclient.ProtectedStore,
	components clientcomponent.RuntimePaths, profile clientruntime.WindowsRuntimeProfile, caPath string) error {
	statusPath := windowsRuntimeStatusPath(root)
	_ = os.Remove(statusPath)
	defer os.Remove(statusPath) //nolint:errcheck
	syncContext, cancel := context.WithTimeout(ctx, 20*time.Second)
	if _, err := deviceclient.Sync(syncContext, store); err != nil {
		log.Printf("private device sync unavailable; using certified LKG: %v", err)
	}
	cancel()
	lkg := store.LKG()
	if lkg == nil || lkg.View.Runtime == nil {
		return errors.New("Windows profile lost its certified LKG")
	}
	if _, err := clientmodel.ProjectRuntimeCandidates(lkg.View.Routes, *lkg.View.Runtime); err != nil {
		return err
	}
	config, err := clientruntime.DeriveWindowsRuntimeConfig([]byte(lkg.View.Runtime.Config), profile, caPath)
	if err != nil {
		return err
	}
	defer clear(config)
	planeDone := make(chan error, 1)
	started := make(chan struct{})
	go func() {
		planeDone <- clientruntime.RunWindowsDataPlaneProfileStarted(ctx, components.SingBox, config,
			filepath.Join(root, "runtime"), profile, caPath, func() { close(started) })
	}()
	select {
	case <-ctx.Done():
		return <-planeDone
	case err := <-planeDone:
		return err
	case <-started:
	}
	selector, err := clientadapter.NewHTTPSelector(string(config))
	if err != nil {
		return err
	}
	scopes, _, err := clientadapter.Scopes(lkg.View.Routes)
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
	activation, activationErr := clientadapter.Activate(ctx, selector, lkg.View.Routes, clientadapter.State{
		Preference: store.Preference(), NetworkGeneration: generation}, clientadapter.BusinessProbe, time.Now)
	if activation.State.NetworkGeneration == "" {
		return activationErr
	}
	selected := ""
	if len(activation.Selections) > 0 {
		selected = activation.Selections[0].CandidateID
	}
	report := control.DeviceReport{Selection: selected, ReportedAt: time.Now().UTC().Truncate(time.Second).Format(time.RFC3339),
		Observations: append([]control.Observation(nil), activation.State.Observations...)}
	reportContext, reportCancel := context.WithTimeout(ctx, 20*time.Second)
	reportErr := deviceclient.Report(reportContext, store, report)
	reportCancel()
	status := windowsRuntimeStatus{Schema: 1, DeviceID: lkg.View.DeviceID, Head: control.HeadID(lkg.Head),
		Preference: activation.State.Preference, Selections: activation.Selections,
		Observations: activation.State.Observations, Reported: reportErr == nil}
	body, err := json.MarshalIndent(status, "", "  ")
	if err == nil {
		err = writeWindowsJoinFile(statusPath, append(body, '\n'))
	}
	if err != nil {
		return err
	}
	if reportErr != nil {
		log.Printf("private signed report unavailable: %v", reportErr)
	}
	if activationErr != nil {
		log.Printf("Windows candidate activation completed with unavailable outcome: %v", activationErr)
	}
	select {
	case <-ctx.Done():
		return <-planeDone
	case err := <-planeDone:
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

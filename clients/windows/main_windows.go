//go:build windows

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"

	"loom/internal/clientcomponent"
	"loom/internal/clientcore"
	"loom/internal/clientruntime"
	"loom/internal/clientsecret"
	"loom/internal/clientupdate"
	"loom/internal/netx"
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
			handler := &loomService{prepare: prepareClient}
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

func prepareClientAt(root string, protector clientsecret.Protector, edition clientEdition, reportClients ...*http.Client) (func(context.Context) error, error) {
	profile, err := runtimeProfile(edition)
	if err != nil {
		return nil, err
	}
	caPath := windowsClientCAPath(root, edition)
	preferencePath := filepath.Join(root, "state", "preference.json")
	if _, err := clientcore.EnsurePreference(preferencePath); err != nil {
		return nil, fmt.Errorf("initialize local route preference: %w", err)
	}

	configPath := filepath.Join(root, "config", "client.json")
	config, err := clientupdate.ReadConfig(configPath)
	if os.IsNotExist(err) {
		log.Printf("client has not joined a Loom network: waiting for QR import")
		return waitForJoinedClient(root, protector, edition), nil
	}
	if err != nil {
		return nil, err
	}
	publicKey, err := clientupdate.ReadPublicKey(filepath.Join(root, "trust", "platform.pub"))
	if err != nil {
		return nil, fmt.Errorf("load pinned platform key: %w", err)
	}
	// Refuse to run over corrupt local coordinates. Network reconciliation may
	// add a newer package, but it must never erase evidence of local corruption.
	verifiedState, err := clientupdate.ReadVerifiedState(root)
	if err != nil {
		return nil, fmt.Errorf("validate local verified state: %w", err)
	}
	vaultPath := filepath.Join(root, "secrets", "vault.json.dpapi")
	prepareActivation := func() (*clientActivation, error) {
		candidate, err := clientruntime.PrepareWindowsCandidate(root, config.NodeID, publicKey, vaultPath, protector)
		if err != nil {
			return nil, err
		}
		if candidate.Components.SingBox == "" {
			return nil, errors.New("signed snapshot does not declare the Windows sing-box version")
		}
		components, err := clientcomponent.LoadWindows(root, publicKey, runtime.GOARCH, candidate.Components.SingBox)
		if err != nil {
			return nil, fmt.Errorf("select signed Windows data plane: %w", err)
		}
		sourceConfig, candidateState, err := clientruntime.ReadCandidateConfig(root, protector)
		if err != nil {
			return nil, fmt.Errorf("load protected Windows candidate: %w", err)
		}
		defer clear(sourceConfig)
		if candidateState.Current != candidate.Version {
			return nil, errors.New("prepared candidate does not match the protected current pointer")
		}
		runtimeConfig, err := clientruntime.DeriveWindowsRuntimeConfig(sourceConfig, profile, caPath)
		if err != nil {
			return nil, err
		}
		health, err := clientruntime.BuildWindowsHealthPlan(runtimeConfig, profile, caPath)
		if err != nil {
			clear(runtimeConfig)
			return nil, err
		}
		return &clientActivation{
			Version: candidate.Version, SlotID: components.SlotID, Executable: components.SingBox,
			Config: runtimeConfig, RuntimeDir: filepath.Join(root, "runtime"), Profile: profile, CAPath: caPath, WaitForStart: true,
			Health: health,
		}, nil
	}
	var initial *clientActivation
	if verifiedState != nil {
		initial, err = prepareActivation()
		if err != nil {
			return nil, fmt.Errorf("restore protected Windows candidate: %w", err)
		}
		log.Printf("restored protected Windows candidate snapshot=%s", initial.Version.Snapshot)
	} else {
		// Joining is a complete transaction: config, trust root, and the
		// protected vault must all be usable before the Service reports Running.
		secrets, err := clientsecret.ReadVault(vaultPath, protector)
		if err != nil {
			return nil, fmt.Errorf("validate protected joined-device vault: %w", err)
		}
		clear(secrets)
	}
	dnsServer := ""
	if len(config.DNS) > 0 {
		dnsServer = config.DNS[0]
	}
	updater := &clientupdate.Updater{
		Client:              netx.Client(dnsServer, 60*time.Second),
		Config:              config,
		PublicKey:           publicKey,
		StateRoot:           root,
		ExpectedCurrentPath: filepath.Join(root, "state", "expected-current.json"),
	}
	return func(ctx context.Context) error {
		dataPlaneLock, err := acquireWindowsDataPlaneLock()
		if err != nil {
			return err
		}
		defer dataPlaneLock.close()
		var reportClient *http.Client
		if len(reportClients) > 0 {
			reportClient = reportClients[0]
		}
		reporter, err := startWindowsReporter(root, protector, config, reportClient)
		if err != nil {
			if initial != nil {
				initial.clear()
			}
			return err
		}
		defer reporter.stop()
		return runActiveUpdateLoop(ctx, updater, config.PullInterval(), initial, prepareActivation,
			preflightClientActivation, runClientActivation, dataPlaneStartupGrace, reporter.update)
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
	if edition == editionInstalled {
		return clientruntime.WindowsInstalledCAPath
	}
	return filepath.Join(root, "tls", "ca.crt")
}

func preflightClientActivation(ctx context.Context, activation *clientActivation) error {
	return clientruntime.PreflightWindowsRuntime(ctx, activation.Executable, activation.Config,
		activation.RuntimeDir, activation.Profile, activation.CAPath)
}

func runClientActivation(ctx context.Context, activation *clientActivation) error {
	return clientruntime.RunWindowsDataPlaneProfileStarted(ctx, activation.Executable, activation.Config,
		activation.RuntimeDir, activation.Profile, activation.CAPath, activation.Started)
}

func waitForJoinedClient(root string, protector clientsecret.Protector, edition clientEdition) func(context.Context) error {
	return func(ctx context.Context) error {
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		configPath := filepath.Join(root, "config", "client.json")
		for {
			select {
			case <-ctx.Done():
				return nil
			case <-ticker.C:
				if _, err := clientupdate.ReadConfig(configPath); errors.Is(err, os.ErrNotExist) {
					continue
				} else if err != nil {
					return fmt.Errorf("load joined-device state: %w", err)
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

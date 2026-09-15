//go:build windows

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sync"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/eventlog"

	"loom/internal/agent"
	"loom/internal/clientcore"
	"loom/internal/clientruntime"
	"loom/internal/clientsecret"
	"loom/internal/version"
)

const serviceName = "LoomClient"

var (
	windowsProbeRegistryOnce sync.Once
	windowsProbeRegistry     *agent.EntryProbeRegistry
)

func processWindowsProbeRegistry() *agent.EntryProbeRegistry {
	windowsProbeRegistryOnce.Do(func() {
		windowsProbeRegistry, _ = agent.NewEntryProbeRegistry(context.Background())
	})
	return windowsProbeRegistry
}

func main() {
	defer clientruntime.CloseProcessWindowsUnderlay()
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
	if len(os.Args) > 1 && os.Args[1] == "--migration-request" {
		if err := exportWindowsMigrationRequest(edition, os.Args[2:]); err != nil {
			showWindowsError("Loom", err)
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

func prepareClientAt(root string, protector clientsecret.Protector, edition clientEdition) (func(context.Context) error, error) {
	if _, err := runtimeProfile(edition); err != nil {
		return nil, err
	}
	if _, err := clientcore.EnsurePreference(filepath.Join(root, "state", "preference.json")); err != nil {
		return nil, err
	}
	state, err := windowsV2Installed(root, protector)
	if err != nil {
		return nil, fmt.Errorf("验证 Windows v2 LKG: %w", err)
	}
	if state != nil {
		return prepareWindowsV2ClientAt(root, protector, edition, state)
	}
	if _, err := os.Lstat(filepath.Join(root, "config", "client.json")); err == nil {
		return nil, errWindowsMigrationRequired
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	return waitForJoinedClient(root, protector, edition), nil
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
	// 每份连接配置读取自己的 CA；运行预检限定机器根和已登记目录形状。
	return filepath.Join(root, "tls", "ca.crt")
}

func preflightClientActivation(ctx context.Context, activation *clientActivation) error {
	return clientruntime.PreflightWindowsRuntime(ctx, activation.Executable, activation.Config,
		activation.RuntimeDir, activation.Profile, activation.CAPath)
}

func runClientActivation(ctx context.Context, activation *clientActivation) error {
	return runWindowsAgentActivation(ctx, activation)
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
				state, stateErr := windowsV2Installed(root, protector)
				if stateErr != nil {
					return fmt.Errorf("load joined Windows v2 state: %w", stateErr)
				}
				if state != nil {
					workload, err := prepareWindowsV2ClientAt(root, protector, edition, state)
					if err != nil {
						return err
					}
					return workload(ctx)
				}

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

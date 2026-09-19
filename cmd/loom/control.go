package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"time"

	"loom/internal/control"
	"loom/internal/localconfig"
	"loom/internal/report"
)

const minimalStateName = "state.json"

func cmdConfig(args []string) error {
	if len(args) == 0 || args[0] != "check" && args[0] != "migrate" {
		return errors.New("用法: loom config <check|migrate> [-env .env]")
	}
	action := args[0]
	fs := flag.NewFlagSet("config "+action, flag.ContinueOnError)
	path := fs.String("env", ".env", "六项部署输入")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("config %s 不接受位置参数", action)
	}
	if action == "migrate" {
		if err := localconfig.Migrate(*path); err != nil {
			return err
		}
		fmt.Println("deployment config migrated to the canonical six-key representation")
		return nil
	}
	config, err := localconfig.Load(*path)
	if err != nil {
		return err
	}
	fmt.Printf("deployment config valid: hosts=%d outputs=%d local=%t provider_secret=present\n",
		len(config.DeployHosts), len(config.PublishOutputs), config.LocalNode != "")
	return nil
}

func cmdControl(args []string) error {
	if len(args) == 0 {
		return errors.New("用法: loom control <import|activate|prepare|serve|inspect|write>")
	}
	switch args[0] {
	case "import":
		return cmdControlImport(args[1:])
	case "serve":
		return cmdControlServe(args[1:])
	case "activate":
		return cmdControlActivate(args[1:])
	case "prepare":
		return cmdControlPrepare(args[1:])
	case "inspect":
		return cmdControlInspect(args[1:])
	case "write":
		return cmdControlWrite(args[1:])
	default:
		return fmt.Errorf("未知 control 子命令 %q", args[0])
	}
}

func cmdControlActivate(args []string) error {
	fs := flag.NewFlagSet("control activate", flag.ContinueOnError)
	stateDir := fs.String("state-dir", "/var/lib/loom-minimal", "控制状态目录")
	memberID := fs.String("member-id", "", "稳定 control 成员 ID")
	networkConfig := fs.String("network-config", "/etc/loom/report/v2/config.json", "既有私有通道配置")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 || *memberID == "" {
		return errors.New("control activate 需要 -member-id")
	}
	private, _, err := loadPrivateChannelConfig(*networkConfig)
	if err != nil {
		return err
	}
	legacyPath := filepath.Join(*stateDir, minimalStateName)
	legacy, err := control.LoadState(legacyPath)
	if err != nil {
		return err
	}
	config, err := control.ActivateLegacy(*stateDir, legacy, *memberID, private.Node, private.Listen)
	if err != nil {
		return err
	}
	if _, err := control.OpenAuthority(*stateDir); err != nil {
		return fmt.Errorf("激活后回读失败: %w", err)
	}
	if err := os.Remove(legacyPath); err != nil {
		return fmt.Errorf("删除已被 genesis Material 取代的恢复缓存: %w", err)
	}
	return json.NewEncoder(os.Stdout).Encode(config.Member())
}

func cmdControlPrepare(args []string) error {
	fs := flag.NewFlagSet("control prepare", flag.ContinueOnError)
	stateDir := fs.String("state-dir", "/var/lib/loom-minimal", "新成员控制状态目录")
	sourceDir := fs.String("source-state-dir", "", "已认证源控制状态目录")
	memberID := fs.String("member-id", "", "稳定 control 成员 ID")
	networkConfig := fs.String("network-config", "/etc/loom/report/v2/config.json", "新成员既有私有通道配置")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 || *sourceDir == "" || *memberID == "" {
		return errors.New("control prepare 缺少 source/member 参数")
	}
	private, _, err := loadPrivateChannelConfig(*networkConfig)
	if err != nil {
		return err
	}
	config, err := control.PrepareMember(*stateDir, *sourceDir, *memberID, private.Node, private.Listen)
	if err != nil {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(config.Member())
}

func cmdControlImport(args []string) error {
	fs := flag.NewFlagSet("control import", flag.ContinueOnError)
	stateDir := fs.String("state-dir", "/var/lib/loom-minimal", "最小控制状态目录")
	sourceDir := fs.String("source-dir", "/var/lib/loom-control", "受保护旧控制状态目录")
	floor := fs.String("release-floor", "/var/lib/loom/release-floor.json", "release anti-rollback floor")
	observation := fs.String("observation", "", "可选的认证 Web 观测快照")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return errors.New("control import 不接受位置参数")
	}
	state, err := control.Import(control.ImportInput{
		ConfigPath: filepath.Join(*sourceDir, "config.json"), CertifiedPath: filepath.Join(*sourceDir, "control-state.json"),
		OperationsPath: filepath.Join(*sourceDir, "operations.json"), BrowserTLSPath: filepath.Join(*sourceDir, "browser-tls.json"),
		ReleaseFloorPath: *floor, ObservationPath: *observation,
	})
	if err != nil {
		return err
	}
	path := filepath.Join(*stateDir, minimalStateName)
	if existing, loadErr := control.LoadState(path); loadErr == nil {
		if !reflect.DeepEqual(existing, state) {
			return errors.New("已存在的最小状态与导入结果不同；拒绝覆盖")
		}
		fmt.Printf("minimal control state already matches: head=%s revision=%d\n", state.Head.Hash, state.Head.Revision)
		return nil
	} else if !errors.Is(loadErr, os.ErrNotExist) {
		return fmt.Errorf("读取已有最小状态: %w", loadErr)
	}
	if err := control.SaveState(path, state); err != nil {
		return err
	}
	fmt.Printf("minimal control state imported: head=%s revision=%d\n", state.Head.Hash, state.Head.Revision)
	return nil
}

func cmdControlServe(args []string) error {
	fs := flag.NewFlagSet("control serve", flag.ContinueOnError)
	stateDir := fs.String("state-dir", "/var/lib/loom-minimal", "最小控制状态目录")
	releaseRoot := fs.String("release-root", "/var/lib/loom/client-dist/releases", "客户端 release 根目录")
	releaseKey := fs.String("release-key", "/etc/loom/trust/platform.pub", "catalog 验签公钥")
	networkConfig := fs.String("network-config", "/etc/loom/report/v2/config.json", "既有私有通道配置")
	adminSocket := fs.String("admin-socket", "/run/loom-control/admin.sock", "本机管理员 Unix socket")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return errors.New("control serve 不接受位置参数")
	}
	private, reportConfig, err := loadPrivateChannelConfig(*networkConfig)
	if err != nil {
		return err
	}
	node, err := control.LoadNodeConfig(*stateDir)
	if err != nil {
		return err
	}
	channel, err := control.OpenPrivateChannel(private, node)
	if err != nil {
		return err
	}
	defer channel.Close()
	runtime, err := control.OpenRuntime(*stateDir, channel)
	if err != nil {
		return err
	}
	defer runtime.Close()
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	reportRuntime, err := report.Start(ctx, reportConfig, func() time.Time { return time.Now() }, os.Stdout)
	if err != nil {
		return err
	}
	reports, err := control.OpenObservationStore(*stateDir)
	if err != nil {
		return err
	}
	err = (&control.Server{Runtime: runtime, Channel: channel, Config: runtime.Config, ReleaseRoot: *releaseRoot,
		ReleaseKey: *releaseKey, AdminSocket: *adminSocket, Reports: reports}).Serve(ctx, reportRuntime.Handler())
	stop()
	if reportErr := reportRuntime.Wait(); err == nil {
		err = reportErr
	}
	return err
}

func loadPrivateChannelConfig(path string) (control.PrivateChannelConfig, *report.Config, error) {
	body, err := os.ReadFile(path)
	if err != nil {
		return control.PrivateChannelConfig{}, nil, err
	}
	reportConfig, err := report.Load(body)
	if err != nil {
		return control.PrivateChannelConfig{}, nil, err
	}
	peers := map[string][]string{}
	for _, neighbor := range reportConfig.Neighbors {
		peers[neighbor.Node] = append(peers[neighbor.Node], neighbor.Addr)
	}
	private := control.PrivateChannelConfig{Node: reportConfig.Node, Listen: append([]string(nil), reportConfig.Listen...), Peers: peers}
	if err := private.Validate(); err != nil {
		return control.PrivateChannelConfig{}, nil, err
	}
	return private, reportConfig, nil
}

func cmdControlInspect(args []string) error {
	fs := flag.NewFlagSet("control inspect", flag.ContinueOnError)
	stateDir := fs.String("state-dir", "/var/lib/loom-minimal", "最小控制状态目录")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return errors.New("control inspect 不接受位置参数")
	}
	config, err := control.LoadNodeConfig(*stateDir)
	if err != nil {
		return err
	}
	authority, err := control.OpenAuthority(*stateDir)
	if err != nil {
		return err
	}
	consensus, projection, certified := authority.Snapshot()
	return json.NewEncoder(os.Stdout).Encode(struct {
		Head          control.GovernanceHead `json:"certified_head"`
		Floor         uint64                 `json:"release_floor_generation"`
		V2Latch       bool                   `json:"v2_latch"`
		Members       int                    `json:"members"`
		Devices       int                    `json:"devices"`
		Endpoints     int                    `json:"endpoint_generations"`
		Enrollments   int                    `json:"enrollments"`
		DeviceViews   int                    `json:"device_views"`
		Services      int                    `json:"services"`
		AdminBindings int                    `json:"admin_bindings"`
		Entries       int                    `json:"consensus_entries"`
	}{certified.Head, config.Recovery.ReleaseFloor.Generation, config.Recovery.V2Latch,
		len(controlMembers(projection.Config)), len(certified.Projection.Web.Devices), len(certified.Projection.EndpointGenerations),
		len(certified.Projection.Enrollments), len(certified.Projection.DeviceAuthorizations), len(certified.Projection.Web.Services),
		len(config.AdminCertDER), len(consensus.Entries)})
}

func controlMembers(config control.ControlConfig) []control.Member {
	if config.Mode == "stable" {
		return config.Members
	}
	return config.New
}

func cmdControlWrite(args []string) error {
	fs := flag.NewFlagSet("control write", flag.ContinueOnError)
	endpoint := fs.String("url", "", "私有 control HTTPS origin")
	socket := fs.String("socket", "", "本机管理员 Unix socket")
	certPath := fs.String("cert", "", "管理员客户端证书")
	keyPath := fs.String("key", "", "管理员客户端私钥")
	caPath := fs.String("ca", "", "control TLS 根证书")
	kind := fs.String("kind", "", "service.put、members.replace、endpoint.put、enrollment.create、enrollment.approve、device.put 或 device.revoke")
	payloadPath := fs.String("payload", "", "operation payload JSON")
	requestID := fs.String("request-id", "", "稳定幂等请求 ID")
	baseHead := fs.String("base-head", "", "读取到的 certified head")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 || *kind == "" || *payloadPath == "" || *requestID == "" || *baseHead == "" {
		return errors.New("control write 缺少 kind/payload/request-id/base-head 参数")
	}
	local := *socket != ""
	remote := *endpoint != "" && *certPath != "" && *keyPath != "" && *caPath != ""
	if local == remote || local && (*endpoint != "" || *certPath != "" || *keyPath != "" || *caPath != "") {
		return errors.New("control write 必须选择 socket，或完整的 url/cert/key/ca")
	}
	payload, err := os.ReadFile(*payloadPath)
	if err != nil {
		return err
	}
	var raw json.RawMessage = payload
	body, err := json.Marshal(struct {
		Kind      string          `json:"kind"`
		Payload   json.RawMessage `json:"payload"`
		RequestID string          `json:"request_id"`
		BaseHead  string          `json:"base_head"`
	}{*kind, raw, *requestID, *baseHead})
	if err != nil {
		return err
	}
	var client *http.Client
	origin := strings.TrimRight(*endpoint, "/")
	if local {
		origin = "http://loom.local"
		client = &http.Client{Timeout: 45 * time.Second, Transport: &http.Transport{Proxy: nil, DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", *socket)
		}}}
	} else {
		certificate, loadErr := tls.LoadX509KeyPair(*certPath, *keyPath)
		if loadErr != nil {
			return loadErr
		}
		caBody, readErr := os.ReadFile(*caPath)
		if readErr != nil {
			return readErr
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caBody) {
			return errors.New("control CA 无有效证书")
		}
		client = &http.Client{Timeout: 45 * time.Second, Transport: &http.Transport{Proxy: nil, TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{certificate}, RootCAs: pool}}}
	}
	request, err := http.NewRequest(http.MethodPost, origin+"/api/control/operations", bytes.NewReader(body))
	if err != nil {
		return err
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Origin", origin)
	response, err := client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	responseBody, err := io.ReadAll(io.LimitReader(response.Body, 4<<20))
	if err != nil {
		return err
	}
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("control write: %s: %s", response.Status, strings.TrimSpace(string(responseBody)))
	}
	_, err = os.Stdout.Write(responseBody)
	return err
}

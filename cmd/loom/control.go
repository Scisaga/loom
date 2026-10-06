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
	"loom/internal/clientrelease"
	"loom/internal/control"
	"loom/internal/deployhost"
	"loom/internal/localconfig"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

func cmdConfig(args []string) error {
	if len(args) == 0 || args[0] != "check" {
		return errors.New("用法: loom config check [-env .env]")
	}
	fs := flag.NewFlagSet("config check", flag.ContinueOnError)
	path := fs.String("env", ".env", "引用唯一部署 YAML 的 dotenv 文件")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return errors.New("config check 不接受位置参数")
	}
	config, err := localconfig.Load(*path)
	if err != nil {
		return err
	}
	mappings := 0
	for _, node := range config.Nodes {
		mappings += len(node.Ingress)
	}
	fmt.Printf("deployment config valid: hosts=%d nodes=%d ingress=%d outputs=%d local=%t provider_secret_present=%t\n",
		len(config.DeployHosts), len(config.Nodes), mappings, len(config.PublishOutputs), config.LocalNode != "", config.GandiPATToken != "")
	return nil
}

func cmdControl(args []string) error {
	if len(args) == 0 {
		return errors.New("用法: loom control <init|serve|relay|edge|inspect|endpoint-inputs|admin|write>")
	}
	switch args[0] {
	case "admin":
		return cmdControlAdmin(args[1:])
	case "init":
		return cmdControlInit(args[1:])
	case "serve":
		return cmdControlServe(args[1:])
	case "relay":
		return cmdControlRelay(args[1:])
	case "edge":
		return cmdControlEdge(args[1:])
	case "inspect":
		return cmdControlInspect(args[1:])
	case "endpoint-inputs":
		return cmdControlEndpointInputs(args[1:])
	case "write":
		return cmdControlWrite(args[1:])
	default:
		return fmt.Errorf("未知 control 子命令 %q", args[0])
	}
}
func readCanonicalControlInput(path string, value any) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
		return errors.New("control input must be an owner-only regular file")
	}
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()
	current, err := file.Stat()
	if err != nil || !os.SameFile(info, current) {
		return errors.New("control input changed while opening")
	}
	body, err := io.ReadAll(io.LimitReader(file, (8<<20)+1))
	if err != nil {
		return err
	}
	return control.DecodeCanonical(body, value, control.ContractDecodeLimits{MaxBytes: 8 << 20, MaxDepth: 128, MaxItems: 1 << 20})
}
func cmdControlInit(args []string) error {
	fs := flag.NewFlagSet("control init", flag.ContinueOnError)
	root := fs.String("state-dir", "", "新空权威目录（绝对路径）")
	nodePath := fs.String("node-config", "", "受保护本机身份和文件引用")
	genesisPath := fs.String("genesis", "", "已签名 schema 3 genesis Material")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 || *root == "" || *nodePath == "" || *genesisPath == "" {
		return errors.New("control init 需要 state-dir、node-config、genesis")
	}
	var config control.NodeConfig
	var genesis control.Material
	if err := readCanonicalControlInput(*nodePath, &config); err != nil {
		return err
	}
	if err := readCanonicalControlInput(*genesisPath, &genesis); err != nil {
		return err
	}
	authority, err := control.InitializeAuthority(*root, config, genesis)
	if err != nil {
		return err
	}
	snapshot := authority.Snapshot()
	return json.NewEncoder(os.Stdout).Encode(map[string]any{"schema": 3, "network_id": snapshot.NetworkID, "genesis_id": config.GenesisID, "control_config_id": snapshot.ControlConfigID, "members": len(snapshot.Config.Members)})
}
func cmdControlServe(args []string) (retErr error) {
	fs := flag.NewFlagSet("control serve", flag.ContinueOnError)
	root := fs.String("state-dir", "/var/lib/loom-control", "现行权威目录")
	privatePath := fs.String("private-inputs", "", "可选的受保护私有监听/成员拨号输入")
	socket := fs.String("admin-socket", "", "本机管理 Unix socket；默认由 state-dir 派生")
	releaseRoot := fs.String("release-root", "", "独立签名 release store 的本机只读目录")
	releaseKey := fs.String("release-pubkey", "", "带外安装的发布验签公钥；不从 catalog 取得")
	deploymentEnv := fs.String("deployment-env", "", "可选 SSH 执行器的既有 .env 引用；严格加载同一部署 YAML")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return errors.New("control serve 不接受位置参数")
	}
	var releases control.ReleaseSource
	var ssh control.SSHExecutor
	if *deploymentEnv != "" {
		var err error
		ssh, err = deployhost.New(*deploymentEnv)
		if err != nil {
			return err
		}
	}
	if (*releaseRoot == "") != (*releaseKey == "") {
		return errors.New("release-root 与 release-pubkey 必须同时指定")
	}
	if *releaseRoot != "" {
		key, err := control.ReadReleasePublicKey(*releaseKey)
		if err != nil {
			return err
		}
		releases, err = clientrelease.New(*releaseRoot, key)
		if err != nil {
			return err
		}
	}
	node, err := control.LoadNodeConfig(*root)
	if err != nil {
		return err
	}
	var channel *control.PrivateChannel
	if *privatePath != "" {
		private, err := control.LoadPrivateChannelConfig(*privatePath)
		if err != nil {
			return err
		}
		channel, err = control.OpenPrivateChannel(private, node)
		if err != nil {
			return err
		}
		defer func() { retErr = errors.Join(retErr, channel.Close()) }()
	}
	runtime, err := control.OpenRuntime(*root, channel)
	if err != nil {
		return err
	}
	defer func() { retErr = errors.Join(retErr, runtime.Close()) }()
	admin := *socket
	if admin == "" {
		admin = filepath.Join(*root, "admin.sock")
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	return (&control.Server{Runtime: runtime, Channel: channel, Config: node, AdminSocket: admin, Releases: releases, SSH: ssh}).Serve(ctx)
}
func cmdControlRelay(args []string) (retErr error) {
	fs := flag.NewFlagSet("control relay", flag.ContinueOnError)
	root := fs.String("state-dir", "/var/lib/loom-control-relay", "受保护 transport relay 身份目录")
	inputs := fs.String("private-inputs", "", "受保护私有监听/拨号输入")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 || *inputs == "" {
		return errors.New("control relay 需要 private-inputs")
	}
	private, err := control.LoadPrivateChannelConfig(*inputs)
	if err != nil {
		return err
	}
	identity, err := control.LoadRelayIdentity(*root, private.Listen)
	if err != nil {
		return err
	}
	channel, err := control.OpenPrivateRelay(private, identity)
	if err != nil {
		return err
	}
	defer func() { retErr = errors.Join(retErr, channel.Close()) }()
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	<-ctx.Done()
	return nil
}
func cmdControlEdge(args []string) (retErr error) {
	fs := flag.NewFlagSet("control edge", flag.ContinueOnError)
	listen := fs.String("listen", "", "操作者提供的本机 TCP 监听地址")
	target := fs.String("target", "", "既有 control 私有 TCP 目标地址")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 || *listen == "" || *target == "" {
		return errors.New("control edge 需要 listen 和 target")
	}
	edge, err := control.OpenEndpointEdge(*listen, *target)
	if err != nil {
		return err
	}
	defer func() { retErr = errors.Join(retErr, edge.Close()) }()
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	<-ctx.Done()
	return nil
}
func cmdControlEndpointInputs(args []string) error {
	fs := flag.NewFlagSet("control endpoint-inputs", flag.ContinueOnError)
	root := fs.String("state-dir", "/var/lib/loom-control", "现行权威目录")
	endpointPath := fs.String("endpoint", "", "完整规范 EndpointGeneration")
	inputsPath := fs.String("inputs", "", "本机 listen/certificate_file/key_file 规范值")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 || *endpointPath == "" || *inputsPath == "" {
		return errors.New("endpoint-inputs 需要 endpoint 和 inputs")
	}
	var endpoint control.EndpointGeneration
	var inputs control.EndpointLocalInputs
	if err := readCanonicalControlInput(*endpointPath, &endpoint); err != nil {
		return err
	}
	if err := readCanonicalControlInput(*inputsPath, &inputs); err != nil {
		return err
	}
	if err := control.InstallEndpointInputs(*root, endpoint, inputs); err != nil {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(map[string]any{"schema": 3, "endpoint_id": endpoint.ID, "generation": endpoint.Generation, "inputs_installed": true})
}
func cmdControlInspect(args []string) error {
	fs := flag.NewFlagSet("control inspect", flag.ContinueOnError)
	root := fs.String("state-dir", "/var/lib/loom-control", "现行权威目录")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return errors.New("control inspect 不接受位置参数")
	}
	node, err := control.LoadNodeConfig(*root)
	if err != nil {
		return err
	}
	authority, err := control.OpenAuthority(*root)
	if err != nil {
		return err
	}
	p := authority.Snapshot()
	// Never return the complete Projection: device authorizations contain RuntimeKey.
	return json.NewEncoder(os.Stdout).Encode(map[string]any{"schema": 3, "network_id": p.NetworkID, "genesis_id": node.GenesisID, "control_config_id": p.ControlConfigID, "members": p.Config.Members, "fact_frontier": p.Frontier, "targets": p.Targets, "pending_material_ids": p.PendingMaterialIDs, "invalid_materials": p.InvalidMaterials, "devices": len(p.DeviceAuthorizations), "endpoints": p.EndpointGenerations, "services": p.NetworkIntent.Services, "policies": p.NetworkIntent.Policies, "resources": p.NetworkIntent.Resources, "links": p.NetworkIntent.Links, "business_probe_targets": p.NetworkIntent.BusinessProbeTargets, "expected_components": p.NetworkIntent.ExpectedComponents})
}

func cmdControlWrite(args []string) error {
	fs := flag.NewFlagSet("control write", flag.ContinueOnError)
	endpoint := fs.String("url", "", "私有 control HTTPS origin")
	socket := fs.String("socket", "", "本机管理员 Unix socket")
	certPath := fs.String("cert", "", "管理员客户端证书")
	keyPath := fs.String("key", "", "管理员客户端私钥")
	caPath := fs.String("ca", "", "control TLS 根证书")
	requestPath := fs.String("request", "", "schema 3 规范 operation JSON 文件")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 || *requestPath == "" {
		return errors.New("control write 需要 request 文件")
	}
	local := *socket != ""
	remote := *endpoint != "" && *certPath != "" && *keyPath != "" && *caPath != ""
	if local == remote || local && (*endpoint != "" || *certPath != "" || *keyPath != "" || *caPath != "") {
		return errors.New("control write 必须选择 socket，或完整的 url/cert/key/ca")
	}
	body, err := os.ReadFile(*requestPath)
	if err != nil {
		return err
	}
	if _, err := control.DecodeOperation(body); err != nil {
		return fmt.Errorf("invalid canonical operation: %w", err)
	}
	var client *http.Client
	origin := strings.TrimRight(*endpoint, "/")
	if local {
		origin = "http://loom.local"
		client = &http.Client{Timeout: 2 * time.Minute, Transport: &http.Transport{Proxy: nil, DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
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
	responseBody, err := io.ReadAll(io.LimitReader(response.Body, (8<<20)+1))
	if err != nil {
		return err
	}
	if len(responseBody) > 8<<20 {
		return errors.New("control response exceeds reader resource boundary")
	}
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("control write: %s: %s", response.Status, strings.TrimSpace(string(responseBody)))
	}
	_, err = os.Stdout.Write(responseBody)
	return err
}

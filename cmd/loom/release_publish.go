package main

import (
	"context"
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
	"strings"
	"time"
	"unicode"

	"loom/internal/clientrelease"
	"loom/internal/control"
	"loom/internal/deployhost"
	"loom/internal/deviceclient"
	"loom/internal/localconfig"
	"loom/internal/releasedeploy"
)

// Target reads the actual installed identity and the entire signed current.
// Missing files below an existing pointer are never treated as an empty target.
func cmdReleaseTarget(args []string) error {
	fs := flag.NewFlagSet("release target", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	root := fs.String("root", "", "YAML 选定的分发根目录")
	pub := fs.String("pubkey", "", "独立管理通道固定的发布公钥")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 || *root == "" || *pub == "" {
		return errors.New("release target 需要 root 和 pubkey")
	}
	key, err := control.ReadReleasePublicKey(*pub)
	if err != nil {
		return err
	}
	device, err := deviceclient.Load(defaultDeviceState)
	if err != nil {
		return err
	}
	identity, err := device.IdentityReadback()
	if err != nil {
		return err
	}
	absolute, err := filepath.Abs(*root)
	if err != nil {
		return err
	}
	result := releasedeploy.TargetReadback{Identity: identity}
	if _, err = os.Lstat(filepath.Join(absolute, "current.json")); err == nil {
		store, err := clientrelease.New(absolute, key)
		if err != nil {
			return err
		}
		set, err := store.Read()
		if err != nil {
			return err
		}
		result.CatalogDigest, result.Generation = set.ID, set.Catalog.Generation
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(result)
}

func cmdReleasePublish(args []string) error {
	fs := flag.NewFlagSet("release publish", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	env := fs.String("env", ".env", "本机部署 YAML 引用")
	source := fs.String("source", "", "本次已经签署的审查目录")
	catalog := fs.String("catalog", "", "精确签名 catalog 摘要")
	pub := fs.String("pubkey", "", "独立固定的发布公钥")
	socket := fs.String("control-socket", "", "私有 control 管理 Unix socket")
	reason := fs.String("reason", "", "本次显式发布理由")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 || *source == "" || *pub == "" || *socket == "" || control.ValidateDigest(*catalog) != nil || strings.TrimSpace(*reason) == "" || len(*reason) > 512 || strings.ContainsFunc(*reason, unicode.IsControl) {
		return errors.New("release publish 需要 source、catalog、pubkey、control-socket 和 reason")
	}
	config, err := localconfig.Load(*env)
	if err != nil {
		return err
	}
	key, err := control.ReadReleasePublicKey(*pub)
	if err != nil {
		return err
	}
	sourcePath, err := filepath.Abs(*source)
	if err != nil {
		return err
	}
	executor, err := deployhost.New(*env)
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	transport := &http.Transport{Proxy: nil, DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", *socket)
	}}
	defer transport.CloseIdleConnections()
	admin := &http.Client{Timeout: 30 * time.Second, Transport: transport}
	read := func(ctx context.Context) (control.ReleaseDeploymentInputs, error) {
		var value control.ReleaseDeploymentInputs
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://loom.local/api/control/releases/inputs", nil)
		if err != nil {
			return value, err
		}
		response, err := admin.Do(request)
		if err != nil {
			return value, errors.New("private deployment authorization readback unavailable")
		}
		defer response.Body.Close()
		if response.StatusCode != http.StatusOK {
			return value, errors.New("private deployment authorization was refused")
		}
		body, err := io.ReadAll(io.LimitReader(response.Body, (8<<20)+1))
		if err != nil || len(body) > 8<<20 {
			return value, errors.New("private deployment inputs exceed readback boundary")
		}
		err = json.Unmarshal(body, &value)
		return value, err
	}
	publicClient := releasePublicHTTPClient(4 * time.Minute)
	defer publicClient.CloseIdleConnections()
	encoder := json.NewEncoder(os.Stdout)
	options := releasedeploy.Options{Config: config, ReloadConfig: func() (localconfig.Config, error) { return localconfig.Load(*env) }, Inputs: read, Transport: executor,
		Source: sourcePath, Catalog: *catalog, PublicKey: key, HTTP: publicClient, Observe: func(value releasedeploy.Result) { encoder.Encode(value) }}
	if err = releasedeploy.Publish(ctx, options); err != nil {
		return fmt.Errorf("publication incomplete: %w", err)
	}
	return nil
}

// Large signed artifacts may take longer than the network inactivity limit.
// Bound each blocked read while allowing a progressing response to finish;
// request cancellation still closes the transport and stops verification.
func releasePublicHTTPClient(idle time.Duration) *http.Client {
	dialer := &net.Dialer{Timeout: 30 * time.Second}
	return &http.Client{Transport: &http.Transport{
		Proxy: nil, DisableCompression: true,
		TLSHandshakeTimeout: 30 * time.Second, ResponseHeaderTimeout: 60 * time.Second,
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			conn, err := dialer.DialContext(ctx, network, address)
			if err != nil {
				return nil, err
			}
			return &releaseDownloadConn{Conn: conn, idle: idle}, nil
		},
	}}
}

type releaseDownloadConn struct {
	net.Conn
	idle time.Duration
}

func (c *releaseDownloadConn) Read(p []byte) (int, error) {
	if err := c.Conn.SetReadDeadline(time.Now().Add(c.idle)); err != nil {
		return 0, err
	}
	return c.Conn.Read(p)
}

package main

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"loom/internal/bootstrapaccess"
	"loom/internal/certmanager"
	"loom/internal/wire"
)

type controlPrepareBootstrapInputV1 struct {
	Schema      int                                               `json:"schema"`
	OperationID string                                            `json:"operation_id"`
	ValidFrom   string                                            `json:"valid_from"`
	ValidUntil  string                                            `json:"valid_until"`
	Listeners   []bootstrapaccess.InitialBootstrapListenerInputV1 `json:"listeners"`
}

func cmdControlPrepareBootstrap(args []string) error {
	flags := flag.NewFlagSet("control prepare-bootstrap", flag.ContinueOnError)
	admin := flags.String("admin-dir", "", "原管理员交付目录")
	input := flags.String("input", "", "现有证书和明确端口资源输入")
	out := flags.String("out", "", "私有安装计划输出")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 || *admin == "" || *input == "" || !filepath.IsAbs(*out) {
		return errors.New("prepare-bootstrap 必须指定 admin-dir、input 与 out 绝对路径")
	}
	parent, err := os.Lstat(filepath.Dir(*out))
	if err != nil || !parent.IsDir() || parent.Mode().Perm() != 0700 || parent.Mode()&os.ModeSymlink != 0 {
		return errors.New("bootstrap 计划输出须位于已有的 0700 实体目录")
	}
	var request controlPrepareBootstrapInputV1
	body, err := readOwnerOnlyFile(*input, 8<<20)
	if err != nil {
		return err
	}
	if _, err := wire.DecodeStrict(body, 8<<20, &request); err != nil {
		return err
	}
	endpoint, client, err := loadControlAdminClient(*admin)
	if err != nil {
		return err
	}
	defer client.CloseIdleConnections()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	status, err := fetchControlStatus(ctx, endpoint, client)
	if err != nil {
		return err
	}
	plan, err := prepareInitialBootstrapPlan(request, status, nil, time.Now().UTC())
	if err != nil {
		return err
	}
	var prior bootstrapaccess.InitialBootstrapInstallationV1
	if err := readCanonicalFile(*out, 16<<20, &prior); err == nil {
		if !wire.EqualCanonical(prior, plan) {
			return errors.New("bootstrap 输出已绑定另一输入或原 Head 已改变")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	} else if err := writeCanonicalAtomic(*out, plan, 0600); err != nil {
		return err
	}
	fmt.Println("✓ 已按原认证 Head 与现有证书生成私有安装计划；未签证、未改 DNS，尚未 advertise")
	return nil
}

func prepareInitialBootstrapPlan(request controlPrepareBootstrapInputV1, status controlStatusResponseV1, roots *x509.CertPool, now time.Time) (bootstrapaccess.InitialBootstrapInstallationV1, error) {
	var empty bootstrapaccess.InitialBootstrapInstallationV1
	if request.Schema != 1 || status.Schema != 1 {
		return empty, errors.New("bootstrap 准备请求或原控制状态无效")
	}
	for _, listener := range request.Listeners {
		if err := certmanager.VerifyExistingPublicCertificate(listener.Certificate, roots, now); err != nil {
			return empty, err
		}
	}
	var qc wire.StableHeadReplicationQCV1
	if err := json.Unmarshal(status.ConfigQC, &qc); err != nil {
		return empty, err
	}
	return bootstrapaccess.BuildInitialBootstrapInstallation(bootstrapaccess.InitialBootstrapInstallationInputV1{Schema: 1, ClusterID: status.ClusterID,
		OperationID: request.OperationID, Parent: status.Head, ParentQC: qc, ControlSet: status.ControlSet, ValidFrom: request.ValidFrom, ValidUntil: request.ValidUntil, Listeners: request.Listeners})
}

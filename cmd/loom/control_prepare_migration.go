package main

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"loom/internal/wire"
)

// 这里只准备原网络将认证的真实软件材料。它不打开 Raft storage、不竞选，
// 不更新 Head/ACL，也不将未认证 listener 或 Device CA 发布到网络。
type controlPreparedMigrationMaterialsV1 struct {
	Schema          int                                  `json:"schema"`
	ClusterID       string                               `json:"cluster_id"`
	DeviceID        string                               `json:"device_id"`
	RequestID       string                               `json:"request_id"`
	DeviceProfile   wire.DeviceCertificateProfileStateV1 `json:"device_profile"`
	PrivateServices controlPrivateMaterialsV1            `json:"private_services"`
	ArtifactPolicy  wire.ArtifactAvailabilityPolicyV1    `json:"artifact_policy"`
}

func cmdControlPrepareMigrationMaterials(args []string) error {
	flags := flag.NewFlagSet("control prepare-migration-materials", flag.ContinueOnError)
	dir := flags.String("state-dir", "/var/lib/loom-control", "原控制状态目录")
	requestID := flags.String("request-id", "", "固定的迁移准备请求 ID")
	enroll := flags.Int64("enroll-port", 0, "私有 Enrollment TCP 端口")
	config := flags.Int64("config-port", 0, "私有 Device 配置 TCP 端口")
	report := flags.Int64("report-port", 0, "私有 Device 报告 TCP 端口")
	out := flags.String("out", "", "准备结果文件，必须位于受保护目录")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 || *requestID == "" || len(*requestID) > 128 || *out == "" {
		return errors.New("prepare-migration-materials 必须指定 request-id、三个独立端口和 out")
	}
	parent, err := os.Lstat(filepath.Dir(*out))
	if err != nil || !parent.IsDir() || parent.Mode().Perm() != 0o700 || parent.Mode()&os.ModeSymlink != 0 {
		return errors.New("迁移材料输出须位于已有的 0700 实体目录")
	}
	prepared, err := prepareControlMigrationMaterials(*dir, *requestID,
		map[string]int64{"enroll": *enroll, "device_config": *config, "device_report": *report}, time.Now().UTC().Truncate(time.Second))
	if err != nil {
		return err
	}
	var existing controlPreparedMigrationMaterialsV1
	if err := readCanonicalFile(*out, 8<<20, &existing); err == nil {
		if !wire.EqualCanonical(existing, prepared) {
			return errors.New("迁移材料输出已有不同内容，不能覆盖")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	} else if err := writeCanonicalAtomic(*out, prepared, 0o600); err != nil {
		return err
	}
	fmt.Println("✓ 原网络的 Device CA、独立私有 TLS 与封装证据已准备；尚未认证激活")
	return nil
}

func prepareControlMigrationMaterials(dir, requestID string, ports map[string]int64, now time.Time) (controlPreparedMigrationMaterialsV1, error) {
	var result controlPreparedMigrationMaterialsV1
	if requestID == "" || len(requestID) > 128 || now.IsZero() || now != now.UTC().Truncate(time.Second) {
		return result, errors.New("迁移准备缺固定请求 ID 或规范时间")
	}
	unlock, err := lockControlState(dir)
	if err != nil {
		return result, err
	}
	defer unlock()
	var config controlDiskConfigV1
	var secrets controlDiskSecretsV1
	if err := readCanonicalFile(filepath.Join(dir, controlConfigName), 8<<20, &config); err != nil {
		return result, err
	}
	if err := readCanonicalFile(filepath.Join(dir, controlSecretsName), 8<<20, &secrets); err != nil {
		return result, err
	}
	if config.Schema != 1 || secrets.Schema != 1 || config.ClusterID == "" || config.DeviceID == "" ||
		config.ControlService.Role != "control_api" || config.ControlService.OverlayIP != config.OverlayIP ||
		config.ControlService.Port != config.ControlPort {
		return result, errors.New("迁移准备缺完整原控制配置")
	}
	if err := wire.ValidatePrivateControlService(&config.ControlService); err != nil {
		return result, err
	}
	certificate, err := tls.X509KeyPair([]byte(secrets.ControlTLSCertificate), []byte(secrets.ControlTLSPrivateKey))
	if err != nil || len(certificate.Certificate) != 2 {
		return result, errors.New("迁移准备缺原 control 完整 TLS 链与匹配私钥")
	}
	defer clearPrivateRuntimeCertificates(map[string]tls.Certificate{"control": certificate})
	leaf, err := x509.ParseCertificate(certificate.Certificate[0])
	if err != nil || !containsControlValue(config.ControlService.SPKIPins, fmt.Sprintf("sha256:%x", sha256.Sum256(leaf.RawSubjectPublicKeyInfo))) {
		return result, errors.New("原 control TLS 不属于已保存的服务 pin")
	}
	runtime := &controlRuntime{dir: dir, config: config, controlTLS: certificate, now: func() time.Time { return now }}
	material, err := openControlSoftwareMaterial(dir, config.DeviceID, true)
	if err != nil {
		return result, err
	}
	defer material.Close()
	profile, err := material.prepareDeviceCA(config.ClusterID, requestID, now)
	if err != nil {
		return result, err
	}
	services, err := runtime.preparePrivateServiceMaterials(requestID, profile.ProfileID, ports, now)
	if err != nil {
		return result, err
	}
	policy, err := material.availabilityPolicy(config.ClusterID)
	if err != nil {
		return result, err
	}
	return controlPreparedMigrationMaterialsV1{Schema: 1, ClusterID: config.ClusterID, DeviceID: config.DeviceID,
		RequestID: requestID, DeviceProfile: profile, PrivateServices: services, ArtifactPolicy: policy}, nil
}

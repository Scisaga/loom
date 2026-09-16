package main

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"path/filepath"
	"time"

	"loom/internal/controlplane"
	"loom/internal/observation"
	"loom/internal/wire"
)

var controlDeviceReportSchemas = wire.DeviceReportSchemaRegistry{"health": 1, "node-health": 1}

func verifyControlDeviceReportPayload(kind string, schema int64, payload []byte) error {
	if kind == "node-health" {
		_, err := wire.DecodeDeviceNodeHealthPayload(kind, schema, payload)
		return err
	}
	_, err := wire.DecodeDeviceHealthPayload(kind, schema, payload)
	return err
}

func (runtime *controlRuntime) openDeviceReportSink() (*controlplane.DeviceReportStore, controlplane.DeviceReportCommitter, error) {
	store, err := controlplane.OpenDeviceReportStore(filepath.Join(runtime.dir, "device-reports.json"), controlDeviceReportSchemas)
	if err != nil {
		return nil, nil, err
	}
	commit := func(ctx context.Context, report controlplane.VerifiedDeviceReportV2) error {
		runtime.mu.Lock()
		defer runtime.mu.Unlock()
		application, err := runtime.certifiedApplicationLocked()
		if err != nil {
			return err
		}
		var profiles []string
		for _, service := range application.Services {
			if service.Role == "device_report" {
				profiles = service.AuthorizedSubjectProfiles
			}
		}
		reader := func(_ context.Context, hash string) (controlplane.DeviceIdentityAuthorityV1, error) {
			return runtime.readDeviceIdentityLocked(hash)
		}
		if err := controlplane.RevalidateDeviceReportAuthority(ctx, report, profiles, reader, runtime.now().UTC()); err != nil {
			return err
		}
		if report.Body().Kind == "node-health" {
			identity, err := runtime.readDeviceIdentityLocked(report.CertificateHash())
			if err != nil {
				return err
			}
			generated, err := wire.ParseTimeZ(report.Body().GeneratedAt)
			if err != nil {
				return err
			}
			if _, err := runtime.verifyNodeReportObservation(report.Payload(), identity, generated); err != nil {
				return err
			}
		}
		return store.Commit(ctx, report)
	}
	return store, commit, nil
}

func (runtime *controlRuntime) verifyNodeReportObservation(payload []byte, identity controlplane.DeviceIdentityAuthorityV1, now time.Time) (*observation.Observation, error) {
	decoded, err := wire.DecodeDeviceNodeHealthPayload("node-health", 1, payload)
	if err != nil {
		return nil, err
	}
	own := &decoded.Observation
	active := identity.CurrentDeviceView.Payload.Active
	if identity.Record.IdentityStatus != "active" || active == nil || !containsControlValue(active.Responsibilities.Values, "forward") || own.Node != identity.Record.DeviceID {
		return nil, errors.New("[节点报告] 原观测不属于当前活动 forward 身份")
	}
	application, err := runtime.certifiedApplicationLocked()
	if err != nil || application == nil || application.ObservationCAPEM == "" {
		return nil, errors.Join(errors.New("[节点报告] 缺认证迁移的原观测 CA"), err)
	}
	ca := []byte(application.ObservationCAPEM)
	trusted, err := observation.VerifyObservationAtLeast(own, ca, now, 10*time.Minute, 5)
	if err != nil || !trusted.MeasurementsVerified {
		return nil, errors.Join(errors.New("[节点报告] 原测量签名无效或已过期"), err)
	}
	if err := observation.VerifyAttachments(own, ca, now, 10*time.Minute); err != nil {
		return nil, err
	}
	block, _ := pem.Decode([]byte(own.Attest.Cert))
	if block == nil {
		return nil, errors.New("[节点报告] 缺原观测证书")
	}
	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, err
	}
	hash, err := wire.HashBytes(wire.DomainEnrollmentIdentitySPKI, certificate.RawSubjectPublicKeyInfo)
	if err != nil || hash != active.IdentitySPKIHash {
		return nil, errors.New("[节点报告] 原测量签名与 v2 报告身份不是同一密钥")
	}
	return own, nil
}

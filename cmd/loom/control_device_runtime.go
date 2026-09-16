package main

import (
	"crypto"
	"crypto/tls"
	"errors"

	"loom/internal/controlplane"
)

// Device API 与管理员 API 使用同一份已认证日志，每次请求重新读取身份和
// 当前配置。只有认证迁移后才存在这些服务；本机材料不能自行授权 listener。
func (runtime *controlRuntime) newDeviceRuntime() (*controlplane.PrivateRuntime, func(), error) {
	options, closeKeys, err := runtime.deviceRuntimeOptions()
	if err != nil || options == nil {
		return nil, closeKeys, err
	}
	deviceRuntime, err := controlplane.NewPrivateDeviceRuntime(*options)
	if err != nil {
		closeKeys()
		return nil, func() {}, errors.Join(errors.New("私有 Device 服务初始化失败"), err)
	}
	return deviceRuntime, closeKeys, nil
}

func (runtime *controlRuntime) deviceRuntimeOptions() (*controlplane.PrivateRuntimeOptions, func(), error) {
	runtime.mu.Lock()
	application, err := runtime.applicationBefore(len(runtime.journal.Records))
	if err == nil && application != nil {
		application, err = runtime.certifiedApplicationLocked()
	}
	runtime.mu.Unlock()
	if err != nil || application == nil {
		return nil, func() {}, err
	}
	certificates, err := runtime.loadPrivateServiceCertificates(application)
	if err != nil {
		return nil, func() {}, err
	}
	closeKeys := func() { clearPrivateRuntimeCertificates(certificates) }
	_, commit, err := runtime.openDeviceReportSink()
	if err != nil {
		closeKeys()
		return nil, func() {}, err
	}
	return &controlplane.PrivateRuntimeOptions{
		Services: application.Services, Certificates: certificates,
		Identities: runtime.readDeviceIdentity, VerifyReport: verifyControlDeviceReportPayload,
		CommitReport: commit, Observations: runtime.readDeviceReportObservations,
		ReportSchemas: controlDeviceReportSchemas, Now: runtime.now,
	}, closeKeys, nil
}

func clearPrivateRuntimeCertificates(certificates map[string]tls.Certificate) {
	for _, certificate := range certificates {
		if signer, ok := certificate.PrivateKey.(crypto.Signer); ok {
			clearControlSigner(signer)
		}
	}
}

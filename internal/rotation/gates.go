package rotation

import (
	"errors"
	"time"

	"loom/internal/wire"
)

const DomainGateEvidenceReport = "loom-rotation-gate-evidence-report-v1"

type GateEvidenceV1 struct {
	Component         string `json:"component"`
	Outcome           string `json:"outcome"`
	ArtifactHash      string `json:"artifact_hash"`
	CertifiedHeadHash string `json:"certified_head_hash"`
	ObservedAt        string `json:"observed_at"`
}

// GateEvidenceReportV1 是自动化只能追加、不能手填布尔值的 gate 输入。
// 只登记当前实际部署的 Linux/Android；未部署平台不能形成虚假门禁。
type GateEvidenceReportV1 struct {
	Schema      int              `json:"schema"`
	ClusterID   string           `json:"cluster_id"`
	EvaluatedAt string           `json:"evaluated_at"`
	Evidence    []GateEvidenceV1 `json:"evidence"`
}

// GateStatus 是机器可读的两道门禁。每一项都必须由 evidence 派生，不能由调用方
// 直接声明 Gate 已打开。
type GateStatus struct {
	Schema                 int  `json:"schema"`
	ServerOverlapGuard     bool `json:"server_overlap_guard"`
	LinuxV2Reader          bool `json:"linux_v2_reader"`
	AndroidV2Reader        bool `json:"android_v2_reader"`
	LinuxAcceptance        bool `json:"linux_acceptance"`
	AndroidAcceptance      bool `json:"android_acceptance"`
	NoV1CallersEvidence    bool `json:"no_v1_callers_evidence"`
	RecoverableBackupProof bool `json:"recoverable_backup_proof"`
}

// ActivePlatformsReady 是开始 listener 轮换的非破坏性门禁。破坏性退役还需要
// Linux/Android 实测、无旧调用方扫描和可恢复备份三类额外证据。
func (g GateStatus) ActivePlatformsReady() bool {
	return g.Schema == 1 && g.ServerOverlapGuard && g.LinuxV2Reader && g.AndroidV2Reader &&
		g.LinuxAcceptance && g.AndroidAcceptance
}

func (g GateStatus) GateA() bool {
	return g.Schema == 1 && g.ServerOverlapGuard && g.LinuxV2Reader && g.AndroidV2Reader
}

func (g GateStatus) GateB() bool {
	return g.GateA() && g.LinuxAcceptance && g.AndroidAcceptance &&
		g.NoV1CallersEvidence && g.RecoverableBackupProof
}

func EvaluateGateEvidence(report *GateEvidenceReportV1) (GateStatus, error) {
	status := GateStatus{Schema: 1}
	if report == nil || report.Schema != 1 || report.ClusterID == "" || report.Evidence == nil {
		return GateStatus{}, errors.New("[gate] evidence report header 无效")
	}
	evaluatedAt, err := wire.ParseTimeZ(report.EvaluatedAt)
	if err != nil {
		return GateStatus{}, err
	}
	for index := range report.Evidence {
		evidence := &report.Evidence[index]
		if index > 0 && report.Evidence[index-1].Component >= evidence.Component {
			return GateStatus{}, errors.New("[gate] evidence component 必须严格排序且唯一")
		}
		if evidence.Outcome != "passed" && evidence.Outcome != "failed" {
			return GateStatus{}, errors.New("[gate] evidence outcome 无效")
		}
		if _, err := wire.ParseHash(evidence.ArtifactHash); err != nil {
			return GateStatus{}, err
		}
		if _, err := wire.ParseHash(evidence.CertifiedHeadHash); err != nil {
			return GateStatus{}, err
		}
		observedAt, err := wire.ParseTimeZ(evidence.ObservedAt)
		if err != nil || observedAt.After(evaluatedAt) {
			return GateStatus{}, errors.New("[gate] evidence observation time 无效")
		}
		passed := evidence.Outcome == "passed"
		switch evidence.Component {
		case "android_acceptance":
			status.AndroidAcceptance = passed
		case "android_v2_reader":
			status.AndroidV2Reader = passed
		case "linux_acceptance":
			status.LinuxAcceptance = passed
		case "linux_v2_reader":
			status.LinuxV2Reader = passed
		case "no_v1_callers":
			status.NoV1CallersEvidence = passed
		case "recoverable_backup":
			status.RecoverableBackupProof = passed
		case "server_overlap_guard":
			status.ServerOverlapGuard = passed
		default:
			return GateStatus{}, errors.New("[gate] evidence component 未获协议授权")
		}
	}
	return status, nil
}

func GateEvidenceReportHash(report *GateEvidenceReportV1) (string, error) {
	if _, err := EvaluateGateEvidence(report); err != nil {
		return "", err
	}
	return wire.HashObject(DomainGateEvidenceReport, report)
}

func GateEvidence(component string, passed bool, artifactHash, headHash string,
	observedAt time.Time) GateEvidenceV1 {
	outcome := "failed"
	if passed {
		outcome = "passed"
	}
	return GateEvidenceV1{Component: component, Outcome: outcome, ArtifactHash: artifactHash,
		CertifiedHeadHash: headHash, ObservedAt: observedAt.UTC().Truncate(time.Second).Format(time.RFC3339)}
}

// Package clientreport implements the existing Observation wire contract for
// client hosts without importing the Linux report/control dependency graph.
package clientreport

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"regexp"
	"slices"
	"time"

	"loom/internal/attest"
	"loom/internal/model"
)

// §16.1 / D98：这是既有 Observation 的最小投影，不增加传输 envelope 或生命周期字段。
type Observation struct {
	Agent     *AgentState             `json:"agent,omitempty"`
	Node      string                  `json:"node"`
	TS        string                  `json:"ts"`
	Applied   string                  `json:"applied"`
	Attest    *attest.Signed          `json:"attest"`
	SelfCheck *attest.SelfCheckAttest `json:"self_check"`
}

// EmptyMeasurementsDigest 仍计算固定字段的 JSON 摘要，空集合按既有 reader 归一为 nil。
func EmptyMeasurementsDigest() string {
	payload := struct {
		Edges   []struct{} `json:"edges"`
		Targets []struct{} `json:"targets"`
	}{}
	body, _ := json.Marshal(payload)
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:])
}

var snapshotID = regexp.MustCompile(`^[0-9a-f]{12}$`)

// Build 只接受已激活快照。时间由串行 reporter 注入，健康问题由宿主提供。
func Build(node, applied string, problems []string, at time.Time, key, cert, ca []byte) (*Observation, error) {
	return BuildWithAgent(node, applied, problems, nil, at, key, cert, ca)
}

// §16.1：复用既有 AgentState、AgentClaim 和 canonical v5，两签仍由同一身份生成。
func BuildWithAgent(node, applied string, problems []string, state *AgentState, at time.Time, key, cert, ca []byte) (*Observation, error) {
	if !model.ValidNodeID(node) || !snapshotID.MatchString(applied) {
		return nil, errors.New("[§16.1 上报] 节点或已激活快照无效")
	}
	problems = append([]string(nil), problems...)
	slices.Sort(problems)
	problems = slices.Compact(problems)
	// 长度、编码与控制字符限制由既有 SignSelfCheck 校验。
	var err error
	o := &Observation{Node: node, TS: at.UTC().Format(time.RFC3339Nano), Applied: applied}
	claim := attest.Claim{CanonicalVersion: 5, Node: node, TS: o.TS, Applied: applied,
		MeasurementsSHA256: EmptyMeasurementsDigest()}
	if state != nil {
		if state.Node != node {
			return nil, errors.New("[§16.1] Agent 节点与上报身份不一致")
		}
		body, e := json.Marshal(state)
		if e != nil {
			return nil, e
		}
		if e = json.Unmarshal(body, &o.Agent); e != nil {
			return nil, e
		}
		if e = json.Unmarshal(body, &claim.Agent); e != nil {
			return nil, e
		}
	}
	if o.Attest, err = attest.Sign(claim, key, cert); err != nil {
		return nil, err
	}
	o.SelfCheck, err = attest.SignSelfCheck(attest.SelfCheckClaim{Version: 1, Node: node, TS: o.TS,
		Healthy: len(problems) == 0, Problems: problems}, key, cert)
	if err != nil {
		return nil, err
	}
	// 复用已有 verifier 核对 DPAPI 私钥、节点名称和 CA；不引入第二套验签协议。
	if _, err := attest.VerifyFresh(o.Attest, ca, at, time.Minute); err != nil {
		return nil, err
	}
	if err := checkP256Certificate(cert); err != nil {
		return nil, err
	}
	return o, nil
}

// §13.1：不再实现客户端 Observation verifier；这里只核签名身份使用的密钥类型。
func checkP256Certificate(cert []byte) error {
	block, rest := pem.Decode(cert)
	if block == nil || block.Type != "CERTIFICATE" || len(bytes.TrimSpace(rest)) != 0 {
		return errors.New("[§16.1 上报] 证书格式错误")
	}
	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return err
	}
	public, ok := certificate.PublicKey.(*ecdsa.PublicKey)
	if !ok || public.Curve != elliptic.P256() {
		return errors.New("[§16.1 上报] 必须使用 P-256 身份")
	}
	return nil
}

// §16.1：report.AgentState 的客户端线格式投影；服务端兼容测试防止类型漂移。
type AgentState struct {
	Node string `json:"node"`
	TS   string `json:"ts"`
	// ComponentVersion 保留既有 JSON 名称，承载的是 Agent 线协议版本；
	// 它不能替代运行中 Agent 进程的 commit/binary 构建坐标。
	ComponentVersion string           `json:"component_version,omitempty"`
	Selections       []AgentSelection `json:"selections"`
}

type AgentSelection struct {
	Declaration string                `json:"declaration"`
	Selector    string                `json:"selector"`
	Candidate   string                `json:"candidate"`
	Chain       []string              `json:"chain,omitempty"`
	Reason      string                `json:"reason,omitempty"`
	UpdatedAt   string                `json:"updated_at"`
	Health      *AgentCandidateHealth `json:"health,omitempty"`
}

// AgentCandidateHealth 与 internal/agent.CandidateHealth 共用线格式。
// report 不能 import agent（agent 已经依赖 report），因此在边界处显式镜像。
// 字段可选以兼容尚未完成滚动升级的旧 Agent。
type AgentCandidateHealth struct {
	Candidates       int    `json:"candidates"`
	RecentSuccess    int    `json:"recent_success"`
	RecentDegraded   int    `json:"recent_degraded,omitempty"`
	RecentFailed     int    `json:"recent_failed"`
	Stale            int    `json:"stale"`
	Unknown          int    `json:"unknown"`
	SelectedState    string `json:"selected_state"`
	SelectedSamples  int    `json:"selected_samples,omitempty"`
	SelectedFailures int    `json:"selected_failures,omitempty"`
	SelectedP50MS    *int   `json:"selected_p50_ms,omitempty"`
	SelectedP95MS    *int   `json:"selected_p95_ms,omitempty"`
	BestP50MS        *int   `json:"best_p50_ms,omitempty"`
	SelectedKBps     *int   `json:"selected_kbps,omitempty"`
	BestKBps         *int   `json:"best_kbps,omitempty"`
}

package report

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"os"
	"strings"
	"time"

	"loom/internal/clientregistry"
	"loom/internal/model"
)

const clientReportMaxBody = 1 << 20

type clientReportReceiver struct {
	table   *table
	control *Control
	now     func() time.Time
	maxAge  time.Duration
	readCA  func(string) ([]byte, error)
	logw    io.Writer
}

func newClientReportReceiver(tbl *table, control *Control, now func() time.Time,
	maxAge time.Duration, logw io.Writer) *clientReportReceiver {
	if logw == nil {
		logw = io.Discard
	}
	return &clientReportReceiver{
		table: tbl, control: control, now: now, maxAge: maxAge, readCA: os.ReadFile, logw: logw,
	}
}

// ServeHTTP 是现有签名 Observation 协议的 NAT 出站传输适配器。它有意不接受
// 完整 Status 或 learned：公网客户端只能提交由本节点拥有的陈述。成功上报与
// WireGuard gossip 进入同一张内存表，因而继续复用既有 /status、转述和 UI 链路。
func (h *clientReportReceiver) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		http.Error(w, "只接受 POST", http.StatusMethodNotAllowed)
		return
	}
	mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		http.Error(w, "客户端上报必须使用 application/json", http.StatusUnsupportedMediaType)
		return
	}
	if r.ContentLength > clientReportMaxBody {
		http.Error(w, "客户端上报超过大小限制", http.StatusRequestEntityTooLarge)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, clientReportMaxBody)
	dec := json.NewDecoder(r.Body)
	var observation Observation
	if err := dec.Decode(&observation); err != nil {
		writeClientReportDecodeError(w, err)
		return
	}
	if err := dec.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		if err == nil {
			err = errors.New("JSON 后还有额外值")
		}
		writeClientReportDecodeError(w, err)
		return
	}

	status, err := h.accept(&observation, h.now().UTC())
	if err != nil {
		// 公网伪造输入只记在反代访问日志；本地状态不可读才进入服务日志，
		// 避免攻击者用无效签名制造日志洪泛。
		if status == http.StatusServiceUnavailable {
			fmt.Fprintf(h.logw, "! 客户端上报入口不可用:%v\n", err)
		}
		http.Error(w, clientReportErrorText(status), status)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func writeClientReportDecodeError(w http.ResponseWriter, err error) {
	var tooLarge *http.MaxBytesError
	if errors.As(err, &tooLarge) {
		http.Error(w, "客户端上报超过大小限制", http.StatusRequestEntityTooLarge)
		return
	}
	http.Error(w, "客户端上报格式错误", http.StatusBadRequest)
}

func clientReportErrorText(status int) string {
	switch status {
	case http.StatusServiceUnavailable:
		return "客户端上报服务暂时不可用"
	default:
		return "客户端上报未获授权"
	}
}

func (h *clientReportReceiver) accept(o *Observation, at time.Time) (int, error) {
	if h == nil || h.table == nil || h.control == nil || h.now == nil || h.readCA == nil || h.maxAge <= 0 {
		return http.StatusServiceUnavailable, errors.New("客户端上报接收器配置不完整")
	}
	ca, err := h.readCA(caPath)
	if err != nil {
		return http.StatusServiceUnavailable, fmt.Errorf("读取上报 CA:%w", err)
	}
	trusted, err := VerifyObservationAtLeast(o, ca, at, h.maxAge, 5)
	if err != nil {
		return http.StatusForbidden, err
	}
	if !trusted.MeasurementsVerified {
		return http.StatusForbidden, errors.New("客户端上报的 measurements 未签名")
	}
	if o.SelfCheck == nil {
		return http.StatusForbidden, errors.New("客户端上报缺少签名 self-check")
	}
	if _, err := verifySelfCheckAttachment(o, ca, at, h.maxAge); err != nil {
		return http.StatusForbidden, err
	}
	if o.Traffic != nil {
		if _, err := verifyTrafficAttachment(o, ca, at, h.maxAge); err != nil {
			return http.StatusForbidden, err
		}
	}
	if o.LinkMetrics != nil {
		if _, err := verifyLinkMetricAttachment(o, ca, at, h.maxAge); err != nil {
			return http.StatusForbidden, err
		}
	}

	publicKey, err := clientReportPublicKey(o)
	if err != nil {
		return http.StatusForbidden, err
	}
	identity, err := (clientregistry.Store{Path: h.control.ClientRegistryPath}).ReportingIdentity(o.Node, publicKey)
	if err != nil {
		var protocol *clientregistry.Error
		if errors.As(err, &protocol) {
			return http.StatusForbidden, err
		}
		return http.StatusServiceUnavailable, err
	}
	ssot, _, err := loadValidatedSSOTSnapshot(h.control.SSOTPath)
	if err != nil {
		return http.StatusServiceUnavailable, err
	}
	node := ssot.NodeByID()[o.Node]
	if node == nil || node.Decommission || node.Access == nil ||
		node.Access.Platform != model.WindowsDesktop || identity.Platform != string(node.Access.Platform) {
		return http.StatusForbidden, errors.New("客户端上报节点不是在役 Windows Device")
	}
	// table.put 有意重复密码学校验。公网客户端上报量很小，让适配器与 gossip
	// 共用最后一道门代价可忽略，也避免以后校验器变化形成两个信任边界。
	if err := h.table.put(o, at, h.maxAge); err != nil {
		return http.StatusForbidden, err
	}
	return http.StatusNoContent, nil
}

// clientReportPublicKey 要求全部签名附件使用同一个 P-256 身份。
// VerifyObservationAtLeast 已证明 CA、名称和签名有效；这里再把精确 SPKI 与
// enrollment registry 当前记录比较，使已被替换但尚未过期的证书不能从公网报告。
func clientReportPublicKey(o *Observation) (string, error) {
	if o == nil {
		return "", errors.New("客户端 Observation 为空")
	}
	var certs []string
	if o.Attest != nil {
		certs = append(certs, o.Attest.Cert)
	}
	if o.AttestExtended != nil {
		certs = append(certs, o.AttestExtended.Cert)
	}
	if o.SelfCheck != nil {
		certs = append(certs, o.SelfCheck.Cert)
	}
	if o.Traffic != nil {
		certs = append(certs, o.Traffic.Cert)
	}
	if o.LinkMetrics != nil {
		certs = append(certs, o.LinkMetrics.Cert)
	}
	if len(certs) == 0 {
		return "", errors.New("客户端上报没有证书")
	}
	want := ""
	for _, certPEM := range certs {
		block, rest := pemDecodeCertificate(certPEM)
		if block == nil || len(bytes.TrimSpace(rest)) != 0 {
			return "", errors.New("客户端上报证书不是单个 PEM certificate")
		}
		certificate, err := x509.ParseCertificate(block)
		if err != nil {
			return "", errors.New("客户端上报证书格式错误")
		}
		key, ok := certificate.PublicKey.(*ecdsa.PublicKey)
		if !ok || key.Curve != elliptic.P256() {
			return "", errors.New("客户端上报证书必须使用 ECDSA P-256")
		}
		spki, err := x509.MarshalPKIXPublicKey(key)
		if err != nil {
			return "", errors.New("客户端上报公钥无法编码")
		}
		encoded := base64.RawStdEncoding.EncodeToString(spki)
		if want == "" {
			want = encoded
		} else if encoded != want {
			return "", errors.New("客户端上报附件使用了不同身份")
		}
	}
	return want, nil
}

// 用小 helper 隔开，使公网适配器无需导出 attest 内部解析器也能强制只收单个 PEM。
func pemDecodeCertificate(body string) ([]byte, []byte) {
	block, rest := pem.Decode([]byte(strings.TrimSpace(body)))
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, rest
	}
	return block.Bytes, rest
}

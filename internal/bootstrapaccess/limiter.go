// Package bootstrapaccess 落实 Bootstrap capability 的运行时计数与精确隧道 ACL。
// 它只接收 wire verifier 产生的不透明 evidence，不持久化 capability body、token、
// intent opening、CSR 或 Device identity（D115、D129、D131）。
package bootstrapaccess

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"loom/internal/wire"
)

type UsageRecordV1 struct {
	CapabilityID       string `json:"capability_id"`
	ExpiresAt          string `json:"expires_at"`
	ConnectionAttempts int64  `json:"connection_attempts"`
	TransferredBytes   int64  `json:"transferred_bytes"`
}

type durableStateV1 struct {
	Schema  int             `json:"schema"`
	Records []UsageRecordV1 `json:"records"`
}

type activeSession struct {
	capabilityID string
	body         wire.BootstrapTunnelCapabilityBodyV1
	deadline     time.Time
}

type Manager struct {
	mu       sync.Mutex
	path     string
	now      func() time.Time
	state    durableStateV1
	sessions map[string]activeSession
}

func Open(path string, now func() time.Time) (*Manager, error) {
	if path == "" || now == nil {
		return nil, errors.New("[D131 capability] usage store path/可信时间源缺失")
	}
	manager := &Manager{
		path: path, now: now, state: durableStateV1{Schema: 1, Records: []UsageRecordV1{}},
		sessions: make(map[string]activeSession),
	}
	body, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return manager, nil
	}
	if err != nil {
		return nil, err
	}
	if _, err := wire.DecodeStrict(body, 8<<20, &manager.state); err != nil {
		return nil, fmt.Errorf("[D131 capability] usage store 损坏: %w", err)
	}
	if err := validateState(&manager.state); err != nil {
		return nil, err
	}
	return manager, nil
}

// OpenSession 在返回前先耐久增加 attempt；崩溃不会恢复次数预算。sessionID 由
// transport 注入，只用于本进程 fd 生命周期，不进入 durable authority（D131）。
func (m *Manager) OpenSession(verified wire.VerifiedBootstrapCapabilityV1, sessionID, ingressSetHash string) (*Session, error) {
	body := verified.Body()
	capabilityID := verified.CapabilityID()
	if capabilityID == "" || sessionID == "" || len(sessionID) > 128 {
		return nil, errors.New("[D131 capability] verified capability/session identity 无效")
	}
	if _, err := wire.ParseHash(ingressSetHash); err != nil || ingressSetHash != body.AllowedIngressSetHash {
		return nil, errors.New("[D131 capability] capability 不允许当前 ingress set")
	}
	notBefore, err := wire.ParseTimeZ(body.NotBefore)
	if err != nil {
		return nil, err
	}
	expires, err := wire.ParseTimeZ(body.ExpiresAt)
	if err != nil {
		return nil, err
	}
	now := m.now().UTC()
	if now.Before(notBefore) || !now.Before(expires) {
		return nil, errors.New("[D131 capability] capability 已过期或尚未生效")
	}
	deadline := now.Add(time.Duration(body.MaximumSessionSeconds) * time.Second)
	if deadline.After(expires) {
		deadline = expires
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	if _, exists := m.sessions[sessionID]; exists {
		return nil, errors.New("[D131 capability] session ID 正在使用")
	}
	active := int64(0)
	for _, session := range m.sessions {
		if session.capabilityID == capabilityID {
			active++
		}
	}
	if active >= body.MaximumConcurrentSessions {
		return nil, errors.New("[D131 capability] concurrent session 上限已达")
	}
	index, found := findRecord(m.state.Records, capabilityID)
	candidate := cloneState(m.state)
	if !found {
		candidate.Records = append(candidate.Records, UsageRecordV1{CapabilityID: capabilityID, ExpiresAt: body.ExpiresAt})
		sort.Slice(candidate.Records, func(i, j int) bool { return candidate.Records[i].CapabilityID < candidate.Records[j].CapabilityID })
		index, _ = findRecord(candidate.Records, capabilityID)
	}
	record := &candidate.Records[index]
	if record.ExpiresAt != body.ExpiresAt || record.ConnectionAttempts >= body.MaximumConnectionAttempts ||
		record.TransferredBytes >= body.MaximumTotalBytes {
		return nil, errors.New("[D131 capability] capability attempt/byte budget 已耗尽或 durable binding 冲突")
	}
	record.ConnectionAttempts++
	if err := m.persistLocked(candidate); err != nil {
		return nil, err
	}
	m.state = candidate
	m.sessions[sessionID] = activeSession{capabilityID: capabilityID, body: body, deadline: deadline}
	return &Session{id: sessionID, manager: m}, nil
}

type Session struct {
	id      string
	manager *Manager
}

// AuthorizeDial 只允许 capability 中的 exact 私有 Enrollment IP:TCP port；
// DNS、UDP、ICMP、SSH、control_api 与 Internet egress 均没有通配路径（D131）。
func (s *Session) AuthorizeDial(network, address string) error {
	if s == nil || s.manager == nil {
		return errors.New("[D131 capability] session 无效")
	}
	s.manager.mu.Lock()
	defer s.manager.mu.Unlock()
	active, ok := s.manager.sessions[s.id]
	if !ok || !s.manager.now().UTC().Before(active.deadline) {
		return errors.New("[D131 capability] session 不存在或已超时")
	}
	if network != "tcp" && network != "tcp4" && network != "tcp6" || active.body.AllowedInsideTransport != "tcp" {
		return errors.New("[D131 capability] inside transport 只允许 TCP")
	}
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return errors.New("[D131 capability] destination 必须是显式 IP:port")
	}
	parsed, err := netip.ParseAddr(host)
	if err != nil || parsed.String() != host || parsed.String() != active.body.AllowedDestinationIP ||
		port != fmt.Sprintf("%d", active.body.AllowedDestinationPort) ||
		network == "tcp4" && !parsed.Is4() || network == "tcp6" && !parsed.Is6() {
		return errors.New("[D131 capability] destination 超出 exact Enrollment tuple")
	}
	return nil
}

// AddTransferredBytes 同时计入双向流量；超限时立即使 session 失效，调用方必须
// 关闭对应 transport fd，不能以另一个 session 绕过 durable 总预算（D131）。
func (s *Session) AddTransferredBytes(count int64) error {
	if s == nil || s.manager == nil || count < 0 {
		return errors.New("[D131 capability] byte accounting 输入无效")
	}
	m := s.manager
	m.mu.Lock()
	defer m.mu.Unlock()
	active, ok := m.sessions[s.id]
	if !ok || !m.now().UTC().Before(active.deadline) {
		delete(m.sessions, s.id)
		return errors.New("[D131 capability] session 不存在或已超时")
	}
	index, found := findRecord(m.state.Records, active.capabilityID)
	if !found {
		delete(m.sessions, s.id)
		return errors.New("[D131 capability] durable usage record 丢失")
	}
	record := m.state.Records[index]
	if count > active.body.MaximumTotalBytes-record.TransferredBytes {
		delete(m.sessions, s.id)
		return errors.New("[D131 capability] total byte budget 已耗尽")
	}
	candidate := cloneState(m.state)
	candidate.Records[index].TransferredBytes += count
	if err := m.persistLocked(candidate); err != nil {
		return err
	}
	m.state = candidate
	return nil
}

func (s *Session) Close() {
	if s == nil || s.manager == nil {
		return
	}
	s.manager.mu.Lock()
	delete(s.manager.sessions, s.id)
	s.manager.mu.Unlock()
}

func (m *Manager) SnapshotUsage() []UsageRecordV1 {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]UsageRecordV1(nil), m.state.Records...)
}

func validateState(state *durableStateV1) error {
	if state == nil || state.Schema != 1 || state.Records == nil {
		return errors.New("[D131 capability] usage state schema 无效")
	}
	for index, record := range state.Records {
		if _, err := wire.ParseHash(record.CapabilityID); err != nil || record.ConnectionAttempts < 0 || record.TransferredBytes < 0 ||
			index > 0 && state.Records[index-1].CapabilityID >= record.CapabilityID {
			return errors.New("[D131 capability] usage record identity/order/counter 无效")
		}
		if _, err := wire.ParseTimeZ(record.ExpiresAt); err != nil {
			return err
		}
	}
	return nil
}

func (m *Manager) persistLocked(state durableStateV1) error {
	if err := validateState(&state); err != nil {
		return err
	}
	body, err := wire.MarshalCanonical(state)
	if err != nil {
		return err
	}
	directory := filepath.Dir(m.path)
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return err
	}
	file, err := os.CreateTemp(directory, filepath.Base(m.path)+".tmp-")
	if err != nil {
		return err
	}
	temporary := file.Name()
	defer os.Remove(temporary)
	if err = file.Chmod(0o600); err == nil {
		_, err = file.Write(body)
	}
	if err == nil {
		err = file.Sync()
	}
	closeErr := file.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	if err := os.Rename(temporary, m.path); err != nil {
		return err
	}
	dir, err := os.Open(directory)
	if err != nil {
		return err
	}
	err = dir.Sync()
	closeErr = dir.Close()
	if err != nil {
		return err
	}
	return closeErr
}

func findRecord(records []UsageRecordV1, capabilityID string) (int, bool) {
	index := sort.Search(len(records), func(i int) bool { return records[i].CapabilityID >= capabilityID })
	return index, index < len(records) && records[index].CapabilityID == capabilityID
}

func cloneState(state durableStateV1) durableStateV1 {
	return durableStateV1{Schema: state.Schema, Records: append([]UsageRecordV1(nil), state.Records...)}
}

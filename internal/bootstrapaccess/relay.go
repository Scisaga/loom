package bootstrapaccess

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"time"

	"loom/internal/wire"
)

// DialContext 是 bootstrap ingress 到私有 Enrollment tuple 的直拨边界。
// 生产实现应使用 net.Dialer.DialContext，不得读取代理环境变量（D115、D131）。
type DialContext func(context.Context, string, string) (net.Conn, error)

// RelayTCP 把已经由 transport 认证的一个 stream 接到 capability 精确允许的
// Enrollment tuple。requestedNetwork/requestedAddress 必须来自 HY2/Trojan 请求本身；
// 入口不能忽略客户端请求后偷偷改拨另一个目标（D131）。
//
// attempt 在任何目标校验或拨号前先耐久计数。双向 payload 在写给对端前计入同一
// durable byte budget；一旦超时、超额、取消或任一方向失败，两端 fd 都会关闭。
func (m *Manager) RelayTCP(ctx context.Context, verified wire.VerifiedBootstrapCapabilityV1,
	sessionID, ingressSetHash, requestedNetwork, requestedAddress string, incoming net.Conn,
	dial DialContext) error {
	if incoming == nil {
		return errors.New("[D131 capability] relay context/connection/dialer 缺失")
	}
	defer incoming.Close()
	if ctx == nil || dial == nil {
		return errors.New("[D131 capability] relay context/connection/dialer 缺失")
	}
	session, err := m.OpenSession(verified, sessionID, ingressSetHash)
	if err != nil {
		return err
	}
	return session.relayTCP(ctx, requestedNetwork, requestedAddress, incoming, dial)
}

// relayTCP 只供已经原子完成 transport credential lookup + OpenSession 的 adapter
// 使用；保持它不导出可避免调用方绕开 CredentialRegistry（D131）。
func (s *Session) relayTCP(ctx context.Context, requestedNetwork, requestedAddress string,
	incoming net.Conn, dial DialContext) error {
	if incoming == nil {
		return errors.New("[D131 capability] relay context/connection/dialer 缺失")
	}
	defer incoming.Close()
	if ctx == nil || dial == nil {
		return errors.New("[D131 capability] relay context/connection/dialer 缺失")
	}
	session := s
	defer session.Close()
	if err := session.AuthorizeDial(requestedNetwork, requestedAddress); err != nil {
		return err
	}
	remaining, err := session.remaining()
	if err != nil {
		return err
	}
	relayContext, cancel := context.WithTimeout(ctx, remaining)
	defer cancel()
	outgoing, err := dial(relayContext, requestedNetwork, requestedAddress)
	if err != nil {
		return fmt.Errorf("[D131 capability] Enrollment tuple 拨号失败: %w", err)
	}
	if outgoing == nil {
		return errors.New("[D131 capability] Enrollment tuple 拨号返回空连接")
	}
	defer outgoing.Close()

	// socket deadline 使用与可信时钟算出的剩余时长，而不是把可信绝对时间直接
	// 交给操作系统；测试时钟和受保护时钟不必等于主机 wall clock（D131）。
	socketDeadline := time.Now().Add(remaining)
	if err := incoming.SetDeadline(socketDeadline); err != nil {
		return fmt.Errorf("[D131 capability] 设置 ingress deadline 失败: %w", err)
	}
	if err := outgoing.SetDeadline(socketDeadline); err != nil {
		return fmt.Errorf("[D131 capability] 设置 Enrollment deadline 失败: %w", err)
	}

	stop := context.AfterFunc(relayContext, func() {
		_ = incoming.Close()
		_ = outgoing.Close()
	})
	defer stop()

	type transferResult struct {
		direction string
		err       error
	}
	results := make(chan transferResult, 2)
	go func() {
		err := session.copyAccounted(outgoing, incoming)
		closeWrite(outgoing)
		results <- transferResult{direction: "client_to_enrollment", err: err}
	}()
	go func() {
		err := session.copyAccounted(incoming, outgoing)
		closeWrite(incoming)
		results <- transferResult{direction: "enrollment_to_client", err: err}
	}()

	first := <-results
	if first.err != nil {
		_ = incoming.Close()
		_ = outgoing.Close()
	}
	second := <-results
	if first.err != nil {
		return fmt.Errorf("[D131 capability] %s relay 失败: %w", first.direction, first.err)
	}
	if second.err != nil {
		return fmt.Errorf("[D131 capability] %s relay 失败: %w", second.direction, second.err)
	}
	if err := relayContext.Err(); err != nil {
		return fmt.Errorf("[D131 capability] relay session 已结束: %w", err)
	}
	return nil
}

func (s *Session) remaining() (time.Duration, error) {
	if s == nil || s.manager == nil {
		return 0, errors.New("[D131 capability] session 无效")
	}
	s.manager.mu.Lock()
	defer s.manager.mu.Unlock()
	active, ok := s.manager.sessions[s.id]
	if !ok {
		return 0, errors.New("[D131 capability] session 不存在")
	}
	remaining := active.deadline.Sub(s.manager.now().UTC())
	if remaining <= 0 {
		delete(s.manager.sessions, s.id)
		return 0, errors.New("[D131 capability] session 已超时")
	}
	return remaining, nil
}

func (s *Session) copyAccounted(destination io.Writer, source io.Reader) error {
	buffer := make([]byte, 32<<10)
	for {
		count, readErr := source.Read(buffer)
		if count > 0 {
			// 先耐久计数再把 payload 交给对端，进程崩溃只会保守消耗预算，
			// 不会让已经转发的字节逃出总量限制（D131）。
			if err := s.AddTransferredBytes(int64(count)); err != nil {
				return err
			}
			written := 0
			for written < count {
				n, err := destination.Write(buffer[written:count])
				written += n
				if err != nil {
					return err
				}
				if n == 0 {
					return io.ErrShortWrite
				}
			}
		}
		if readErr != nil {
			if errors.Is(readErr, io.EOF) || errors.Is(readErr, net.ErrClosed) || errors.Is(readErr, io.ErrClosedPipe) {
				return nil
			}
			return readErr
		}
		if count == 0 {
			return io.ErrNoProgress
		}
	}
}

type closeWriter interface {
	CloseWrite() error
}

func closeWrite(connection io.Writer) {
	if closer, ok := connection.(closeWriter); ok {
		_ = closer.CloseWrite()
	}
}

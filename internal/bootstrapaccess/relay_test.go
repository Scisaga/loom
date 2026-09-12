package bootstrapaccess

import (
	"context"
	"errors"
	"io"
	"net"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

func TestRelayTCPForwardsOnlyExactEnrollmentTupleAndAccountsBothDirections(t *testing.T) {
	instant := time.Date(2026, 9, 11, 11, 1, 0, 0, time.UTC)
	verified, ingressHash := verifiedCapability(t, instant)
	manager, err := Open(filepath.Join(t.TempDir(), "usage.json"), func() time.Time { return instant })
	if err != nil {
		t.Fatal(err)
	}
	incoming, client := net.Pipe()
	outgoing, enrollment := net.Pipe()
	dialed := make(chan struct{}, 1)
	result := make(chan error, 1)
	go func() {
		result <- manager.RelayTCP(context.Background(), verified, "session-1", ingressHash,
			"tcp4", "10.30.0.1:7444", incoming, func(_ context.Context, network, address string) (net.Conn, error) {
				if network != "tcp4" || address != "10.30.0.1:7444" {
					t.Errorf("拨号 tuple=%s/%s", network, address)
				}
				dialed <- struct{}{}
				return outgoing, nil
			})
	}()
	<-dialed

	request := []byte("ping")
	response := []byte("pong!!")
	writeResult := make(chan error, 1)
	go func() {
		_, err := client.Write(request)
		writeResult <- err
	}()
	gotRequest := make([]byte, len(request))
	if _, err := io.ReadFull(enrollment, gotRequest); err != nil || string(gotRequest) != string(request) {
		t.Fatalf("Enrollment 收到请求=%q err=%v", gotRequest, err)
	}
	if err := <-writeResult; err != nil {
		t.Fatal(err)
	}
	go func() {
		_, err := enrollment.Write(response)
		writeResult <- err
	}()
	gotResponse := make([]byte, len(response))
	if _, err := io.ReadFull(client, gotResponse); err != nil || string(gotResponse) != string(response) {
		t.Fatalf("客户端收到响应=%q err=%v", gotResponse, err)
	}
	if err := <-writeResult; err != nil {
		t.Fatal(err)
	}
	_ = client.Close()
	_ = enrollment.Close()
	if err := <-result; err != nil {
		t.Fatal(err)
	}
	usage := manager.SnapshotUsage()
	if len(usage) != 1 || usage[0].ConnectionAttempts != 1 || usage[0].TransferredBytes != int64(len(request)+len(response)) {
		t.Fatalf("durable 双向 usage=%#v", usage)
	}
}

func TestRelayTCPRejectsUnauthorizedTargetBeforeDialButConsumesAttempt(t *testing.T) {
	instant := time.Date(2026, 9, 11, 11, 1, 0, 0, time.UTC)
	verified, ingressHash := verifiedCapability(t, instant)
	manager, err := Open(filepath.Join(t.TempDir(), "usage.json"), func() time.Time { return instant })
	if err != nil {
		t.Fatal(err)
	}
	incoming, client := net.Pipe()
	defer client.Close()
	var dialCalls atomic.Int64
	err = manager.RelayTCP(context.Background(), verified, "session-1", ingressHash,
		"tcp4", "10.30.0.1:22", incoming, func(context.Context, string, string) (net.Conn, error) {
			dialCalls.Add(1)
			return nil, errors.New("不应拨号")
		})
	if err == nil || dialCalls.Load() != 0 {
		t.Fatalf("越权 relay err=%v dial_calls=%d", err, dialCalls.Load())
	}
	usage := manager.SnapshotUsage()
	if len(usage) != 1 || usage[0].ConnectionAttempts != 1 || usage[0].TransferredBytes != 0 {
		t.Fatalf("越权 attempt 未耐久计数:%#v", usage)
	}
}

func TestRelayTCPClosesBeforeForwardingBytesBeyondDurableBudget(t *testing.T) {
	instant := time.Date(2026, 9, 11, 11, 1, 0, 0, time.UTC)
	verified, ingressHash := verifiedCapability(t, instant)
	manager, err := Open(filepath.Join(t.TempDir(), "usage.json"), func() time.Time { return instant })
	if err != nil {
		t.Fatal(err)
	}
	incoming, client := net.Pipe()
	outgoing, enrollment := net.Pipe()
	result := make(chan error, 1)
	go func() {
		result <- manager.RelayTCP(context.Background(), verified, "session-1", ingressHash,
			"tcp4", "10.30.0.1:7444", incoming, func(context.Context, string, string) (net.Conn, error) {
				return outgoing, nil
			})
	}()
	writeResult := make(chan error, 1)
	go func() {
		_, err := client.Write([]byte("eleven-byte"))
		writeResult <- err
	}()
	readBuffer := make([]byte, 32)
	count, readErr := enrollment.Read(readBuffer)
	if count != 0 || readErr == nil {
		t.Fatalf("超额 payload 被转发 count=%d err=%v", count, readErr)
	}
	if err := <-result; err == nil {
		t.Fatal("超过 byte budget 的 relay 没有失败")
	}
	// net.Pipe 的 Write 在 relay 已从内存取走 payload 后允许成功；授权边界是
	// payload 没有写到 Enrollment，而不是发送方一定观察到哪一种 errno。
	_ = <-writeResult
	_ = client.Close()
	_ = enrollment.Close()
	usage := manager.SnapshotUsage()
	if len(usage) != 1 || usage[0].ConnectionAttempts != 1 || usage[0].TransferredBytes != 0 {
		t.Fatalf("超额 payload 不应部分计入/转发:%#v", usage)
	}
}

func TestRelayTCPDialFailureClosesIngressAndKeepsAttempt(t *testing.T) {
	instant := time.Date(2026, 9, 11, 11, 1, 0, 0, time.UTC)
	verified, ingressHash := verifiedCapability(t, instant)
	manager, err := Open(filepath.Join(t.TempDir(), "usage.json"), func() time.Time { return instant })
	if err != nil {
		t.Fatal(err)
	}
	incoming, client := net.Pipe()
	err = manager.RelayTCP(context.Background(), verified, "session-1", ingressHash,
		"tcp4", "10.30.0.1:7444", incoming, func(context.Context, string, string) (net.Conn, error) {
			return nil, errors.New("unreachable")
		})
	if err == nil {
		t.Fatal("Enrollment 拨号失败被忽略")
	}
	if _, err := client.Write([]byte("must fail")); err == nil {
		t.Fatal("拨号失败后 ingress fd 仍可写")
	}
	_ = client.Close()
	usage := manager.SnapshotUsage()
	if len(usage) != 1 || usage[0].ConnectionAttempts != 1 {
		t.Fatalf("拨号失败 attempt 未保留:%#v", usage)
	}
}

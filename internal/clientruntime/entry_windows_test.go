//go:build windows

package clientruntime

import (
	"context"
	"net"
	"testing"
	"time"

	"loom/internal/agent"
)

func TestWindowsEntryNativeSinglePing(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	e := agent.ClientEntry{Node: "demo-entry", Address: "127.0.0.1", Source: "127.0.0.1"}
	rtt, err := pingWindowsEntry(ctx, e)
	if err != nil || rtt < 0 || rtt > time.Second {
		t.Fatalf("native ICMP reply=%v err=%v", rtt, err)
	}
	cancel()
	if _, err := pingWindowsEntry(ctx, e); err == nil {
		t.Fatal("canceled ping ran")
	}
	if ip := net.ParseIP(entrySource("127.0.0.1")); ip == nil || !ip.IsLoopback() {
		t.Fatal("could not capture entry source")
	}
}

// §16.1：健康上报只能接触本机监听，连接后不发送代理协议或业务数据。
func TestWindowsHealthCheckDoesNotSendBusinessTraffic(t *testing.T) {
	l, err := net.Listen("tcp4", "127.0.0.1:1080")
	if err != nil {
		t.Skip("local proxy listener occupied")
	}
	defer l.Close()
	done := make(chan int, 1)
	go func() {
		c, err := l.Accept()
		if err != nil {
			done <- -1
			return
		}
		defer c.Close()
		_ = c.SetReadDeadline(time.Now().Add(time.Second))
		var b [1]byte
		n, _ := c.Read(b[:])
		done <- n
	}()
	if p := CheckWindowsHealth(context.Background(), &WindowsHealthPlan{profile: WindowsPortableMixedProfile}); len(p) != 0 {
		t.Fatal(p)
	}
	if n := <-done; n != 0 {
		t.Fatalf("health sent %d business bytes", n)
	}
	l.Close()
	if p := CheckWindowsHealth(context.Background(), &WindowsHealthPlan{profile: WindowsPortableMixedProfile}); len(p) == 0 {
		t.Fatal("missing local listener considered ready")
	}
}

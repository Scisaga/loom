package loomcore

import (
	"context"
	"net"
	"testing"
	"time"

	"loom/internal/control"
)

type testAndroidProtector struct {
	calls int
	allow bool
}

func (p *testAndroidProtector) ProtectSocket(fd int64) bool { p.calls++; return p.allow && fd >= 0 }

func TestAndroidPrivateSocketsUseProtectAndRejectProtectionFailure(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	protector := &testAndroidProtector{allow: true}
	SetAndroidSocketProtector(protector)
	defer SetAndroidSocketProtector(nil)
	ctx, cancel := context.WithTimeout(androidNetworkContext(), time.Second)
	defer cancel()
	conn, err := control.EndpointDialer(ctx)(ctx, "tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	conn.Close()
	if protector.calls != 1 {
		t.Fatal("private socket bypassed platform protection")
	}
	protector.allow = false
	if conn, err := control.EndpointDialer(ctx)(ctx, "tcp", listener.Addr().String()); err == nil {
		conn.Close()
		t.Fatal("failed protection opened an underlay connection")
	}
}

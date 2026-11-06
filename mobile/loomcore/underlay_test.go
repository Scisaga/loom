package loomcore

import (
	"context"
	"net"
	"reflect"
	"sync/atomic"
	"testing"
	"time"

	"loom/internal/control"
)

func TestAndroidPlatformPrefixesDistinguishUnknownAndExcludeOwnCapture(t *testing.T) {
	for _, tc := range []struct {
		body string
		want *[]string
	}{
		{`null`, nil},
		{`[]`, new([]string{})},
		{`["192.0.2.1/30","198.51.100.2/32","203.0.113.7/24","203.0.113.8/24"]`, new([]string{"198.51.100.2/32", "203.0.113.0/24"})},
	} {
		got, err := androidConnectedIPv4Prefixes([]byte(tc.body))
		if err != nil || !reflect.DeepEqual(got, tc.want) {
			t.Fatal("platform prefix projection lost unknown/empty or own-address boundary", err)
		}
	}
	for _, bad := range []string{`{}`, `["invalid"]`} {
		if got, err := androidConnectedIPv4Prefixes([]byte(bad)); err == nil || got != nil {
			t.Fatal("malformed platform readback became an available underlay")
		}
	}
}

type testAndroidProtector struct {
	calls atomic.Int64
	allow bool
}

func (p *testAndroidProtector) ProtectSocket(fd int64) bool {
	p.calls.Add(1)
	return p.allow && fd >= 0
}

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
	_, port, _ := net.SplitHostPort(listener.Addr().String())
	if named, err := control.EndpointDialer(ctx)(ctx, "tcp", net.JoinHostPort("demo-entry.example", port)); err == nil {
		named.Close()
		t.Fatal("unresolved hostname bypassed the certified resolver")
	}
	if protector.calls.Load() != 1 {
		t.Fatal("private socket bypassed platform protection")
	}
	protector.allow = false
	if conn, err := control.EndpointDialer(ctx)(ctx, "tcp", listener.Addr().String()); err == nil {
		conn.Close()
		t.Fatal("failed protection opened an underlay connection")
	}
}

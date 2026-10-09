package loomcore

import (
	"context"
	"net"
	"reflect"
	"testing"
	"time"

	"loom/internal/control"
)

func TestAndroidPlatformPrefixesDistinguishUnknownAndExcludeOwnCapture(t *testing.T) {
	local := []string{"198.51.100.2/32"}
	resources := []control.TransportResource{{Authentication: control.ResourceAuthentication{LocalAddresses: &local}}}
	for _, tc := range []struct {
		body string
		want *[]string
	}{
		{`null`, nil},
		{`[]`, new([]string{})},
		{`["192.0.2.1/30","198.51.100.2/32","203.0.113.7/24","203.0.113.8/24"]`, new([]string{"203.0.113.0/24"})},
	} {
		got, err := androidConnectedIPv4Prefixes([]byte(tc.body), resources...)
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

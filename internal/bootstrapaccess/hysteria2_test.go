package bootstrapaccess

import (
	"bytes"
	"context"
	"crypto/tls"
	"net"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/sagernet/quic-go/quicvarint"

	"loom/internal/wire"
)

func TestReadHysteria2TCPRequestUsesBoundedExactWire(t *testing.T) {
	address := "10.30.0.1:7444"
	body := quicvarint.Append(nil, uint64(len(address)))
	body = append(body, address...)
	body = quicvarint.Append(body, 3)
	body = append(body, "pad"...)
	got, err := readHysteria2TCPRequest(bytes.NewReader(body))
	if err != nil || got != address {
		t.Fatalf("HY2 TCP request=%q err=%v", got, err)
	}
	invalid := [][]byte{
		nil,
		quicvarint.Append(nil, 0),
		append(quicvarint.Append(nil, hysteria2MaxAddressLength+1), 'x'),
		append(append(quicvarint.Append(nil, 1), 0xff), 0),
		append(append(quicvarint.Append(nil, 1), 'x'), quicvarint.Append(nil, hysteria2MaxPaddingLength+1)...),
	}
	for index, candidate := range invalid {
		if _, err := readHysteria2TCPRequest(bytes.NewReader(candidate)); err == nil {
			t.Fatalf("无效 HY2 request #%d 被接受", index)
		}
	}
}

func TestNewHysteria2ServerRejectsUncertifiedConfiguration(t *testing.T) {
	instant := time.Date(2026, 9, 11, 11, 1, 0, 0, time.UTC)
	verified, ingressHash := verifiedCapability(t, instant)
	manager, err := Open(t.TempDir()+"/usage.json", func() time.Time { return instant })
	if err != nil {
		t.Fatal(err)
	}
	registry, err := NewCredentialRegistry(ingressHash, []wire.VerifiedBootstrapCapabilityV1{verified})
	if err != nil {
		t.Fatal(err)
	}
	_, certificate, _ := trojanCertificate(t, "bootstrap.example")
	_, wrongCertificate, _ := trojanCertificate(t, "other.example")
	base := Hysteria2ServerOptions{
		ServerName: "bootstrap.example", TLSConfig: certificate, HandshakeTimeout: 5 * time.Second,
		IdleTimeout: 30 * time.Second, MaximumConcurrentConnections: 4, MaximumStreamsPerConnection: 4,
		Dial: func(context.Context, string, string) (net.Conn, error) { return nil, net.ErrClosed },
	}
	invalid := []Hysteria2ServerOptions{
		{ServerName: "192.0.2.10", TLSConfig: base.TLSConfig, HandshakeTimeout: base.HandshakeTimeout,
			IdleTimeout: base.IdleTimeout, MaximumConcurrentConnections: 4, MaximumStreamsPerConnection: 4, Dial: base.Dial},
		{ServerName: base.ServerName, TLSConfig: &tls.Config{}, HandshakeTimeout: base.HandshakeTimeout,
			IdleTimeout: base.IdleTimeout, MaximumConcurrentConnections: 4, MaximumStreamsPerConnection: 4, Dial: base.Dial},
		{ServerName: base.ServerName, TLSConfig: wrongCertificate, HandshakeTimeout: base.HandshakeTimeout,
			IdleTimeout: base.IdleTimeout, MaximumConcurrentConnections: 4, MaximumStreamsPerConnection: 4, Dial: base.Dial},
	}
	for index, options := range invalid {
		if _, err := NewHysteria2Server(manager, registry, options); err == nil {
			t.Fatalf("无效 Hysteria2 配置 #%d 被接受", index)
		}
	}
}

func FuzzReadHysteria2TCPRequest(f *testing.F) {
	validAddress := "10.30.0.1:7444"
	valid := quicvarint.Append(nil, uint64(len(validAddress)))
	valid = append(valid, validAddress...)
	valid = quicvarint.Append(valid, 0)
	f.Add(valid)
	f.Add([]byte{0})
	f.Fuzz(func(t *testing.T, body []byte) {
		address, err := readHysteria2TCPRequest(bytes.NewReader(body))
		if err != nil {
			return
		}
		if address == "" || !utf8.ValidString(address) || len(address) > hysteria2MaxAddressLength {
			t.Fatalf("parser 返回越界 address，length=%d", len(address))
		}
	})
}

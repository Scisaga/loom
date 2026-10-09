package clientadapter

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/netip"

	"golang.org/x/net/dns/dnsmessage"
	"golang.org/x/net/proxy"
	"loom/internal/control"
)

type nativeDiagnosticKey struct{}
type nativeDiagnostic struct {
	secret string
	dial   func(context.Context, string, string) (net.Conn, error)
}

// WithNativeDiagnostic selects the current process's protected local entry,
// including its network namespace. It never instantiates a second WG session.
func WithNativeDiagnostic(ctx context.Context, config string, dial func(context.Context, string, string) (net.Conn, error)) (context.Context, error) {
	var document struct {
		Experimental struct {
			API struct {
				Secret  string `json:"secret"`
				Address string `json:"external_controller"`
			} `json:"clash_api"`
		} `json:"experimental"`
	}
	if json.Unmarshal([]byte(config), &document) != nil || document.Experimental.API.Secret == "" || document.Experimental.API.Address != "127.0.0.1:61800" {
		return nil, errors.New("native diagnostic requires the running local API identity")
	}
	return NativeDiagnosticContext(ctx, document.Experimental.API.Secret, dial)
}

func NativeDiagnosticContext(ctx context.Context, secret string, dial func(context.Context, string, string) (net.Conn, error)) (context.Context, error) {
	if secret == "" {
		return nil, errors.New("native diagnostic secret is missing")
	}
	if dial == nil {
		dial = (&net.Dialer{}).DialContext
	}
	return context.WithValue(ctx, nativeDiagnosticKey{}, nativeDiagnostic{secret: secret, dial: dial}), nil
}

type diagnosticDialer struct {
	nativeDiagnostic
	ctx context.Context
}

func (d diagnosticDialer) Dial(network, address string) (net.Conn, error) {
	return d.dial(d.ctx, network, address)
}
func (d diagnosticDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return d.dial(ctx, network, address)
}

// ProbeWireGuard proves an authenticated DNS request and response through the
// running native WG sender. It is neither a Service success nor an ICMP probe.
func ProbeWireGuard(ctx context.Context, network string, resource control.TransportResource) error {
	diagnostic, ok := ctx.Value(nativeDiagnosticKey{}).(nativeDiagnostic)
	if !ok {
		return errors.New("no running native diagnostic entry")
	}
	address, err := control.WireGuardAccessAddress(resource, "")
	if err != nil {
		return err
	}
	dialer, err := proxy.SOCKS5("tcp", NativeProbeAddress, &proxy.Auth{User: resource.ID, Password: diagnostic.secret}, diagnosticDialer{diagnostic, ctx})
	if err != nil {
		return err
	}
	connection, err := dialer.(proxy.ContextDialer).DialContext(ctx, "tcp", net.JoinHostPort(address.String(), "53"))
	if err != nil {
		return err
	}
	defer connection.Close()
	stop := context.AfterFunc(ctx, func() { connection.Close() })
	defer stop()
	if deadline, ok := ctx.Deadline(); ok {
		if err := connection.SetDeadline(deadline); err != nil {
			return err
		}
	}
	var nonce [2]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return err
	}
	question := dnsmessage.Question{Name: dnsmessage.MustNewName("loom-probe.example."), Type: dnsmessage.TypeAAAA, Class: dnsmessage.ClassINET}
	message := dnsmessage.Message{Header: dnsmessage.Header{ID: binary.BigEndian.Uint16(nonce[:]), RecursionDesired: true}, Questions: []dnsmessage.Question{question}}
	body, err := message.Pack()
	if err != nil {
		return err
	}
	packet := make([]byte, len(body)+2)
	binary.BigEndian.PutUint16(packet, uint16(len(body)))
	copy(packet[2:], body)
	if _, err := io.Copy(connection, bytes.NewReader(packet)); err != nil {
		return err
	}
	if _, err := io.ReadFull(connection, nonce[:]); err != nil {
		return err
	}
	size := int(binary.BigEndian.Uint16(nonce[:]))
	if size < 12 || size > 4096 {
		return errors.New("native DNS response size is invalid")
	}
	response := make([]byte, size)
	if _, err := io.ReadFull(connection, response); err != nil {
		return err
	}
	var decoded dnsmessage.Message
	if decoded.Unpack(response) != nil || !decoded.Header.Response || decoded.Header.ID != message.Header.ID || decoded.Header.RCode != dnsmessage.RCodeSuccess || len(decoded.Questions) != 1 || decoded.Questions[0] != question {
		return errors.New("native DNS response does not match the request")
	}
	pool, err := control.WireGuardTargetPrefix(network, resource)
	if err != nil {
		return err
	}
	for _, answer := range decoded.Answers {
		if value, ok := answer.Body.(*dnsmessage.AAAAResource); ok && answer.Header.Name == question.Name && pool.Contains(netip.AddrFrom16(value.AAAA)) {
			return nil
		}
	}
	return errors.New("native DNS response has no authenticated execution address")
}

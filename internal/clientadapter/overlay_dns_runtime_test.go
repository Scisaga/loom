package clientadapter

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
	"golang.org/x/net/proxy"
	"loom/internal/control"
)

// All listeners are loopback-only; no TUN, host DNS, routes or service changes.
func TestOverlayDNSRealAnswersBusinessAndRemoval(t *testing.T) {
	executable := os.Getenv("LOOM_TUN_ROUTING_EXECUTABLE")
	if executable == "" {
		t.Skip("requires the reviewed data-plane executable")
	}
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "demo-private-business") }))
	defer target.Close()
	_, targetPort, _ := net.SplitHostPort(target.Listener.Addr().String())
	free := func() (string, int) {
		l, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer l.Close()
		return l.Addr().String(), l.Addr().(*net.TCPAddr).Port
	}
	dnsAddress, dnsPort := free()
	proxyAddress, proxyPort := free()
	root := t.TempDir()
	source, _ := json.Marshal(map[string]any{
		"inbounds":  []any{map[string]any{"type": "direct", "tag": "demo-dns", "listen": "127.0.0.1", "listen_port": dnsPort}, map[string]any{"type": "mixed", "tag": "demo-mixed", "listen": "127.0.0.1", "listen_port": proxyPort}},
		"outbounds": []any{map[string]any{"type": "direct", "tag": "demo-direct"}, map[string]any{"type": "block", "tag": "reject"}},
		"route":     map[string]any{"final": "reject", "rules": []any{map[string]any{"inbound": []string{"demo-dns"}, "action": "hijack-dns"}, map[string]any{"domain": []string{"demo-service.loom"}, "outbound": "demo-direct"}}},
		"dns":       map[string]any{"servers": []any{map[string]any{"tag": "demo-no-upstream", "address": "rcode://refused"}}},
	})
	records := []control.DNSRecord{{ID: "demo-record", Name: "demo-service.loom", Addresses: []string{"127.0.0.1", "2001:db8::10"}}, {ID: "demo-v4", Name: "demo-v4.loom", Addresses: []string{"192.0.2.10"}}}
	exchange := func(network, name string, typ dnsmessage.Type) (dnsmessage.Message, error) {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		connection, err := (&net.Dialer{}).DialContext(ctx, network, dnsAddress)
		if err != nil {
			return dnsmessage.Message{}, err
		}
		defer connection.Close()
		connection.SetDeadline(time.Now().Add(time.Second))
		q := dnsmessage.Message{Header: dnsmessage.Header{ID: 42, RecursionDesired: true}, Questions: []dnsmessage.Question{{Name: dnsmessage.MustNewName(name), Type: typ, Class: dnsmessage.ClassINET}}}
		body, _ := q.Pack()
		if network == "tcp" {
			body = binary.BigEndian.AppendUint16(nil, uint16(len(body)))
			packet, _ := q.Pack()
			body = append(body, packet...)
		}
		if _, err = connection.Write(body); err != nil {
			return dnsmessage.Message{}, err
		}
		reply := make([]byte, 65535)
		if network == "tcp" {
			var size [2]byte
			if _, err = io.ReadFull(connection, size[:]); err != nil {
				return dnsmessage.Message{}, err
			}
			reply = reply[:binary.BigEndian.Uint16(size[:])]
			_, err = io.ReadFull(connection, reply)
		} else {
			var n int
			n, err = connection.Read(reply)
			reply = reply[:n]
		}
		var result dnsmessage.Message
		if err == nil {
			err = result.Unpack(reply)
		}
		return result, err
	}
	for step := 0; step < 3; step++ {
		current := records
		if step == 2 {
			current = nil
		}
		config, err := WithOverlayDNS(string(source), current, false)
		if err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(root, "config.json")
		if err = os.WriteFile(path, []byte(config), 0600); err != nil {
			t.Fatal(err)
		}
		var log bytes.Buffer
		command := exec.Command(executable, "run", "-c", path)
		command.Stdout = &log
		command.Stderr = &log
		if err = command.Start(); err != nil {
			t.Fatal(err)
		}
		func() {
			defer func() { command.Process.Kill(); command.Wait() }()
			var answer dnsmessage.Message
			until := time.Now().Add(5 * time.Second)
			for time.Now().Before(until) {
				answer, err = exchange("udp", "demo-service.loom.", dnsmessage.TypeA)
				if err == nil {
					break
				}
				time.Sleep(20 * time.Millisecond)
			}
			if err != nil {
				t.Fatal("DNS did not start", err)
			}
			if step == 2 {
				if answer.RCode != dnsmessage.RCodeNameError || len(answer.Answers) != 0 {
					t.Fatal("withdrawn DNS answer survived", answer)
				}
			} else {
				for _, network := range []string{"udp", "tcp"} {
					for _, typ := range []dnsmessage.Type{dnsmessage.TypeA, dnsmessage.TypeAAAA} {
						answer, err = exchange(network, "DeMo-SeRvIcE.LOOM.", typ)
						if err != nil || answer.RCode != dnsmessage.RCodeSuccess || len(answer.Answers) != 1 || answer.Answers[0].Header.TTL != 0 {
							t.Fatal("wrong exact overlay answer", network, typ, err, answer)
						}
					}
				}
				answer, err = exchange("udp", "demo-v4.loom.", dnsmessage.TypeAAAA)
				if err != nil || answer.RCode != dnsmessage.RCodeSuccess || len(answer.Answers) != 0 {
					t.Fatal("missing address family became NXDOMAIN", err, answer)
				}
			}
			for _, name := range []string{"demo-missing.loom.", "control.loom."} {
				answer, err = exchange("tcp", name, dnsmessage.TypeA)
				if err != nil || answer.RCode != dnsmessage.RCodeNameError {
					t.Fatal("missing name escaped overlay", name, err, answer)
				}
			}
			dialer, err := proxy.SOCKS5("tcp", proxyAddress, nil, &net.Dialer{Timeout: time.Second})
			if err != nil {
				t.Fatal(err)
			}
			transport := &http.Transport{DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
				return dialer.(proxy.ContextDialer).DialContext(ctx, network, address)
			}}
			defer transport.CloseIdleConnections()
			client := &http.Client{Transport: transport, Timeout: 2 * time.Second}
			response, err := client.Get("http://demo-service.loom:" + targetPort + "/")
			if step < 2 {
				if err != nil {
					t.Fatal("authorized private business failed", err)
				}
				body, _ := io.ReadAll(response.Body)
				response.Body.Close()
				if string(body) != "demo-private-business" {
					t.Fatal("wrong business reply")
				}
			} else if err == nil {
				response.Body.Close()
				t.Fatal("withdrawn name still executed")
			}
			response, err = client.Get("http://demo-v4.loom:" + strconv.Itoa(proxyPort) + "/")
			if err == nil {
				response.Body.Close()
				t.Fatal("DNS record granted unauthorized business")
			}
		}()
	}
}

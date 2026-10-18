package control

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestMemberRelayAuthenticatesIdentityAcrossUnderlayAddressChange(t *testing.T) {
	f := newMaterialFixture(t)
	key := testKey(t)
	f.keys = append(f.keys, key)
	f.members = append(f.members, Member{ControlID: "demo-control-c", NodeID: "demo-node-c", PublicKey: base64.RawURLEncoding.EncodeToString(key.Public().(ed25519.PublicKey))})
	config := f.genesis.Payload.(Genesis)
	config.ControlConfig.Members = f.members
	f.configID, _ = ConfigID(config.ControlConfig)
	var err error
	f.genesis, err = SignMaterial(Material{Schema: 3, NetworkID: f.genesis.NetworkID, IssuerControlID: f.members[0].ControlID, IssuerKeyID: f.genesis.IssuerKeyID, Operation: "genesis", Payload: config}, f.keys[0])
	if err != nil {
		t.Fatal(err)
	}
	authorities, nodes := materialAuthorities(t, f)
	root := t.TempDir()
	ca := testTransportCA(t, root)
	addresses := []string{testLoopbackAddress(t), testLoopbackAddress(t), ""}
	listener, err := net.Listen("tcp", "127.0.0.2:0")
	if err != nil {
		t.Fatal(err)
	}
	addresses[2] = listener.Addr().String()
	listener.Close()
	dns := newPrivateDNSFixture(t)
	dns.set("192.0.2.53", "127.0.0.1")
	channels := make([]*PrivateChannel, 3)
	for i := range nodes {
		files, _, leaf := testTransportIdentity(t, root, nodes[i].ControlID, int64(100+i), f.keys[i], ca, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth})
		nodes[i].PeerTLS = &files
		if i == 2 && leaf.VerifyHostname("127.0.0.2") == nil {
			t.Fatal("fixture relay certificate unexpectedly covers the new underlay coordinate")
		}
		peers := []PrivatePeer{}
		if i == 1 {
			peers = append(peers, PrivatePeer{Node: nodes[2].NodeID, Addresses: []string{addresses[2]}})
		} else if i == 2 {
			_, port, _ := net.SplitHostPort(addresses[0])
			peers = append(peers, PrivatePeer{Node: nodes[0].NodeID, Addresses: []string{net.JoinHostPort("demo.example", port)}})
		}
		channel, err := OpenPrivateChannel(PrivateChannelConfig{Schema: 3, Node: nodes[i].NodeID, Listen: []string{addresses[i]}, Peers: peers}, nodes[i])
		if err != nil {
			t.Fatal(err)
		}
		channels[i] = channel
		channel.AttachAuthority(authorities[i])
		if i == 2 {
			channel.underlayDial = dns.dial
			setPrivateDNSProjection(authorities[i], nodes[i].NodeID, []string{"192.0.2.53"})
		}
		t.Cleanup(func() { channel.Close() })
	}
	runtime, err := OpenRuntime(authorities[0].root, channels[0])
	if err != nil {
		t.Fatal(err)
	}
	defer runtime.Close()
	accepted := submitAuthority(t, runtime, authorityService("demo-member-relay-service", "demo-member-relay-create"))
	server := &http.Server{Handler: (&Server{Runtime: runtime, Channel: channels[0], Config: nodes[0]}).Handler(), ConnContext: controlConnContext}
	defer server.Close()
	go server.Serve(channels[0].ControlListener())
	reports, err := testOpenObservationStore(t, authorities[1].root)
	if err != nil {
		t.Fatal(err)
	}
	defer reports.Close()
	caller := &Runtime{Config: nodes[1], Authority: authorities[1], Reports: reports, Channel: channels[1]}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := caller.reconcilePeer(ctx, f.members[0]); err != nil {
		t.Fatal("normal signed delta failed through the current member's new underlay coordinate", err)
	}
	if _, err := authorities[1].Material(accepted.MaterialID); err != nil {
		t.Fatal("relayed original did not reach the receiving authority", err)
	}
	queries, _ := dns.observations()
	if len(queries) == 0 {
		t.Fatal("member relay target bypassed its current authorized resolver", queries)
	}
	for _, address := range queries {
		if address != "192.0.2.53:53" {
			t.Fatal("member relay target used an unauthorized resolver", address)
		}
	}

	// A CA-issued leaf with the right ControlID still needs the current key.
	_, wrongPair, _ := testTransportIdentity(t, t.TempDir(), nodes[2].ControlID, 200, testKey(t), ca, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth})
	pool := x509.NewCertPool()
	pool.AddCert(ca.certificate)
	fake, err := net.Listen("tcp", "127.0.0.2:0")
	if err != nil {
		t.Fatal(err)
	}
	defer fake.Close()
	tlsListener := tls.NewListener(fake, &tls.Config{Certificates: []tls.Certificate{wrongPair}, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: pool, MinVersion: tls.VersionTLS13, NextProtos: []string{controlRelayALPN}})
	finished := make(chan struct{})
	go func() {
		defer close(finished)
		for range 2 {
			connection, err := tlsListener.Accept()
			if err != nil {
				return
			}
			connection.SetDeadline(time.Now().Add(time.Second))
			connection.(*tls.Conn).Handshake()
			connection.Close()
		}
	}()
	_, err = channels[1].dialMemberRoute(ctx, nodes[0].NodeID, fake.Addr().String(), controlALPN, controlRelayALPN, nodes[2].NodeID, true)
	if err == nil || !strings.Contains(err.Error(), "key is not the current member key") {
		t.Fatal("outer member hop accepted a noncurrent key for a proof-only request", err)
	}
	_, err = channels[1].dialMemberRoute(ctx, nodes[0].NodeID, fake.Addr().String(), controlALPN, controlRelayALPN, "demo-independent-relay", false)
	var hostname x509.HostnameError
	if err == nil || !errors.As(err, &hostname) {
		t.Fatal("nonmember relay lost its original hostname verification", err)
	}
	<-finished
}

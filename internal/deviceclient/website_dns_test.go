package deviceclient

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"net"
	"reflect"
	"testing"
	"time"

	"loom/internal/control"
)

func TestWebsiteResolutionUsesCertifiedUnderlayAndKeepsEndpointIdentity(t *testing.T) {
	invite, _ := schema3Fixture(t, "linux")
	endpoint := invite.Material.Payload.(control.Invite).Endpoint
	endpoint.ID, endpoint.Host, endpoint.ServerName, endpoint.State = "demo-website", "demo-web.example", "control.loom", "serving"
	endpoint.Modes = []string{"web"}
	endpoint.WebsiteTrustID = control.WebsiteTrustID([]byte("demo-root"))
	before, _ := control.CanonicalEncode(endpoint)
	queries := 0
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	ctx = control.WithEndpointDialer(ctx, func(_ context.Context, network, address string) (net.Conn, error) {
		if network != "udp" || address != "192.0.2.53:53" {
			t.Errorf("website bypassed certified underlay DNS: %s %s", network, address)
			return nil, errors.New("unexpected dial")
		}
		queries++
		client, server := net.Pipe()
		go func() {
			defer server.Close()
			query := make([]byte, 512)
			n, err := server.Read(query)
			if err != nil {
				return
			}
			answer := append([]byte{}, query[:n]...)
			binary.BigEndian.PutUint16(answer[2:4], 0x8180)
			if binary.BigEndian.Uint16(query[n-4:n-2]) == 1 {
				binary.BigEndian.PutUint16(answer[6:8], 1)
				answer = append(answer, 0xc0, 12, 0, 1, 0, 1, 0, 0, 0, 30, 0, 4, 192, 0, 2, 20)
			}
			_, _ = server.Write(answer)
		}()
		return client, nil
	})
	addresses, err := WebsiteAddresses(ctx, []control.EndpointGeneration{endpoint}, []string{"192.0.2.53"})
	if err != nil || !reflect.DeepEqual(addresses, []string{"192.0.2.20"}) || queries != 2 {
		t.Fatal("website did not consume the protected certified resolver", addresses, queries, err)
	}
	if _, err := WebsiteAddresses(ctx, []control.EndpointGeneration{endpoint}, nil); err == nil || queries != 2 {
		t.Fatal("website used an unconfigured DNS fallback")
	}
	after, _ := control.CanonicalEncode(endpoint)
	if !bytes.Equal(before, after) {
		t.Fatal("DNS replaced authenticated website coordinates")
	}
}

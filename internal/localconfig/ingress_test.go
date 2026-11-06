package localconfig

import (
	"net/netip"
	"testing"
)

func TestIngressAddressSeparatesPublicAndLocalPorts(t *testing.T) {
	nodes := []NodeNetwork{{ID: "demo-node", Ingress: []IngressMapping{{Protocol: "udp", PublicHost: "192.0.2.10", PublicPorts: PortRange{First: 40000, Last: 40002}, HostAddress: "192.0.2.20", HostPorts: PortRange{First: 50000, Last: 50002}}}}}
	for public := 40000; public <= 40002; public++ {
		got, err := IngressAddress(nodes, "demo-node", "udp", "192.0.2.10", public)
		if err != nil || got != netip.AddrPortFrom(netip.MustParseAddr("192.0.2.20"), uint16(public+10000)) {
			t.Fatal("mapping lost its explicit translation", got, err)
		}
	}
	for _, port := range []int{39999, 40003} {
		if _, err := IngressAddress(nodes, "demo-node", "udp", "192.0.2.10", port); err == nil {
			t.Fatal("unmapped public port accepted")
		}
	}
	if _, err := IngressAddress(nodes, "demo-other", "udp", "192.0.2.10", 40000); err == nil {
		t.Fatal("mapping changed owner")
	}
	if _, err := IngressAddress(nodes, "demo-node", "tcp", "192.0.2.10", 40000); err == nil {
		t.Fatal("mapping changed transport")
	}
	nodes[0].Ingress = append(nodes[0].Ingress, nodes[0].Ingress[0])
	if _, err := IngressAddress(nodes, "demo-node", "udp", "192.0.2.10", 40000); err == nil {
		t.Fatal("ambiguous mapping accepted")
	}
}

//go:build linux

package clientv2

import "testing"

func TestBootstrapEnrollmentTCPNetworkAcceptsResolvedIPFamilies(t *testing.T) {
	for _, network := range []string{"tcp", "tcp4", "tcp6"} {
		if !bootstrapEnrollmentTCPNetwork(network) {
			t.Fatalf("应接受 Enrollment TCP 网络 %q", network)
		}
	}
	for _, network := range []string{"", "udp", "udp4", "unix"} {
		if bootstrapEnrollmentTCPNetwork(network) {
			t.Fatalf("不应接受 Enrollment 非 TCP 网络 %q", network)
		}
	}
}

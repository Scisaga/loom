package protocol

import "testing"

func TestConnectionTargetKeySeparatesNetworksAndRejectsNoncanonicalValues(t *testing.T) {
	for _, host := range []string{"demo.example", "192.0.2.10", "2001:db8::10"} {
		for _, network := range []string{"tcp", "udp"} {
			key, err := ConnectionTargetKey(network, host, 443)
			actualNetwork, actualHost, port, parseErr := ParseConnectionTargetKey(key)
			if err != nil || parseErr != nil || actualNetwork != network || actualHost != host || port != 443 {
				t.Fatal("network-qualified target did not round trip", key, err, parseErr)
			}
		}
	}
	for _, value := range []string{"demo.example:443", "TCP://demo.example:443", "https://demo.example:443", "tcp://Demo.example:443", "tcp://demo.example.:443", "tcp://demo.example:0443", "tcp://demo.example:0", "tcp://demo.example:65536", "tcp://user@demo.example:443", "tcp://demo.example:443/path", "tcp://demo.example:443?x=1", "tcp://[::ffff:192.0.2.10]:443", "tcp://[2001:0db8::10]:443"} {
		if _, _, _, err := ParseConnectionTargetKey(value); err == nil {
			t.Fatal("noncanonical network target accepted", value)
		}
	}
}

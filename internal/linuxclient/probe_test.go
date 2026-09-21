package linuxclient

import "testing"

func TestDNSEndpoint(t *testing.T) {
	tests := []struct {
		name    string
		address string
		want    string
		wantErr bool
	}{
		{name: "IPv4", address: "192.0.2.53", want: "192.0.2.53:53"},
		{name: "IPv6", address: "2001:db8::53", want: "[2001:db8::53]:53"},
		{name: "hostname rejected", address: "resolver.example", wantErr: true},
		{name: "endpoint rejected", address: "192.0.2.53:53", wantErr: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := dnsEndpoint(test.address)
			if test.wantErr {
				if err == nil {
					t.Fatal("dnsEndpoint unexpectedly accepted an uncertified value")
				}
				return
			}
			if err != nil {
				t.Fatalf("dnsEndpoint: %v", err)
			}
			if got != test.want {
				t.Fatalf("dnsEndpoint = %q, want %q", got, test.want)
			}
		})
	}
}

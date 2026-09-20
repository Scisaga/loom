package clientruntime

import "testing"

func TestHasServerInboundSeparatesClientCaptureFromServerListener(t *testing.T) {
	for _, test := range []struct {
		name string
		body string
		want bool
	}{
		{name: "client", body: `{"inbounds":[{"type":"tun"},{"type":"mixed"}]}`, want: false},
		{name: "hysteria2", body: `{"inbounds":[{"type":"hysteria2"}]}`, want: true},
		{name: "trojan", body: `{"inbounds":[{"type":"trojan"}]}`, want: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			got, err := HasServerInbound([]byte(test.body))
			if err != nil || got != test.want {
				t.Fatalf("HasServerInbound() = %v, %v; want %v, nil", got, err, test.want)
			}
		})
	}
}

func TestHasServerInboundRejectsAmbiguousConfig(t *testing.T) {
	for _, body := range []string{
		`{"inbounds":[{"type":"redirect"}]}`,
		`{"inbounds":[],"inbounds":[{"type":"mixed"}]}`,
		`{"inbounds":[]} trailing`,
	} {
		if _, err := HasServerInbound([]byte(body)); err == nil {
			t.Fatalf("ambiguous config was accepted: %s", body)
		}
	}
}

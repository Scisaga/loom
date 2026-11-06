package control

import "testing"

func TestSenderAuthenticationIgnoresDialCoordinatesAndFencesIdentity(t *testing.T) {
	for _, kind := range []string{"wireguard", "hysteria2"} {
		t.Run(kind, func(t *testing.T) {
			key := "demo-receiver-key"
			view := DeviceView{DeviceID: "demo-source", WireGuardPublicKey: "demo-source-key"}
			resource := TransportResource{ID: "demo-resource", Kind: kind, OwnerNodeID: "demo-exit", DialHost: "old.example", DialPort: 443, Authentication: ResourceAuthentication{PublicKey: &key}}
			before, err := senderAuthenticationDigest(view, resource, "demo-credential")
			if err != nil {
				t.Fatal(err)
			}
			resource.DialHost, resource.DialPort = "new.example", 8443
			after, err := senderAuthenticationDigest(view, resource, "demo-credential")
			if err != nil || after != before {
				t.Fatal("dial coordinate changed a connection's authentication identity", err)
			}
			if kind == "wireguard" {
				view.WireGuardPublicKey = "demo-new-source-key"
			} else {
				key = "demo-receiver-key-new"
			}
			after, err = senderAuthenticationDigest(view, resource, "demo-credential-new")
			if err != nil || after == before {
				t.Fatal("changed authentication kept its old connection binding", err)
			}
		})
	}
}

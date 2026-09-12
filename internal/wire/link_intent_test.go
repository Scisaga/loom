package wire

import "testing"

func TestLinkIntentEnforcesPurposeTransportAndExactResourceBindings(t *testing.T) {
	hash := HashRaw("link-intent-test", []byte("head"))
	valid := LinkIntentV1{
		Schema: 1, ClusterID: "cluster", LinkID: "link-1", FromDeviceID: "device-a",
		To: LinkIntentDestinationV1{DeviceID: "device-b"}, Purpose: "data_forward",
		AllowedTransports: []string{"wireguard", "hysteria2"}, Initiator: "from",
		ListenerResourceRefs: []string{"edge-a"}, CredentialRefs: []string{"credential-a"},
		RouteScope: "service-a", Generation: 1, ParentHeadHash: hash,
	}
	if err := ValidateLinkIntent(&valid); err != nil {
		t.Fatal(err)
	}
	control := valid
	control.LinkID = "control-1"
	control.Purpose = "control_overlay"
	control.AllowedTransports = []string{"wireguard"}
	control.RouteScope = "control-overlay"
	if err := ValidateLinkIntent(&control); err != nil {
		t.Fatal(err)
	}
	bootstrap := valid
	bootstrap.LinkID = "bootstrap-1"
	bootstrap.To = LinkIntentDestinationV1{ServiceID: "enrollment-service"}
	bootstrap.Purpose = "bootstrap"
	bootstrap.AllowedTransports = []string{"hysteria2", "trojan_tls"}
	bootstrap.RouteScope = "enrollment"
	if err := ValidateLinkIntent(&bootstrap); err != nil {
		t.Fatal(err)
	}

	cases := []LinkIntentV1{
		func() LinkIntentV1 { value := valid; value.ListenerResourceRefs = nil; return value }(),
		func() LinkIntentV1 { value := valid; value.CredentialRefs = nil; return value }(),
		func() LinkIntentV1 { value := valid; value.RouteScope = ""; return value }(),
		func() LinkIntentV1 { value := valid; value.To.DeviceID = value.FromDeviceID; return value }(),
		func() LinkIntentV1 { value := control; value.AllowedTransports = []string{"hysteria2"}; return value }(),
		func() LinkIntentV1 {
			value := control
			value.To = LinkIntentDestinationV1{ServiceID: "control"}
			return value
		}(),
		func() LinkIntentV1 { value := bootstrap; value.AllowedTransports = []string{"wireguard"}; return value }(),
		func() LinkIntentV1 { value := bootstrap; value.Initiator = "to"; return value }(),
		func() LinkIntentV1 {
			value := bootstrap
			value.To = LinkIntentDestinationV1{DeviceID: "device-b"}
			return value
		}(),
	}
	for index := range cases {
		if err := ValidateLinkIntent(&cases[index]); err == nil {
			t.Fatalf("invalid LinkIntent[%d] accepted: %#v", index, cases[index])
		}
	}
}

func TestDeviceConfigArtifactRefRequiresRenderContractIdentity(t *testing.T) {
	payload := validDeviceViewPayloadForResponsibilities(t)
	payload.Active.ConfigArtifactRefs = []DeviceConfigArtifactRefV1{{
		ArtifactID: "linux-config", Generation: 1, Platform: "linux-server",
		MediaType: "application/vnd.loom.config+json", RenderContractID: "linux-runtime-v1", SizeBytes: 2,
		ContentHash: HashRaw("link-intent-test", []byte("config")),
	}}
	if _, err := DeviceViewHash(&payload); err != nil {
		t.Fatal(err)
	}
	payload.Active.ConfigArtifactRefs[0].RenderContractID = ""
	if _, err := DeviceViewHash(&payload); err == nil {
		t.Fatal("config artifact ref 接受空 render contract ID")
	}
	payload.Active.ConfigArtifactRefs[0].RenderContractID = "linux-runtime-v1"
	payload.Active.ConfigArtifactRefs[0].SizeBytes = 0
	if _, err := DeviceViewHash(&payload); err == nil {
		t.Fatal("config artifact ref 接受空 artifact")
	}
}

package render

import (
	"encoding/json"
	"reflect"
	"slices"
	"strings"
	"testing"
)

func TestAccessPauseBlocksServerCredentialsAndResumesExactly(t *testing.T) {
	s := load(t)
	device := s.AccessNodeForCredential("cred-ws-eg")
	if device == nil || device.IsServer() {
		t.Fatal("fixture needs a pure access device")
	}
	// 暂停必须同时拒绝轮换窗口内的两代凭据(§13.4 / §14.4)。
	s.CredentialByID()["cred-ws-eg"].Generation = 2
	s.CredentialByID()["cred-ws-eg"].AcceptPrevious = true
	before, err := Render(s)
	if err != nil {
		t.Fatal(err)
	}
	device.Paused = true
	paused, err := Render(s)
	if err != nil {
		t.Fatal(err)
	}
	checkedClient, checkedServer := false, false
	for _, bundle := range paused.Bundles {
		for _, file := range bundle.Files {
			if file.Path != "sing-box/config.json" {
				continue
			}
			var cfg struct {
				Inbounds []struct {
					Users []struct {
						Name string `json:"name"`
					} `json:"users"`
				} `json:"inbounds"`
			}
			if err := json.Unmarshal([]byte(file.Content), &cfg); err != nil {
				t.Fatal(err)
			}
			if bundle.Owner == device.ID {
				checkedClient = true
				for _, original := range before.Bundles {
					if original.Owner == device.ID && !reflect.DeepEqual(original, bundle) {
						t.Fatal("pause changed the client configuration or its recovery channel")
					}
				}
			} else if s.NodeByID()[bundle.Owner].IsServer() {
				checkedServer = true
				for _, inbound := range cfg.Inbounds {
					for _, user := range inbound.Users {
						credentialID, _, _ := strings.Cut(user.Name, "@")
						if slices.Contains(device.Access.Credentials, credentialID) {
							t.Fatalf("server %s still accepts paused Device credential %s", bundle.Owner, user.Name)
						}
					}
				}
			}
		}
	}
	if !checkedClient || !checkedServer {
		t.Fatal("pause did not preserve client and server configuration delivery")
	}
	device.Paused = false
	resumed, err := Render(s)
	if err != nil || !reflect.DeepEqual(before, resumed) {
		t.Fatalf("resume did not restore the exact original rendered configuration: %v", err)
	}
}

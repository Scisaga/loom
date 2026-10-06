package clientruntime

import (
	"encoding/json"
	"loom/internal/control"
	"testing"
)

func TestWindowsOverlayDNSAllProfilesAndResolverAbsence(t *testing.T) {
	record := control.DNSRecord{ID: "demo-dns", Name: "demo-service.loom", Addresses: []string{"192.0.2.10"}}
	for _, profile := range []WindowsRuntimeProfile{WindowsInstalledProfile, WindowsPortableTUNProfile, WindowsPortableMixedProfile} {
		for _, resolvers := range [][]string{nil, {"192.0.2.53"}} {
			source, _ := decodeWindowsConfig([]byte(validWindowsConfig("")))
			source.Route.Rules[0].Rules[0].Domain = []string{record.Name}
			body, _ := json.Marshal(source)
			actual, err := DeriveWindowsRuntimeConfig(body, profile, resolvers, []control.DNSRecord{record})
			if err != nil {
				t.Fatal(profile, len(resolvers), err)
			}
			derived, err := decodeWindowsConfig(actual)
			if err != nil {
				t.Fatal(err)
			}
			var found bool
			for _, server := range derived.DNS.Servers {
				if server.Address == "loom-static" && len(server.StaticRecords[record.Name]) == 1 {
					found = true
				}
			}
			if !found {
				t.Fatal("Windows lost authenticated overlay DNS")
			}
		}
	}
}

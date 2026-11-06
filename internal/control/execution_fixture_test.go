package control

import (
	"slices"
	"sort"
	"testing"
)

// Fixtures explicitly model the forward registration of their existing keys.
// Production projections never call this or infer identity from resources.
func registerTestWireGuardIdentities(t testing.TB, projection *Projection) {
	t.Helper()
	for index := range projection.DeviceAuthorizations {
		value := &projection.DeviceAuthorizations[index]
		public, err := DerivedWireGuardPublicKey(projection.NetworkID, *value)
		if err != nil {
			t.Fatal(err)
		}
		for _, resource := range projection.NetworkIntent.Resources {
			if resource.Kind == "wireguard" && resource.OwnerNodeID == value.ID {
				public = *resource.Authentication.PublicKey
			}
		}
		value.WireGuardPublicKey = public
	}
}

// Test fixtures name one Internet selection and one per independent LAN. This
// helper derives executable values; it never puts them back into signed View.
func testPolicyIDs(view DeviceView) []string {
	selected := []string{}
	internet := false
	lan := map[string]bool{}
	if slices.Contains(view.Responsibilities, "access") {
		for _, policy := range view.Policies {
			if policy.Action != "allow" || !slices.Contains(view.PolicyIDs, policy.ID) {
				continue
			}
			for _, service := range view.Services {
				if service.ID != policy.ServiceID {
					continue
				}
				if service.Kind == "internet" {
					if internet {
						continue
					}
					internet = true
				} else {
					if lan[service.ID] {
						continue
					}
					lan[service.ID] = true
				}
				selected = append(selected, policy.ID)
			}
		}
	}
	sort.Strings(selected)
	return selected
}

func testDeviceExecution(view DeviceView) DeviceExecution {
	result, err := ProjectDeviceExecution(view, testPolicyIDs(view))
	if err != nil {
		panic(err)
	}
	return result
}

// Static UI scenarios explicitly supply fixture intent. Production snapshots
// derive candidates only from verified current reports, including pending.
func testWebSnapshotWithIntent(projection Projection, admin, local, writable bool, releases ...ReleaseSet) WebSnapshot {
	value := buildWebSnapshot(projection, admin, local, writable, releases...)
	reports := []DeviceReport{}
	for _, device := range projection.DeviceAuthorizations {
		view, err := ProjectDeviceView(projection, device.ID, releases...)
		if err != nil {
			continue
		}
		report := DeviceReport{DeviceID: device.ID}
		for _, id := range testPolicyIDs(view) {
			for _, p := range view.Policies {
				if p.ID != id {
					continue
				}
				for _, service := range view.Services {
					if service.ID != p.ServiceID {
						continue
					}
					if service.Kind == "internet" {
						report.PolicyID = id
					} else {
						if report.LANPolicyIDs == nil {
							report.LANPolicyIDs = map[string]string{}
						}
						report.LANPolicyIDs[service.ID] = id
					}
				}
			}
		}
		reports = append(reports, report)
	}
	value.Paths = projectWebPathsUsing(projection, func(id string) (DeviceView, error) { return ProjectDeviceView(projection, id, releases...) }, reports...)
	return value
}

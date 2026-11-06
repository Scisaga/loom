package linuxclient

import (
	"loom/internal/control"
	"slices"
	"sort"
)

// Test fixtures name one Internet selection and one per independent LAN. This
// helper derives executable values; it never puts them back into signed View.
func testPolicyIDs(view control.DeviceView) []string {
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

func testDeviceExecution(view control.DeviceView) control.DeviceExecution {
	result, err := control.ProjectDeviceExecution(view, testPolicyIDs(view))
	if err != nil {
		panic(err)
	}
	return result
}

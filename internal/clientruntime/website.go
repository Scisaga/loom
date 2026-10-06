package clientruntime

import (
	"errors"
	"loom/internal/clientadapter"
	"reflect"
)

// Recover only the exact deterministic website projection before checking the
// unchanged Service authorization. Unknown fields and broadened rules reject.
func windowsWebsiteInput(config singBoxConfig) (clientadapter.WebsiteAccess, error) {
	var website clientadapter.WebsiteAccess
	if config.DNS != nil {
		for _, server := range config.DNS.Servers {
			if server.Tag == "loom-overlay-dns" {
				website.Addresses = server.StaticRecords["control.loom"]
			}
		}
	}
	if len(website.Addresses) == 0 {
		return website, nil
	}
	if len(config.Route.Rules) == 0 || len(config.Route.Rules[0].Port) != 1 || len(config.Outbounds) == 0 {
		return website, errors.New("website DNS has no exact underlay route")
	}
	website.Port = config.Route.Rules[0].Port[0]
	if err := website.Validate(); err != nil {
		return website, err
	}
	want := singBoxRule{Domain: []string{"control.loom"}, Network: "tcp", Port: []int{website.Port}, Outbound: "website-underlay"}
	if !reflect.DeepEqual(config.Route.Rules[0], want) ||
		!reflect.DeepEqual(config.Outbounds[len(config.Outbounds)-1], singBoxOutbound{Type: "direct", Tag: "website-underlay"}) {
		return website, errors.New("website underlay rule was changed, reordered or broadened")
	}
	return website, nil
}

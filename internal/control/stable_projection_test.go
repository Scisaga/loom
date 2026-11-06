package control

import (
	"encoding/json"
	"fmt"
	"sort"
	"testing"
	"time"
)

func TestStableViewAndSelectedRuntimeDoNotExpandPolicyPathProducts(t *testing.T) {
	project := func(count int) (DeviceView, DeviceExecution, int, time.Duration) {
		p := denseRelayProjection(t)
		template := p.NetworkIntent.Policies[0]
		p.NetworkIntent.Services = []Service{}
		p.NetworkIntent.Policies = []NetworkPolicy{}
		p.DeviceAuthorizations[0].PolicyIDs = []string{}
		for i := 0; i < count; i++ {
			id := fmt.Sprintf("demo-policy-%03d", i)
			service := Service{ID: fmt.Sprintf("demo-service-%03d", i), Name: "Demo Internet", Kind: "internet", RestrictToProbeTargets: new(false)}
			policy := template
			policy.ID = id
			policy.ServiceID = service.ID
			p.NetworkIntent.Services = append(p.NetworkIntent.Services, service)
			p.NetworkIntent.Policies = append(p.NetworkIntent.Policies, policy)
			p.DeviceAuthorizations[0].PolicyIDs = append(p.DeviceAuthorizations[0].PolicyIDs, id)
		}
		started := time.Now()
		view, err := ProjectDeviceView(p, "demo-access")
		if err != nil {
			t.Fatal(err)
		}
		execution, err := ProjectDeviceExecution(view, []string{p.NetworkIntent.Policies[0].ID})
		if err != nil {
			t.Fatal(err)
		}
		var config struct {
			Outbounds []json.RawMessage `json:"outbounds"`
		}
		if err = json.Unmarshal([]byte(execution.RuntimeProfile.Config), &config); err != nil {
			t.Fatal(err)
		}
		return view, execution, len(config.Outbounds), time.Since(started)
	}
	small, first, smallOutbounds, _ := project(20)
	large, last, largeOutbounds, elapsed := project(100)
	if len(first.Routes) != len(last.Routes) || smallOutbounds != largeOutbounds || len(small.TransportCredentials) != len(large.TransportCredentials) {
		t.Fatal("inactive Policies multiplied paths, transports or logins")
	}
	pending, err := ProjectDeviceCandidates(large, nil)
	if err != nil || len(pending.Routes) != 0 {
		t.Fatal("pending selection expanded all grants", err)
	}
	body, err := CanonicalEncode(large)
	if err != nil {
		t.Fatal(err)
	}
	if len(body) > 1<<20 {
		t.Fatal("stable authorization unexpectedly expanded execution")
	}
	t.Logf("100 Policies: signed View %d bytes, current candidates %d, native outbounds %d, local projection %s", len(body), len(last.Routes), largeOutbounds, elapsed)
}

func TestSharedLinkSpecsUseSourceDNSWithoutChangingRuntimePermissions(t *testing.T) {
	p := relayProjectionFixture(t)
	for i := range p.DeviceAuthorizations {
		p.DeviceAuthorizations[i].DNSServers = []string{fmt.Sprintf("192.0.2.%d", 53+i)}
	}
	source, err := ProjectDeviceView(p, "demo-entry")
	if err != nil {
		t.Fatal(err)
	}
	recipient, err := ProjectDeviceView(p, "demo-exit")
	if err != nil {
		t.Fatal(err)
	}
	links, err := DerivedViewLinks(source)
	if err != nil {
		t.Fatal(err)
	}
	var id string
	for _, link := range links {
		if link.FromNodeID == source.DeviceID {
			id = link.ID
			break
		}
	}
	a, err := LinkSpecDigest(source, id)
	if err != nil {
		t.Fatal(err)
	}
	b, err := LinkSpecDigest(recipient, id)
	if err != nil || a != b {
		t.Fatal("recipient substituted its own resolver parameters", err)
	}
	beforeRuntime, _ := RuntimeExecutionDigest(recipient)
	beforeACL, _ := InboundACLDigest(recipient, "demo-exit-wg")
	for i := range p.DeviceAuthorizations {
		if p.DeviceAuthorizations[i].ID == source.DeviceID {
			p.DeviceAuthorizations[i].DNSServers = []string{"192.0.2.60"}
		}
	}
	sort.Slice(p.DeviceAuthorizations, func(i, j int) bool { return p.DeviceAuthorizations[i].ID < p.DeviceAuthorizations[j].ID })
	next, err := ProjectDeviceView(p, recipient.DeviceID)
	if err != nil {
		t.Fatal(err)
	}
	changed, err := LinkSpecDigest(next, id)
	if err != nil || changed == b {
		t.Fatal("changed source request parameters retained an old specification", err)
	}
	afterRuntime, _ := RuntimeExecutionDigest(next)
	afterACL, _ := InboundACLDigest(next, "demo-exit-wg")
	if beforeRuntime != afterRuntime || beforeACL != afterACL {
		t.Fatal("another source's measurement parameters changed this node's permission or execution")
	}
}

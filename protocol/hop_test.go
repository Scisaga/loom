package protocol

import (
	"reflect"
	"testing"
)

func hopFixture() HopPolicy {
	return HopPolicy{PolicyID: "demo-policy", ServiceID: "demo-service", Kind: "internet", Origins: []string{"demo-access"}, Exits: []string{"demo-exit"}, Nodes: []string{"demo-a", "demo-b", "demo-exit"}, EntryScope: PolicyScope{"any", []string{}}, RelayScope: PolicyScope{"any", []string{}}, Edges: []DirectedHop{{"demo-a", "demo-b"}, {"demo-a", "demo-exit"}, {"demo-b", "demo-a"}, {"demo-b", "demo-exit"}}}
}
func TestActualHopsCheckOriginSenderExitRolesAndStopDistributedLoops(t *testing.T) {
	policy := hopFixture()
	start := PathContext{"demo-access", "demo-exit", []string{}}
	entry := HopPermission{SenderID: "demo-access", ReceiverID: "demo-a", Purpose: "access", Forward: true}
	first, err := policy.Admit(start, entry)
	if err != nil || len(start.Visited) != 0 || !reflect.DeepEqual(first.Visited, []string{"demo-a"}) {
		t.Fatal("entry changed original context or failed", first, err)
	}
	second, err := policy.Admit(first, HopPermission{SenderID: "demo-a", ReceiverID: "demo-b", Purpose: "forward", Forward: true})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := policy.Admit(second, HopPermission{SenderID: "demo-b", ReceiverID: "demo-a", Purpose: "forward", Forward: true}); err == nil {
		t.Fatal("mutually preferred forwarders formed a loop")
	}
	final, err := policy.Admit(second, HopPermission{SenderID: "demo-b", ReceiverID: "demo-exit", Purpose: "forward", InternetEgress: true})
	if err != nil || !reflect.DeepEqual(final.Visited, []string{"demo-a", "demo-b", "demo-exit"}) {
		t.Fatal("allowed final exit failed", final, err)
	}
	if _, err := policy.Admit(first, HopPermission{SenderID: "demo-other", ReceiverID: "demo-exit", Purpose: "forward", InternetEgress: true}); err == nil {
		t.Fatal("wrong actual predecessor was accepted")
	}
	for _, change := range []func(*HopPolicy, *PathContext, *HopPermission){
		func(_ *HopPolicy, c *PathContext, _ *HopPermission) { c.OriginID = "demo-ungranted" },
		func(_ *HopPolicy, c *PathContext, _ *HopPermission) { c.FinalExitID = "demo-other-exit" },
		func(_ *HopPolicy, _ *PathContext, p *HopPermission) { p.Forward = false },
		func(p *HopPolicy, _ *PathContext, _ *HopPermission) { p.EntryScope = PolicyScope{"none", []string{}} },
	} {
		p, c, a := policy, start, entry
		change(&p, &c, &a)
		if _, err := p.Admit(c, a); err == nil {
			t.Fatal("invalid role or grant was accepted")
		}
	}
	policy.MaxHops = 2
	if _, err := policy.Admit(second, HopPermission{SenderID: "demo-b", ReceiverID: "demo-exit", Purpose: "forward", InternetEgress: true}); err == nil {
		t.Fatal("hop limit was silently extended")
	}
	policy = hopFixture()
	policy.Origins = []string{}
	if _, err := policy.Admit(first, HopPermission{SenderID: "demo-a", ReceiverID: "demo-exit", Purpose: "forward", InternetEgress: true}); err == nil {
		t.Fatal("forward preserved a withdrawn origin")
	}
}
func TestForwardDoesNotImplyInternetEgressAndLANStaysAtItsGateway(t *testing.T) {
	policy := hopFixture()
	context := PathContext{"demo-access", "demo-exit", []string{"demo-a"}}
	permission := HopPermission{SenderID: "demo-a", ReceiverID: "demo-exit", Purpose: "forward", Forward: true}
	if _, err := policy.Admit(context, permission); err == nil {
		t.Fatal("forward role became internet egress permission")
	}
	policy.Kind = "local_network"
	permission.LANGateway = true
	if _, err := policy.Admit(context, permission); err != nil {
		t.Fatal("authorized LAN gateway required Internet egress", err)
	}
	permission.LANGateway = false
	permission.InternetEgress = true
	if _, err := policy.Admit(context, permission); err == nil {
		t.Fatal("Internet egress became LAN gateway permission")
	}
}

func TestCompiledProjectionDoesNotChangeWithCallerAndRestoresAgainstCurrentGrants(t *testing.T) {
	projection := hopFixture()
	compiled, err := projection.Compile()
	if err != nil {
		t.Fatal(err)
	}
	permission := HopPermission{SenderID: "demo-access", ReceiverID: "demo-a", Purpose: "access", Forward: true}
	value, err := compiled.Admit(PathContext{"demo-access", "demo-exit", []string{}}, permission)
	if err != nil {
		t.Fatal(err)
	}
	projection.Origins[0] = "demo-other"
	projection.Edges[0] = DirectedHop{"demo-b", "demo-a"}
	if err := compiled.VerifyCurrent(value, permission); err != nil {
		t.Fatal("caller changed accepted snapshot", err)
	}
	replacement := hopFixture()
	replacement.Origins = []string{}
	current, err := replacement.Compile()
	if err != nil {
		t.Fatal(err)
	}
	if err := current.VerifyCurrent(value, permission); err == nil {
		t.Fatal("restored registration bypassed revoked grant")
	}
	value.Visited = []string{"demo-b"}
	if err := compiled.VerifyCurrent(value, permission); err == nil {
		t.Fatal("restoration accepted another receiver")
	}
}

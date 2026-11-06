package control

import (
	"bytes"
	"context"
	"net/http"
	"reflect"
	"strings"
	"testing"
)

func TestHistoricalDenyReferenceKeepsSignedMeaningUntilExplicitWithdrawal(t *testing.T) {
	server, invite, _, claim, _, _ := enrollmentAuthorityFixture(t)
	if response := enrollmentHTTP(t, server, "/enrollment/claim", claim, enrollmentTunnel(invite)); response.Code != http.StatusOK {
		t.Fatal("join failed")
	}
	runtime := server.Runtime
	projection := runtime.Authority.Snapshot()
	deny := projection.NetworkIntent.Policies[0]
	deny.Action = "deny"
	dependencies := []string{}
	for _, target := range projection.Targets {
		dependencies = append(dependencies, target.MaterialIDs...)
	}
	dependencies = sortedUniqueDependencies(dependencies)
	op := Operation{Schema: 3, RequestID: "demo-new-deny", Operation: "policy.put", TargetKind: "policy", TargetID: deny.ID, Dependencies: dependencies, Payload: deny}
	encoded, err := EncodeOperation(op)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := runtime.Submit(context.Background(), encoded); err == nil {
		t.Fatal("normal writer created deny")
	}
	key, err := runtime.Config.PrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	frontier := projection.Frontier[0]
	historical, err := SignMaterial(Material{Schema: 3, NetworkID: projection.NetworkID, IssuerControlID: runtime.Config.ControlID, IssuerKeyID: frontier.KeyID, ControlConfigID: projection.ControlConfigID, Sequence: frontier.Sequence + 1, PreviousMaterialID: frontier.TipMaterialID, Dependencies: dependencies, RequestID: "demo-historical-deny", TargetKind: "policy", TargetID: deny.ID, Operation: "policy.put", Payload: deny}, key)
	if err != nil {
		t.Fatal(err)
	}
	original, id, err := EncodeMaterial(historical)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := runtime.Authority.PutMaterial(original); err != nil {
		t.Fatal("historical signed fact was rejected", err)
	}
	root := runtime.Authority.root
	runtime.Close()
	runtime, err = OpenRuntime(root, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer runtime.Close()
	server.Runtime = runtime
	projection = runtime.Authority.Snapshot()
	if len(projection.InvalidMaterials) != 0 || len(projection.DeviceAuthorizations) != 1 || projection.NetworkIntent.Policies[0].Action != "deny" {
		t.Fatal("historical deny reference was reinterpreted or discarded")
	}
	view, err := ProjectDeviceView(projection, invite.DeviceID)
	if err != nil || len(testDeviceExecution(view).Routes) != 0 {
		t.Fatal("historical deny granted business", err)
	}
	dependencies = []string{}
	for _, target := range projection.Targets {
		dependencies = append(dependencies, target.MaterialIDs...)
	}
	dependencies = sortedUniqueDependencies(dependencies)
	device := DevicePut{ID: invite.DeviceID, Name: invite.Name, Responsibilities: []string{"access"}, PolicyIDs: []string{deny.ID}, DistributionURLs: []string{}}
	for _, value := range []Operation{
		{Schema: 3, RequestID: "demo-retain-deny", Operation: "device.put", TargetKind: "device", TargetID: device.ID, Dependencies: dependencies, Payload: device},
		{Schema: 3, RequestID: "demo-convert-deny", Operation: "policy.put", TargetKind: "policy", TargetID: deny.ID, Dependencies: dependencies, Payload: materialTestPolicy(deny.ID, deny.ServiceID)},
	} {
		body, _ := EncodeOperation(value)
		if _, err := runtime.Submit(context.Background(), body); err == nil {
			t.Fatal("current writer retained deny or converted it into allow")
		}
	}
	device.PolicyIDs = []string{}
	submitAuthority(t, runtime, Operation{Schema: 3, RequestID: "demo-withdraw-deny", Operation: "device.put", TargetKind: "device", TargetID: device.ID, Dependencies: dependencies, Payload: device})
	submitAuthority(t, runtime, Operation{Schema: 3, RequestID: "demo-delete-deny", Operation: "policy.delete", TargetKind: "policy", TargetID: deny.ID, Dependencies: []string{id}, Payload: DeleteTarget{ID: deny.ID}})
	readback, err := runtime.Authority.Material(id)
	if err != nil || !bytes.Equal(original, readback) {
		t.Fatal("withdrawal rewrote historical signed bytes", err)
	}
}

func TestSameServicePoliciesHaveDistinctCandidatesAndDefaultReject(t *testing.T) {
	_, _, projection := deviceContractFixture(t)
	second := materialTestPolicy("demo-policy-b", "demo-service")
	projection.NetworkIntent.Policies = append(projection.NetworkIntent.Policies, second)
	projection.DeviceAuthorizations[0].PolicyIDs = append(projection.DeviceAuthorizations[0].PolicyIDs, second.ID)
	view, err := ProjectDeviceView(projection, "demo-access")
	if err != nil {
		t.Fatal(err)
	}
	first, err := ProjectDeviceCandidates(view, []string{view.PolicyIDs[0]})
	if err != nil {
		t.Fatal(err)
	}
	other, err := ProjectDeviceCandidates(view, []string{second.ID})
	if err != nil || len(first.Routes) != 1 || len(other.Routes) != 1 || first.Routes[0].ID == other.Routes[0].ID {
		t.Fatal("same path lost Policy identity", err)
	}
	pending, err := ProjectDeviceExecution(view, nil)
	if err != nil || len(pending.Routes) != 0 || !strings.Contains(pending.RuntimeProfile.Config, `"default":"reject"`) {
		t.Fatal("pending selection grants execution", err)
	}
	if _, err := ProjectDeviceCandidates(view, []string{"demo-unauthorized"}); err == nil {
		t.Fatal("unassigned Policy executed")
	}

}

func TestSameServicePoliciesReuseOnlySenderResourceAuthentication(t *testing.T) {
	projection := hy2ProjectionFixture(t)
	second := projection.NetworkIntent.Policies[0]
	second.ID = "demo-policy-b"
	projection.NetworkIntent.Policies = append(projection.NetworkIntent.Policies, second)
	projection.DeviceAuthorizations[0].PolicyIDs = append(projection.DeviceAuthorizations[0].PolicyIDs, second.ID)
	access, err := ProjectDeviceView(projection, "demo-access")
	if err != nil {
		t.Fatal(err)
	}
	receiver, err := ProjectDeviceView(projection, "demo-exit")
	if err != nil || len(access.TransportCredentials) != 1 || len(receiver.TransportCredentials) != 1 {
		t.Fatal("Policy multiplied transport authentication", err)
	}
	if !reflect.DeepEqual(access.TransportCredentials, receiver.TransportCredentials) {
		t.Fatal("sender and receiver authentication differ")
	}
	first, err := ProjectDeviceCandidates(access, []string{projection.NetworkIntent.Policies[0].ID})
	if err != nil {
		t.Fatal(err)
	}
	other, err := ProjectDeviceCandidates(access, []string{second.ID})
	if err != nil || len(first.Routes) != 1 || len(other.Routes) != 1 || first.Routes[0].ID == other.Routes[0].ID {
		t.Fatal("independent Policy choices were conflated", err)
	}
	if _, err := ProjectDeviceCandidates(access, access.PolicyIDs); err == nil {
		t.Fatal("two Internet Policies executed together")
	}
	value, err := ReceiverExecutionOptions(receiver, "demo-hy2")
	if err != nil || len(value["policies"].([]any)) != 2 {
		t.Fatal("transport authentication replaced Policy authorization", err)
	}
}

func TestReceiverOnlyOverlappingServiceDoesNotBecomeClientAuthorization(t *testing.T) {
	projection := hy2ProjectionFixture(t)
	service := projection.NetworkIntent.Services[0]
	service.ID = "demo-service-own"
	policy := materialTestPolicy("demo-policy-own", service.ID)
	projection.NetworkIntent.Services = append(projection.NetworkIntent.Services, service)
	projection.NetworkIntent.Policies = append(projection.NetworkIntent.Policies, policy)
	projection.NetworkIntent.Services[1].ProbeURLs = []string{"https://demo-service.example/probe"}
	projection.DeviceAuthorizations[1].Responsibilities = []string{"access", "internet_egress"}
	projection.DeviceAuthorizations[1].PolicyIDs = []string{policy.ID}
	view, err := ProjectDeviceView(projection, "demo-exit")
	if err != nil || len(view.TransportCredentials) != 1 || len(testDeviceExecution(view).BusinessProbeTargets) != 1 || len(testDeviceExecution(view).BusinessProbeTargets[0].Targets) != 1 || testDeviceExecution(view).BusinessProbeTargets[0].ServiceID != service.ID {
		t.Fatal("receiver's foreign service permissions changed its own probe authorization", err)
	}
}

func TestReportedPolicyRejectsUnauthorizedChoiceAndDifferentSelectedPath(t *testing.T) {
	_, _, projection := deviceContractFixture(t)
	view, err := ProjectDeviceView(projection, "demo-access")
	if err != nil {
		t.Fatal(err)
	}
	route := testDeviceExecution(view).Routes[0]
	report := DeviceReport{PolicyID: route.PolicyID, Selections: []ReportSelection{{ServiceID: route.ServiceID, PolicyID: route.PolicyID, CandidateID: route.ID}}}
	if err := verifyReportViewFields(report, view); err != nil {
		t.Fatal("saved intent and actual readback were conflated", err)
	}
	report.PolicyID = "demo-ungranted"
	if verifyReportViewFields(report, view) == nil {
		t.Fatal("report invented policy authorization")
	}
	report.PolicyID = route.PolicyID
	report.Selections[0].PolicyID = "demo-ungranted"
	if verifyReportViewFields(report, view) == nil {
		t.Fatal("actual selection reused another policy's candidate")
	}
}

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
	if err != nil || len(view.Routes) != 0 {
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
	if len(view.Routes) != 2 || view.Routes[0].ID == view.Routes[1].ID || view.Routes[0].PolicyID == view.Routes[1].PolicyID {
		t.Fatal("same path lost policy identity", view.Routes)
	}
	if !strings.Contains(view.RuntimeProfile.Config, `"default":"reject"`) {
		t.Fatal("service starts before client chooses policy")
	}
	view.Routes[0].PolicyID = "demo-unauthorized"
	if view.Validate() == nil {
		t.Fatal("candidate used an ungranted policy")
	}
}

func TestSameServicePoliciesKeepIndependentTransportCredentials(t *testing.T) {
	projection := hy2ProjectionFixture(t)
	second := projection.NetworkIntent.Policies[0]
	second.ID = "demo-policy-b"
	projection.NetworkIntent.Policies = append(projection.NetworkIntent.Policies, second)
	projection.DeviceAuthorizations[0].PolicyIDs = append(projection.DeviceAuthorizations[0].PolicyIDs, second.ID)
	access, err := ProjectDeviceView(projection, "demo-access")
	if err != nil || len(access.Routes) != 2 {
		t.Fatal("same-Service policies lost a candidate", err)
	}
	receiver, err := ProjectDeviceView(projection, "demo-exit")
	if err != nil || len(receiver.InboundCredentials) != 2 {
		t.Fatal("receiver lost a policy permission", err)
	}
	passwords, err := profileCredentials(access)
	if err != nil {
		t.Fatal(err)
	}
	first, secondPermission := receiver.InboundCredentials[0], receiver.InboundCredentials[1]
	if first.PolicyID == secondPermission.PolicyID || first.Credential == secondPermission.Credential || first.Candidate.ID == secondPermission.Candidate.ID || !reflect.DeepEqual(first.AllowedTargets, secondPermission.AllowedTargets) {
		t.Fatal("identical targets conflated independent policy permissions")
	}
	for _, permission := range receiver.InboundCredentials {
		if permission.Credential != passwords[permission.Candidate.ID] || permission.PolicyID != permission.Candidate.PolicyID {
			t.Fatal("client and receiver disagree on the complete policy binding")
		}
	}
	wrong := first
	wrong.PolicyID = secondPermission.PolicyID
	if wrong.Validate() == nil {
		t.Fatal("request permission accepted another policy's candidate")
	}
}

func TestReceiverOnlyOverlappingServiceDoesNotBecomeClientAuthorization(t *testing.T) {
	projection := hy2ProjectionFixture(t)
	service := projection.NetworkIntent.Services[0]
	service.ID = "demo-service-own"
	policy := materialTestPolicy("demo-policy-own", service.ID)
	projection.NetworkIntent.Services = append(projection.NetworkIntent.Services, service)
	projection.NetworkIntent.Policies = append(projection.NetworkIntent.Policies, policy)
	projection.NetworkIntent.BusinessProbeTargets = []BusinessProbeTarget{{ID: "demo-probe", URL: "https://demo-service.example/probe"}}
	projection.DeviceAuthorizations[1].Responsibilities = []string{"access", "internet_egress"}
	projection.DeviceAuthorizations[1].PolicyIDs = []string{policy.ID}
	view, err := ProjectDeviceView(projection, "demo-exit")
	if err != nil || len(view.InboundCredentials) != 1 || len(view.BusinessProbeTargets) != 1 || len(view.BusinessProbeTargets[0].Targets) != 1 || view.BusinessProbeTargets[0].ServiceID != service.ID {
		t.Fatal("receiver's foreign service permissions changed its own probe authorization", err)
	}
}

func TestReportedChoicesRejectUnauthorizedPolicyWithoutInferringFromActualPath(t *testing.T) {
	_, _, projection := deviceContractFixture(t)
	view, err := ProjectDeviceView(projection, "demo-access")
	if err != nil {
		t.Fatal(err)
	}
	route := view.Routes[0]
	report := DeviceReport{PolicyChoices: new([]PolicyChoice{{ServiceID: route.ServiceID}}), Selections: []ReportSelection{{ServiceID: route.ServiceID, PolicyID: route.PolicyID, CandidateID: route.ID}}}
	if err := verifyReportViewFields(report, view); err != nil {
		t.Fatal("saved intent and actual readback were conflated", err)
	}
	report.PolicyChoices = new([]PolicyChoice{{ServiceID: route.ServiceID, PolicyID: "demo-ungranted"}})
	if verifyReportViewFields(report, view) == nil {
		t.Fatal("report invented policy authorization")
	}
	report.PolicyChoices = new([]PolicyChoice{{ServiceID: route.ServiceID, PolicyID: route.PolicyID}})
	report.Selections[0].PolicyID = "demo-ungranted"
	if verifyReportViewFields(report, view) == nil {
		t.Fatal("actual selection reused another policy's candidate")
	}
}

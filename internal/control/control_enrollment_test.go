package control

import (
	"context"
	"net/http"
	"testing"
)

func TestControlEnrollmentWaitsForCertificateAndRestoresIdentity(t *testing.T) {
	for _, combined := range []bool{false, true} {
		name := "pure"
		if combined {
			name = "combined"
		}
		t.Run(name, func(t *testing.T) {
			server, invite, _, claim, key, _ := enrollmentAuthorityFixture(t, func(invite *Invite) {
				invite.DeviceID, invite.Medium = "demo-new-control", "sh"
				invite.Responsibilities, invite.PolicyIDs = []string{"control"}, []string{}
				if combined {
					invite.Responsibilities, invite.PolicyIDs = []string{"access", "control"}, []string{"demo-policy"}
				}
			})
			before := server.Runtime.Authority.Snapshot().ControlConfigID
			if _, err := server.Runtime.Authority.CompleteEnrollment(context.Background(), claim, false, enrollmentTunnel(invite), server.now(), server.Runtime.Config); err != nil {
				t.Fatal(err)
			}
			state, err := server.EnrollmentResponse(invite.ID)
			if err != nil || state.State != "bound" || state.DeviceView != nil || len(server.Runtime.Authority.Snapshot().DeviceAuthorizations) != 0 {
				t.Fatalf("binding granted roles before majority: %v %#v", err, state)
			}
			if _, err = server.Runtime.Authority.CompleteEnrollment(context.Background(), claim, false, enrollmentTunnel(invite), server.now(), server.Runtime.Config); err != nil {
				t.Fatalf("bound retry lost original identity: %v", err)
			}
			response := enrollmentHTTP(t, server, "/enrollment/claim", claim, enrollmentTunnel(invite))
			if response.Code != http.StatusOK {
				t.Fatalf("formal claim: %s", response.Body.String())
			}
			var enrollment EnrollmentResponse
			if err = DecodeCanonical(response.Body.Bytes(), &enrollment, ContractDecodeLimits{MaxBytes: 8 << 20, MaxDepth: 128, MaxItems: 1 << 20}); err != nil {
				t.Fatal(err)
			}
			if enrollment.State != "completed" || enrollment.DeviceView == nil {
				t.Fatalf("claim did not obtain majority: %s", response.Body.String())
			}
			proof := enrollment.DeviceView.ControlProof
			if len(proof.Successors) != 1 || proof.Successors[0].Config.PreviousConfigID != before || (proof.Successors[0].Config.Join.AuthorizationMaterialID != "") != combined {
				t.Fatal("certificate does not bind the exact ordinary grant")
			}
			member, ok := proofMember(proof.Successors[0].Config, invite.DeviceID)
			if !ok || member.PublicKey != claim.DevicePublicKey {
				t.Fatal("member did not use the proven claim key")
			}
			trusted, err := server.bootstrapInvite(invite.ID)
			if err != nil {
				t.Fatal(err)
			}
			if err = VerifyDeviceViewEnvelope(*enrollment.DeviceView, trusted); err != nil {
				t.Fatal(err)
			}
			if combined != containsString(enrollment.DeviceView.View.Responsibilities, "access") {
				t.Fatal("member certificate changed invited responsibilities")
			}
			if !combined && (len(enrollment.DeviceView.View.Services) != 0 || enrollment.DeviceView.View.RuntimeProfile != nil || len(server.Runtime.Authority.Snapshot().DeviceAuthorizations) != 0) {
				t.Fatal("pure control manufactured an ordinary authorization")
			}
			for _, device := range projectWebDevices(server.Runtime.Authority.Snapshot()) {
				if device.ID == invite.DeviceID && (device.Enrollment != "completed" || device.Platform != "linux" || device.Name != invite.Name) {
					t.Fatal("normal readback lost certificate-bound identity")
				}
			}
			frontier := server.Runtime.Authority.Frontier()
			root := server.Runtime.Authority.root
			server.Runtime.Close()
			runtime, err := OpenRuntime(root, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer runtime.Close()
			server.Runtime = runtime
			resume := EnrollmentResumeRequest(claim)
			resume.Signature = ""
			resume, err = SignEnrollmentResume(resume, key)
			if err != nil {
				t.Fatal(err)
			}
			response = enrollmentHTTP(t, server, "/enrollment/resume", resume, enrollmentTunnel(invite))
			if response.Code != http.StatusOK {
				t.Fatalf("restarted resume: %s", response.Body.String())
			}
			after := runtime.Authority.Frontier()
			if len(after) != len(frontier) {
				t.Fatal("resume changed signing history")
			}
			for i := range frontier {
				if after[i] != frontier[i] {
					t.Fatal("resume regenerated enrollment facts")
				}
			}
			if !combined {
				join := proof.Successors[0].Config.Join
				request := Operation{Schema: 3, RequestID: "demo-first-ordinary-grant", Operation: "device.put", TargetKind: "device", TargetID: invite.DeviceID, Dependencies: []string{join.BindingMaterialID}, Payload: DevicePut{ID: invite.DeviceID, Name: "Demo ordinary access", Responsibilities: []string{"access"}, PolicyIDs: []string{}, DistributionURLs: []string{}}}
				granted, _, err := server.HandleOperation(context.Background(), request)
				if err != nil {
					t.Fatal("pure control could not receive an ordinary grant", err)
				}
				value := granted.Projection.DeviceAuthorizations[0]
				if value.DevicePublicKey != claim.DevicePublicKey || value.BindingMaterialID != join.BindingMaterialID || value.RuntimeKey == "" {
					t.Fatal("ordinary grant did not retain its proven identity")
				}
				revoked, _, err := server.HandleOperation(context.Background(), Operation{Schema: 3, RequestID: "demo-revoke-ordinary", Operation: "device.revoke", TargetKind: "device", TargetID: invite.DeviceID, Dependencies: []string{granted.MaterialID}, Payload: DeleteTarget{ID: invite.DeviceID}})
				if err != nil {
					t.Fatal(err)
				}
				view, err := server.deviceEnvelope(invite.DeviceID)
				if err != nil || len(view.View.Responsibilities) != 1 || view.View.Responsibilities[0] != "control" || view.View.RuntimeProfile != nil {
					t.Fatal("ordinary revocation removed control identity or retained access", err)
				}
				for _, device := range projectWebDevices(revoked.Projection) {
					if device.ID == invite.DeviceID && (!device.Authorized || device.Deleted || device.Enrollment != "completed" || len(device.Roles) != 1 || device.Roles[0] != "control" || len(device.PolicyIDs) != 0) {
						t.Fatal("web readback confused ordinary revocation with control removal")
					}
				}
				request.RequestID, request.Dependencies = "demo-regrant-ordinary", []string{revoked.MaterialID}
				regranted, _, err := server.HandleOperation(context.Background(), request)
				if err != nil || regranted.Projection.DeviceAuthorizations[0].RuntimeKey != value.RuntimeKey {
					t.Fatal("ordinary regrant replaced its credential root", err)
				}
			}
			endpoint := invite.Endpoint
			endpoint.State, endpoint.DrainUntil = "draining", server.now().UnixMilli()+60000
			target, _ := runtime.Authority.Snapshot().CurrentTarget("endpoint", endpoint.ID)
			if _, err := runtime.Authority.Submit(context.Background(), Operation{Schema: 3, RequestID: "demo-member-completed-drain", Operation: "endpoint.put", TargetKind: "endpoint", TargetID: endpoint.ID, Dependencies: target.MaterialIDs, Payload: endpoint}, runtime.Config); err != nil {
				t.Fatal("completed member transaction still blocked endpoint retirement", err)
			}
		})
	}
}

func TestControlMemberOtherIssuerRecoversConditionalGrantAndKeepsSelectedRoot(t *testing.T) {
	peers := membershipTLSPeers(t, newMaterialFixture(t))
	a, b := peers[0].server.Runtime, peers[1].server.Runtime
	server, invite, _, claim, _, policyDeps := enrollmentFixtureWithRuntime(t, a, func(invite *Invite) {
		invite.DeviceID, invite.Medium = "demo-combined-member", "sh"
		invite.Responsibilities = []string{"access", "control"}
	})
	prepared, err := a.Authority.CompleteEnrollment(context.Background(), claim, false, enrollmentTunnel(invite), server.now(), a.Config)
	if err != nil {
		t.Fatal(err)
	}
	// The original issuer's final conditional authorization did not reach its
	// peer. The verified claim and all its dependencies did reach that peer.
	for _, material := range a.Authority.materials {
		id, _ := MaterialID(material)
		if id == prepared.MaterialID {
			continue
		}
		body, _ := CanonicalEncode(material)
		if _, err = b.Authority.PutMaterial(body); err != nil {
			t.Fatal(err)
		}
	}
	result, err := b.ChangeControl(context.Background(), ControlChangeRequest{Schema: 3, BaseConfigID: b.Authority.Snapshot().ControlConfigID, Operation: "add", TargetNodeID: invite.DeviceID, TransactionID: invite.ID}, server.now())
	if err != nil {
		t.Fatal("verified binding could not continue on another member", err)
	}
	selected := result.Certificate.Config.Join.AuthorizationMaterialID
	if selected == prepared.MaterialID {
		t.Fatal("test failed to exercise a separately prepared original")
	}
	original, err := b.Authority.Material(selected)
	if err != nil {
		t.Fatal(err)
	}
	material, err := DecodeMaterial(original)
	if err != nil {
		t.Fatal(err)
	}
	root := material.Payload.(DeviceAuthorization).RuntimeKey
	for _, runtime := range []*Runtime{a, b} {
		projection := runtime.Authority.Snapshot()
		if len(projection.DeviceAuthorizations) != 1 || projection.DeviceAuthorizations[0].RuntimeKey != root {
			t.Fatal("unselected conditional original changed the majority-bound authorization")
		}
	}
	target, _ := a.Authority.Snapshot().CurrentTarget("device", invite.DeviceID)
	op := Operation{Schema: 3, RequestID: "demo-selected-root-edit", Operation: "device.put", TargetKind: "device", TargetID: invite.DeviceID, Dependencies: sortedUniqueDependencies(append(policyDeps, target.MaterialIDs...)), Payload: DevicePut{ID: invite.DeviceID, Name: "Demo edited member", Responsibilities: []string{"access"}, PolicyIDs: invite.PolicyIDs, DistributionURLs: []string{}}}
	updated, _, err := server.HandleOperation(context.Background(), op)
	if err != nil || updated.Projection.DeviceAuthorizations[0].RuntimeKey != root {
		t.Fatal("ordinary edit reused an unselected credential root", err)
	}
}

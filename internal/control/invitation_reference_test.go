package control

import (
	"bytes"
	"compress/zlib"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"testing"
	"time"
)

func TestInvitationReferenceCapacityAndPrivacyIndependentOfAuthoritySize(t *testing.T) {
	fixture := newEndpointFixture(t)
	original, _, _ := fixture.invite(t, "privacy")
	key, err := fixture.server.Config.PrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	size := 0
	for _, count := range []int{0, 8, 256} {
		value := original
		payload := value.Material.Payload.(Invite)
		payload.PolicyIDs = []string{}
		value.Material.Dependencies = []string{}
		for i := 0; i < count; i++ {
			payload.PolicyIDs = append(payload.PolicyIDs, fmt.Sprintf("demo-private-policy-%04d", i))
			value.Material.Dependencies = append(value.Material.Dependencies, ReleaseDigest([]byte(fmt.Sprintf("demo-private-dependency-%04d", i))))
		}
		value.Material.Dependencies = sortedUniqueDependencies(value.Material.Dependencies)
		if count > 0 {
			genesis := original.ControlProof.Genesis
			domain := genesis.Payload.(Genesis)
			for i := 0; i < count; i++ {
				domain.ControlConfig.Members = append(domain.ControlConfig.Members, Member{ControlID: fmt.Sprintf("demo-member-control-%04d", i), NodeID: fmt.Sprintf("demo-member-node-%04d", i), PublicKey: base64.RawURLEncoding.EncodeToString(testKey(t).Public().(ed25519.PublicKey))})
			}
			sort.Slice(domain.ControlConfig.Members, func(i, j int) bool {
				return domain.ControlConfig.Members[i].ControlID < domain.ControlConfig.Members[j].ControlID
			})
			genesis.Payload = domain
			genesis, err = SignMaterial(genesis, key)
			if err != nil {
				t.Fatal(err)
			}
			anchor, _ := MaterialID(genesis)
			value.ControlProof = ControlProof{Genesis: genesis, Successors: []ControlCertificate{}}
			value.GenesisDigest = anchor
			payload.GenesisDigest = anchor
			value.Material.ControlConfigID, _ = ConfigID(domain.ControlConfig)
		}
		value.Material.Payload = payload
		value.Material, err = SignMaterial(value.Material, key)
		if err != nil {
			t.Fatal(err)
		}
		uri, err := EncodeInvite(value)
		if err != nil {
			t.Fatal(err)
		}
		if size == 0 {
			size = len(uri)
		} else if len(uri) != size {
			t.Fatal("policy or dependency growth increased delivery size")
		}
		body, _ := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(uri, invitationPrefix))
		for _, private := range []string{"policy", "dependency", "control_proof", "members", "name", "device_id", "issuer_control_id", "network_id"} {
			if bytes.Contains(body, []byte(`"`+private+`"`)) || bytes.Contains(body, []byte("demo-private")) {
				t.Fatalf("private data %s exposed", private)
			}
		}
		reference, err := DecodeInvite(uri)
		if err != nil || reference.MatchesInvite(value) != nil {
			t.Fatal("reference lost exact private original", err)
		}
		if _, err := inviteQRCode(uri); err != nil {
			t.Fatal("short invitation does not fit readable QR", err)
		}
		full, _ := CanonicalEncode(value)
		var compressed bytes.Buffer
		writer := zlib.NewWriter(&compressed)
		_, _ = writer.Write(full)
		_ = writer.Close()
		for _, old := range [][]byte{full, compressed.Bytes()} {
			if _, err := DecodeInvite(invitationPrefix + base64.RawURLEncoding.EncodeToString(old)); err == nil {
				t.Fatal("old full invitation admitted as current delivery")
			}
		}
	}
	// Maximum valid locator and escaped transaction text still fit one QR.
	reference, _ := ReferenceForInvite(original)
	reference.TransactionID = strings.Repeat("\\", 128)
	reference.Endpoint.Host = strings.Repeat("a", 63) + "." + strings.Repeat("b", 63) + "." + strings.Repeat("c", 63) + "." + strings.Repeat("d", 61)
	reference.Endpoint.ServerName = reference.Endpoint.Host
	uri, err := EncodeInvitationReference(reference)
	if err != nil {
		t.Fatal("maximum canonical locator exceeds reference budget", err)
	}
	if _, err := inviteQRCode(uri); err != nil {
		t.Fatal("maximum reference cannot be scanned", err)
	}
	t.Logf("ordinary reference %d bytes; maximum locator %d bytes", size, len(uri))
}

func TestBootstrapShortCredentialRestrictsTransactionAndIdentity(t *testing.T) {
	fixture := newEndpointFixture(t)
	invite, claim, key := fixture.invite(t, "credential")
	reference, _ := ReferenceForInvite(invite)
	for _, kind := range []string{"capability", "transaction", "certificate", "anchor", "medium"} {
		bad := reference
		switch kind {
		case "capability":
			bad.Capability = base64.RawURLEncoding.EncodeToString(make([]byte, 32))
		case "transaction":
			bad.TransactionID = "demo-unknown"
		case "certificate":
			bad.Endpoint.CertificateDigest = ReleaseDigest([]byte("demo-other"))
		case "anchor":
			bad.GenesisDigest = ReleaseDigest([]byte("demo-other"))
		case "medium":
			bad.Medium = "sh"
		}
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		connection, _, err := DialInvitation(ctx, bad)
		cancel()
		if err == nil {
			connection.Close()
			t.Fatalf("changed %s accepted", kind)
		}
	}
	if _, bound, _ := fixture.server.Runtime.Authority.Binding(claim.TransactionID); bound {
		t.Fatal("credential authentication bound an identity")
	}
	status, body := endpointPost(t, fixture.dialReference(t, reference), "/device/config", map[string]any{})
	if status == http.StatusOK {
		t.Fatal("short bearer disclosed device configuration")
	}
	status, body = endpointPost(t, fixture.dialReference(t, reference), "/enrollment/claim", claim)
	if status != http.StatusOK {
		t.Fatalf("claim failed: %s", body)
	}
	var response EnrollmentResponse
	if err := DecodeCanonical(body, &response, ContractDecodeLimits{MaxBytes: 8 << 20, MaxDepth: 128, MaxItems: 1 << 20}); err != nil || response.EnrollmentProof == nil || reference.MatchesInvite(*response.EnrollmentProof) != nil || response.DeviceView == nil || VerifyDeviceViewEnvelope(*response.DeviceView, *response.EnrollmentProof) != nil {
		t.Fatal("bound claim omitted or corrupted private proof", err)
	}
	otherKey := testKey(t)
	different := claim
	different.RequestID = "demo-other-claim"
	different.DevicePublicKey = base64.RawURLEncoding.EncodeToString(otherKey.Public().(ed25519.PublicKey))
	different, err := SignEnrollmentClaim(different, otherKey)
	if err != nil {
		t.Fatal(err)
	}
	status, _ = endpointPost(t, fixture.dialReference(t, reference), "/enrollment/claim", different)
	if status == http.StatusOK {
		t.Fatal("same credential took over a bound identity")
	}
	// The existing key/request can recover after the original open deadline.
	fixture.clock.Add(120000)
	resumed, err := SignEnrollmentResume(EnrollmentResumeRequest(claim), key)
	if err != nil {
		t.Fatal(err)
	}
	status, _ = endpointPost(t, fixture.dialReference(t, reference), "/enrollment/resume", resumed)
	if status != http.StatusOK {
		t.Fatal("bound identity could not resume after deadline")
	}
}

package control

import (
	"context"
	"net/http"
	"testing"
)

func TestHistoricalReportKeysIncludeCertifiedControlOnlyIdentity(t *testing.T) {
	server, invite, _, claim, _, _ := enrollmentAuthorityFixture(t, func(invite *Invite) {
		invite.DeviceID, invite.Medium = "demo-report-control", "sh"
		invite.Responsibilities, invite.PolicyIDs = []string{"control"}, []string{}
	})
	response := enrollmentHTTP(t, server, "/enrollment/claim", claim, enrollmentTunnel(invite))
	if response.Code != http.StatusOK {
		t.Fatal("control claim did not reach its certified binding", response.Code)
	}
	keys, err := server.Runtime.Authority.reportVerificationKeys()
	if err != nil || keys[reportOwner{claim.NetworkID, invite.DeviceID}] != claim.DevicePublicKey || len(server.Runtime.Authority.Snapshot().DeviceAuthorizations) != 0 {
		t.Fatal("certified control identity required an ordinary grant", err)
	}
	root := server.Runtime.Authority.root
	if err := server.Runtime.Close(); err != nil {
		t.Fatal(err)
	}
	after, err := loadReportVerificationKeys(context.Background(), root)
	if err != nil || after[reportOwner{claim.NetworkID, invite.DeviceID}] != claim.DevicePublicKey {
		t.Fatal("restart lost the exact certificate-bound device key", err)
	}
}

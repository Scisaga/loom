package wire

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"testing"
)

func TestEnrollmentPreflightProofBindsInviteRecordCapabilityAndPurpose(t *testing.T) {
	request := EnrollmentIntentPreflightRequestV1{Schema: 1, ClusterID: "demo-cluster", InviteID: "demo-invite",
		CertifiedInviteRecordHash: HashRaw("demo-preflight", []byte("record")), CapabilityID: HashRaw("demo-preflight", []byte("capability"))}
	token := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	initial, err := AuthorizeInitialEnrollmentPreflight(request, token)
	if err != nil || VerifyInitialEnrollmentPreflight(&initial, token) != nil {
		t.Fatal(err)
	}
	if initial.Authorization.TokenMAC == token || initial.Authorization.IdentityPublicKey != "" {
		t.Fatal("预取携带了 token 或尚未生成的设备 key")
	}
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	spki, _ := x509.MarshalPKIXPublicKey(&key.PublicKey)
	identityHash, _ := HashBytes(DomainEnrollmentIdentitySPKI, spki)
	resume, err := AuthorizeResumeEnrollmentPreflight(request, key)
	if err != nil || VerifyResumeEnrollmentPreflight(&resume, identityHash) != nil {
		t.Fatal(err)
	}
	if VerifyInitialEnrollmentPreflight(&resume, token) == nil || VerifyResumeEnrollmentPreflight(&initial, identityHash) == nil {
		t.Fatal("初次和恢复授权混用")
	}
	for name, mutate := range map[string]func(*EnrollmentIntentPreflightRequestV1){
		"cluster": func(r *EnrollmentIntentPreflightRequestV1) { r.ClusterID = "demo-other-cluster" },
		"invite":  func(r *EnrollmentIntentPreflightRequestV1) { r.InviteID = "demo-other-invite" },
		"record": func(r *EnrollmentIntentPreflightRequestV1) {
			r.CertifiedInviteRecordHash = HashRaw("demo-preflight", []byte("other-record"))
		},
		"capability": func(r *EnrollmentIntentPreflightRequestV1) {
			r.CapabilityID = HashRaw("demo-preflight", []byte("other-capability"))
		},
	} {
		t.Run(name, func(t *testing.T) {
			changed := initial
			mutate(&changed)
			if VerifyInitialEnrollmentPreflight(&changed, token) == nil {
				t.Fatal("初次授权未绑定请求")
			}
			changed = resume
			mutate(&changed)
			if VerifyResumeEnrollmentPreflight(&changed, identityHash) == nil {
				t.Fatal("恢复签名未绑定请求")
			}
		})
	}
	initial.Authorization.IdentityPublicKey = resume.Authorization.IdentityPublicKey
	if VerifyInitialEnrollmentPreflight(&initial, token) == nil {
		t.Fatal("初次请求接受混合身份字段")
	}
	resume.Authorization.TokenMAC = token
	if VerifyResumeEnrollmentPreflight(&resume, identityHash) == nil {
		t.Fatal("恢复请求接受 token 字段")
	}
}

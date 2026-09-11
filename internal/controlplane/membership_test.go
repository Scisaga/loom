package controlplane

import (
	"testing"
	"time"
)

func TestMembershipTransitionUsesCertifiedTimeForPeerCertificates(t *testing.T) {
	set, _ := testControlSet(t, 1)
	directory, _ := raftDirectoryFixture(t, set)
	validTime := time.Date(2026, 9, 11, 12, 0, 0, 0, time.UTC)

	transition, err := NewMembershipTransition("transition-1", set, set, directory, nil, validTime)
	if err != nil || transition.Phase != MembershipCandidate {
		t.Fatalf("合法目录未能建立成员变更: transition=%#v err=%v", transition, err)
	}
	if _, err := NewMembershipTransition("transition-2", set, set, directory, nil, validTime.Add(48*time.Hour)); err == nil {
		t.Fatal("成员变更接受了在认证逻辑时间已过期的 control-peer 证书")
	}
}

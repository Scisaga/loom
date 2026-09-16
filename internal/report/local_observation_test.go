package report

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
	"time"

	"loom/internal/attest"
	"loom/internal/wire"
)

func TestLocalObservationHandoffPreservesOriginalEvidence(t *testing.T) {
	at := time.Now().UTC().Truncate(time.Second)
	ca, key, certificate := reportTestIdentity(t, "demo-node")
	own := Observation{Node: "demo-node", TS: at.Format(time.RFC3339), Edges: []Edge{{To: "demo-peer", Samples: 1, RTTMs: 17}}}
	_, claim := claimsForObservation(&own, 5)
	var err error
	own.Attest, err = attest.Sign(claim, key, certificate)
	if err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	if err := os.Chmod(directory, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "node-observation.json")
	if err := SaveLocalObservation(path, &own); err != nil {
		t.Fatal(err)
	}
	want, _ := wire.MarshalCanonical(own)
	body, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(body, want) {
		t.Fatal("本机交接改变原签名或时间", err)
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatal("观测缓存没有限制权限", err)
	}
	var restored Observation
	if _, err := wire.DecodeStrict(body, 1<<20, &restored); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyObservationAtLeast(&restored, ca, at, 10*time.Minute, 5); err != nil {
		t.Fatal(err)
	}
	if err := SaveLocalObservation(path, nil); err == nil {
		t.Fatal("签名缺失时覆盖了原缓存")
	}
	if err := os.Chmod(directory, 0755); err != nil {
		t.Fatal(err)
	}
	if err := SaveLocalObservation(path, &own); err == nil {
		t.Fatal("向未保护的目录交付观测")
	}
}

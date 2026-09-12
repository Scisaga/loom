//go:build linux

package clientv2

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"loom/internal/wire"
)

func TestLinuxLinkRuntimeStateCommitsOnlyFromDurableDeviceLKG(t *testing.T) {
	now := time.Date(2026, 9, 12, 0, 0, 0, 0, time.UTC)
	deviceStatePath, identityPath, set, initial, key := installedDeviceConfigStateWithKey(t, now)
	envelope := advanceClientEnvelope(t, initial, &set, key)
	artifact := LinuxLinkIntentArtifactV1{
		Schema: 1, ClusterID: set.ClusterID, DeviceID: envelope.Payload.DeviceID,
		DeviceGeneration: envelope.Payload.DeviceGeneration, Generation: 1,
		RenderContractID: wire.LinuxLinkIntentRenderContract, AuthorityHeadHash: envelope.SignedCurrent.Head.HeadHash,
		LinkIntents: []wire.LinkIntentV1{},
	}
	artifactRaw := bindRuntimeArtifactToEnvelope(t, &envelope, &set, key, artifact)
	identity, err := LoadEnrollmentIdentityForResume(identityPath)
	if err != nil {
		t.Fatal(err)
	}
	identityHash, err := identity.IdentitySPKIHash()
	if err != nil {
		t.Fatal(err)
	}
	deviceStore, err := Open(deviceStatePath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := deviceStore.Accept(&envelope, &set, envelope.Payload.DeviceID, identityHash); err != nil {
		t.Fatal(err)
	}
	directory := filepath.Dir(deviceStatePath)
	runtimeStatePath := filepath.Join(directory, "runtime-state.json")
	state, err := AcceptLinuxLinkRuntimePlan(runtimeStatePath, deviceStatePath, &envelope, nil,
		nil, nil, artifactRaw, now)
	if err != nil {
		t.Fatal(err)
	}
	if state.Plan.Actions == nil || len(state.Plan.Actions) != 0 || state.PlanHash == "" ||
		state.AuthorityFloors.HeadHash != envelope.SignedCurrent.Head.HeadHash {
		t.Fatalf("runtime state=%#v", state)
	}
	info, _ := os.Stat(runtimeStatePath)
	if info == nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("runtime state mode=%v", info)
	}
	reloaded, err := LoadLinuxLinkRuntimeState(runtimeStatePath)
	if err != nil || !wire.EqualCanonical(*state, *reloaded) {
		t.Fatalf("offline runtime LKG 不可重载: state=%#v err=%v", reloaded, err)
	}

	before, _ := os.ReadFile(runtimeStatePath)
	otherEnvelope := envelope
	otherEnvelope.Payload.DeviceID = "other-device"
	if _, err := AcceptLinuxLinkRuntimePlan(runtimeStatePath, deviceStatePath, &otherEnvelope, nil,
		nil, nil, artifactRaw, now); err == nil {
		t.Fatal("未持久化的候选 Device view 进入 runtime state")
	}
	after, _ := os.ReadFile(runtimeStatePath)
	if !bytes.Equal(before, after) {
		t.Fatal("失败的 runtime candidate 改写了 LKG")
	}
}

func TestLinuxLinkRuntimeStateRejectsDeviceStateWithoutFormalEnrollment(t *testing.T) {
	set, key := clientControlSet(t)
	envelope := clientEnvelope(t, &set, key)
	artifact := LinuxLinkIntentArtifactV1{
		Schema: 1, ClusterID: set.ClusterID, DeviceID: envelope.Payload.DeviceID,
		DeviceGeneration: envelope.Payload.DeviceGeneration, Generation: 1,
		RenderContractID: wire.LinuxLinkIntentRenderContract, AuthorityHeadHash: envelope.SignedCurrent.Head.HeadHash,
		LinkIntents: []wire.LinkIntentV1{},
	}
	artifactRaw := bindRuntimeArtifactToEnvelope(t, &envelope, &set, key, artifact)
	directory := filepath.Join(t.TempDir(), "private")
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	deviceStatePath := filepath.Join(directory, "state.json")
	store, err := Open(deviceStatePath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.acceptWithAdvance(&envelope, &set, nil, envelope.Payload.DeviceID,
		envelope.Payload.Active.IdentitySPKIHash, wire.AdvanceFloors); err != nil {
		t.Fatal(err)
	}
	_, err = AcceptLinuxLinkRuntimePlan(filepath.Join(directory, "runtime.json"), deviceStatePath,
		&envelope, &set, nil, nil, artifactRaw, time.Date(2026, 9, 12, 0, 0, 0, 0, time.UTC))
	if err == nil || !strings.Contains(err.Error(), "enrollment installation") {
		t.Fatalf("未正式 enrollment 的 Device 生成 runtime LKG: %v", err)
	}
}

func TestLinuxRuntimeGenerationFloorsRetainObservedAndTombstonedMaximum(t *testing.T) {
	floors := map[string]int64{"removed-endpoint": 9, "edge": 1}
	bundle := wire.DeviceEndpointBundleV1{DataIngressSets: []wire.DeviceDataIngressBindingV1{{
		EndpointSet: wire.DataIngressEndpointSetV2{Endpoints: []wire.DataIngressEndpointV2{{
			EndpointID:          "edge",
			ListenerGenerations: []wire.ListenerGenerationV2{{ListenerGeneration: 2}},
			ListenerTombstones:  []wire.ListenerGenerationTombstoneV1{{ListenerGeneration: 4}},
		}}},
	}}}
	mergeLinuxEndpointGenerationFloors(floors, bundle)
	if floors["edge"] != 4 || floors["removed-endpoint"] != 9 {
		t.Fatalf("generation floors 未保留历史最大值: %#v", floors)
	}
}

//go:build linux

package control

import (
	"context"
	"encoding/binary"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestWGPortRecoveryOriginalWindowHighestAndFork(t *testing.T) {
	store, _, _ := admissionReports(t)
	key := testKey(t)
	now := time.Unix(2000000000, 0).UTC()
	makeReport := func(device string, sequence U64, at time.Time, state string) DeviceReport {
		t.Helper()
		value, err := SignDeviceReport(DeviceReport{Schema: 3, NetworkID: "demo-network", DeviceID: device, ReportSequence: sequence, ReportedAt: at.UnixMilli(), ViewDigest: "sha256:" + strings.Repeat("0", 64), NetworkGeneration: "demo-underlay", Selections: []ReportSelection{}, Observations: []Observation{}, Components: []ComponentReadback{}, Runtime: RuntimeReadback{State: state, AppliedViewDigest: "sha256:" + strings.Repeat("0", 64)}}, key)
		if err != nil {
			t.Fatal(err)
		}
		return value
	}
	originals := []DeviceReport{
		makeReport("demo-active", 1, now.Add(-3*time.Minute), "stopped"),
		makeReport("demo-active", 2, now.Add(-90*time.Second), "stopped"),
		makeReport("demo-active", 3, now.Add(-50*time.Second), "unknown"),
		makeReport("demo-active", 4, now.Add(-10*time.Second), "running"),
		makeReport("demo-stale", 7, now.Add(-4*time.Minute), "stopped"),
		makeReport("demo-unrelated", 9, now, "running"),
	}
	testSetObservationReports(t, store, originals)
	projection := Projection{NetworkID: "demo-network", DeviceAuthorizations: []DeviceAuthorization{{ID: "demo-stale"}, {ID: "demo-active"}}}
	server := &Server{Runtime: &Runtime{Reports: store}}
	read := func(at time.Time) []WGPortRecoveryReports {
		t.Helper()
		value, err := server.wgPortRecoveryReports(context.Background(), projection, at)
		if err != nil {
			t.Fatal(err)
		}
		return value
	}
	values := read(now)
	sequences := func(value WGPortRecoveryReports) []U64 {
		result := []U64{}
		for _, report := range value.Reports {
			result = append(result, report.ReportSequence)
		}
		return result
	}
	if len(values) != 2 || values[0].DeviceID != "demo-active" || values[0].Highest != 4 || !reflect.DeepEqual(sequences(values[0]), []U64{4, 3, 2}) || values[1].Highest != 7 || !reflect.DeepEqual(sequences(values[1]), []U64{7}) {
		t.Fatal("short window omitted a breaking original, included an inactive device, or lost the real stale highest", values)
	}
	fork := makeReport("demo-active", 4, now.Add(-9*time.Second), "error")
	testSetObservationReports(t, store, append(originals, fork))
	values = read(now)
	if values[0].Highest != 4 || !values[0].Forked || !reflect.DeepEqual(sequences(values[0]), []U64{3, 2}) {
		t.Fatal("highest fork selected an original or changed the persistent highest", values[0])
	}
	baseline := read(now.Add(-time.Minute))
	if baseline[0].Highest != 4 || baseline[0].Forked || !reflect.DeepEqual(sequences(baseline[0]), []U64{2, 1}) {
		t.Fatal("historical baseline admitted later reports or invented an earlier database highest", baseline[0])
	}
	afterWindow := read(now.Add(4 * time.Minute))
	if afterWindow[0].Highest != 4 || afterWindow[0].Forked || len(afterWindow[0].Reports) != 0 {
		t.Fatal("an entirely forked highest fell back to an old original outside the time window", afterWindow[0])
	}
	oldFork := makeReport("demo-active", 2, now.Add(-89*time.Second), "error")
	testSetObservationReports(t, store, append(originals, oldFork))
	historicalFork := read(now.Add(-time.Minute))
	if historicalFork[0].Highest != 4 || !historicalFork[0].Forked || !reflect.DeepEqual(sequences(historicalFork[0]), []U64{1}) {
		t.Fatal("a selected historical fork was hidden by a newer report outside the baseline window", historicalFork[0])
	}
}

func recoveryResourceHistoryFixture(t *testing.T) (*Authority, string, []Material, time.Time) {
	t.Helper()
	f := newMaterialFixture(t)
	p := relayProjectionFixture(t)
	var resource TransportResource
	for _, value := range p.NetworkIntent.Resources {
		if value.Kind == "wireguard" {
			resource = value
			break
		}
	}
	root := t.TempDir()
	if err := os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(root, "materials"), 0700); err != nil {
		t.Fatal(err)
	}
	now := time.Unix(2000000000, 0).UTC()
	ports := []int{51819, 51820, 51821, 51820, 51820}
	requests := []string{"demo-create-resource", "wg-port-recovery-demo-old", "wg-port-recovery-demo-attempt", "wg-port-recovery-restore-demo-attempt", "demo-manual-confirm"}
	ages := []time.Duration{9 * 24 * time.Hour, 8 * 24 * time.Hour, 10 * time.Minute, 9 * time.Minute, 8 * time.Minute}
	authority := &Authority{root: root, genesis: f.genesis}
	materials := []Material{}
	for index, port := range ports {
		resource.DialPort = port
		var previous *Material
		dependencies := []string{}
		if index > 0 {
			previous = &materials[index-1]
			dependencies = append(dependencies, materialTestID(t, *previous))
		}
		material := f.sign(t, 0, U64(index+1), previous, requests[index], "resource.put", "resource", resource.ID, resource, dependencies...)
		body, id, err := EncodeMaterial(material)
		if err != nil {
			t.Fatal(err)
		}
		path, _ := authority.materialPath(id)
		if err := putControlBytes(path, body); err != nil {
			t.Fatal(err)
		}
		at := binary.BigEndian.AppendUint64(nil, uint64(now.Add(-ages[index]).UnixNano()))
		if err := unix.Setxattr(path, receptionAttribute, at, 0); err != nil {
			t.Fatal(err)
		}
		materials = append(materials, material)
	}
	authority.materials = materials
	authority.projection = Projection{NetworkID: p.NetworkID, NetworkIntent: NetworkIntent{Resources: []TransportResource{resource}}, Targets: []TargetState{{TargetKind: "resource", TargetID: resource.ID, MaterialIDs: []string{materialTestID(t, materials[len(materials)-1])}}}}
	// An unrelated old manual receipt is not needed for the automatic budget.
	initial, _ := authority.materialPath(materialTestID(t, materials[0]))
	if err := unix.Removexattr(initial, receptionAttribute); err != nil {
		t.Fatal(err)
	}
	return authority, resource.ID, materials, now
}

func TestWGPortRecoveryResourceReceiptsAndExpiringAvoidance(t *testing.T) {
	authority, id, materials, now := recoveryResourceHistoryFixture(t)
	changes, err := authority.wgPortRecoveryChanges(id, now)
	if err != nil || len(changes) != 3 || changes[0].MaterialID != materialTestID(t, materials[2]) || !changes[0].Automatic || changes[1].Automatic || changes[2].Automatic {
		t.Fatal("cooldown/attempt inputs did not retain current manual head and recent automatic originals", changes, err)
	}
	ports, err := authority.wgPortRecoveryAvoidedPorts(id, now)
	if err != nil || !reflect.DeepEqual(ports, []int{51820, 51821}) {
		t.Fatal("failed original and restored candidate were not temporarily avoided, or an expired port remained blocked", ports, err)
	}
	restarted := &Authority{root: authority.root, genesis: authority.genesis, materials: append([]Material{}, authority.materials...), projection: authority.projection}
	again, err := restarted.wgPortRecoveryChanges(id, now)
	if err != nil || !reflect.DeepEqual(changes, again) {
		t.Fatal("reconstructing the authority reset the cooldown inputs", again, err)
	}
	expired, err := restarted.wgPortRecoveryAvoidedPorts(id, now.Add(8*24*time.Hour))
	if err != nil || len(expired) != 0 {
		t.Fatal("temporary avoidance became a permanent blacklist", expired, err)
	}
	atBoundary, err := restarted.wgPortRecoveryAvoidedPorts(id, now.Add(7*24*time.Hour-9*time.Minute))
	if err != nil || len(atBoundary) != 0 {
		t.Fatal("temporary avoidance did not expire at exactly seven days", atBoundary, err)
	}
}

func TestWGPortRecoveryInitialResourceUsesOriginalReceipt(t *testing.T) {
	authority, id, materials, now := recoveryResourceHistoryFixture(t)
	initialID := materialTestID(t, materials[0])
	path, _ := authority.materialPath(initialID)
	if err := unix.Setxattr(path, receptionAttribute, binary.BigEndian.AppendUint64(nil, uint64(now.Add(-time.Minute).UnixNano())), 0); err != nil {
		t.Fatal(err)
	}
	authority.materials = materials[:1]
	authority.projection.Targets[0].MaterialIDs = []string{initialID}
	changes, err := authority.wgPortRecoveryChanges(id, now)
	if err != nil || len(changes) != 1 || changes[0].MaterialID != initialID || changes[0].Automatic {
		t.Fatal("unchanged initial resource did not use its canonical put and protected original receipt", changes, err)
	}
	avoided, err := authority.wgPortRecoveryAvoidedPorts(id, now)
	if err != nil || len(avoided) != 0 {
		t.Fatal("initial resource invented automatic port history", avoided, err)
	}
}

func TestWGPortRecoveryRejectsMissingReceiptsAndAmbiguousParents(t *testing.T) {
	for _, damage := range []string{"current_receipt", "auto_receipt", "future_receipt", "missing_parent", "ambiguous_parent", "conflicted_head"} {
		t.Run(damage, func(t *testing.T) {
			authority, id, materials, now := recoveryResourceHistoryFixture(t)
			switch damage {
			case "current_receipt", "auto_receipt", "future_receipt":
				index := 2
				if damage == "current_receipt" {
					index = len(materials) - 1
				}
				path, _ := authority.materialPath(materialTestID(t, materials[index]))
				var err error
				if damage == "future_receipt" {
					err = unix.Setxattr(path, receptionAttribute, binary.BigEndian.AppendUint64(nil, uint64(now.Add(time.Second).UnixNano())), 0)
				} else {
					err = unix.Removexattr(path, receptionAttribute)
				}
				if err != nil {
					t.Fatal(err)
				}
				if _, err := authority.wgPortRecoveryChanges(id, now); err == nil {
					t.Fatal("an absent or future receipt permitted another automatic attempt")
				}
			case "missing_parent":
				authority.materials = append(materials[:1:1], materials[2:]...)
			case "ambiguous_parent":
				value := materials[2]
				value.Dependencies = append(value.Dependencies, materialTestID(t, materials[0]))
				sort.Strings(value.Dependencies)
				var err error
				value, err = SignMaterial(value, newMaterialFixture(t).keys[0])
				if err != nil {
					t.Fatal(err)
				}
				body, newID, err := EncodeMaterial(value)
				if err != nil {
					t.Fatal(err)
				}
				path, _ := authority.materialPath(newID)
				if err := putControlBytes(path, body); err != nil {
					t.Fatal(err)
				}
				if err := unix.Setxattr(path, receptionAttribute, binary.BigEndian.AppendUint64(nil, uint64(now.Add(-10*time.Minute).UnixNano())), 0); err != nil {
					t.Fatal(err)
				}
				authority.materials = append(authority.materials, value)
			case "conflicted_head":
				authority.projection.Targets[0].Conflicted = true
			}
			if _, err := authority.wgPortRecoveryAvoidedPorts(id, now); err == nil {
				t.Fatal("unsafe receipt, resource parent or current head permitted automatic reuse")
			}
		})
	}
}

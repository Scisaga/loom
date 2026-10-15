package control

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net"
	"reflect"
	"sort"
	"strconv"
	"testing"
	"time"
)

type wgRecoveryFixture struct {
	p         Projection
	now       time.Time
	keys      map[string]ed25519.PrivateKey
	link      NetworkLink
	histories []WGPortRecoveryReports
	input     WGPortRecoveryResource
}

func newWGRecoveryFixture(t *testing.T) *wgRecoveryFixture {
	t.Helper()
	f := &wgRecoveryFixture{p: relayProjectionFixture(t), now: time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC), keys: map[string]ed25519.PrivateKey{}}
	// A healthy second sender does not veto recovery of a per-pair UDP fault.
	other := f.p.DeviceAuthorizations[2]
	other.ID, other.Name = "demo-other", "Demo other"
	f.p.DeviceAuthorizations = append(f.p.DeviceAuthorizations, other)
	key := base64.RawURLEncoding.EncodeToString([]byte("cccccccccccccccccccccccccccccccc"))
	addresses := []string{"198.51.100.3/32"}
	f.p.NetworkIntent.Resources = append(f.p.NetworkIntent.Resources, TransportResource{ID: "demo-other-wg", Kind: "wireguard", OwnerNodeID: other.ID, ListenerID: "demo-other-wg", DialHost: "192.0.2.12", DialPort: 51820, Authentication: ResourceAuthentication{PublicKey: &key, LocalAddresses: &addresses}})
	sort.Slice(f.p.NetworkIntent.Resources, func(i, j int) bool { return f.p.NetworkIntent.Resources[i].ID < f.p.NetworkIntent.Resources[j].ID })
	for i := range f.p.DeviceAuthorizations {
		device := &f.p.DeviceAuthorizations[i]
		seed := sha256.Sum256([]byte(device.ID))
		key := ed25519.NewKeyFromSeed(seed[:])
		device.DevicePublicKey = base64.RawURLEncoding.EncodeToString(key.Public().(ed25519.PublicKey))
		f.keys[device.ID] = key
	}
	f.link = testDerivedLink(t, f.p, "demo-entry", "demo-exit")
	head := ReleaseDigest([]byte("demo-current-resource"))
	f.p.Targets = append(f.p.Targets, TargetState{TargetKind: "resource", TargetID: f.link.ResourceID, MaterialIDs: []string{head}})
	f.input = WGPortRecoveryResource{ResourceID: f.link.ResourceID, Ports: []int{51820, 51822, 51821}, Changes: []WGPortRecoveryChange{{MaterialID: head, ReceivedAt: f.now.Add(-10 * time.Minute)}}}
	for i, before := range []time.Duration{41 * time.Second, 21 * time.Second, time.Second} {
		at := f.now.Add(-before)
		sample := f.sample(t, f.link, at, "unavailable")
		report := f.report(t, "demo-entry", U64(i+1), at, []Observation{sample})
		if i == 0 {
			f.histories = append(f.histories, WGPortRecoveryReports{DeviceID: report.DeviceID, Highest: 3})
		}
		f.histories[0].Reports = append(f.histories[0].Reports, report)
	}
	for _, id := range []string{"demo-exit", "demo-other"} {
		samples := []Observation{}
		if id == "demo-other" {
			link := testDerivedLink(t, f.p, id, "demo-exit")
			samples = append(samples, f.sample(t, link, f.now.Add(-time.Second), "available"))
		}
		f.histories = append(f.histories, WGPortRecoveryReports{DeviceID: id, Highest: 1, Reports: []DeviceReport{f.report(t, id, 1, f.now, samples)}})
	}
	return f
}

func (f *wgRecoveryFixture) sample(t *testing.T, link NetworkLink, at time.Time, result string) Observation {
	t.Helper()
	view, err := ProjectDeviceView(f.p, link.FromNodeID)
	if err != nil {
		t.Fatal(err)
	}
	spec, err := LinkSpecDigest(view, link.ID)
	if err != nil {
		t.Fatal(err)
	}
	return Observation{Level: "link", ResourceID: link.ResourceID, LinkID: link.ID, SpecDigest: spec, Target: net.JoinHostPort(link.ProbeTarget.Host, "53"), Action: "wireguard_dns", NetworkGeneration: "demo-underlay", Result: result, ObservedAt: at.UnixMilli(), ValidUntil: at.Add(30 * time.Second).UnixMilli()}
}

func (f *wgRecoveryFixture) report(t *testing.T, id string, sequence U64, at time.Time, samples []Observation) DeviceReport {
	t.Helper()
	view, err := ProjectDeviceView(f.p, id)
	if err != nil {
		t.Fatal(err)
	}
	digest, err := DeviceViewDigest(view)
	if err != nil {
		t.Fatal(err)
	}
	resources := []ResourceReadback{}
	for _, resource := range view.Resources {
		if resource.OwnerNodeID != id {
			continue
		}
		acl, err := InboundACLDigest(view, resource.ID)
		if err != nil {
			t.Fatal(err)
		}
		value := ResourceReadback{ResourceID: resource.ID, ListenerID: resource.ListenerID, Listen: net.JoinHostPort("0.0.0.0", strconv.Itoa(resource.DialPort)), ACLDigest: acl, CertificateDigest: ReleaseDigest([]byte("demo-certificate"))}
		if resource.Kind == "wireguard" {
			value.CertificateDigest, value.PublicKey = "", *resource.Authentication.PublicKey
		}
		resources = append(resources, value)
	}
	report := DeviceReport{Schema: 3, NetworkID: f.p.NetworkID, DeviceID: id, ReportSequence: sequence, ViewDigest: digest, NetworkGeneration: "demo-underlay", ReportedAt: at.UnixMilli(), Selections: []ReportSelection{}, Observations: samples, Runtime: RuntimeReadback{State: "running", AppliedViewDigest: digest, Resources: &resources}, Components: []ComponentReadback{}}
	if len(resources) == 0 {
		report.Runtime.Resources = nil
	}
	return f.sign(t, report)
}

func (f *wgRecoveryFixture) sign(t *testing.T, report DeviceReport) DeviceReport {
	t.Helper()
	result, err := SignDeviceReport(report, f.keys[report.DeviceID])
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func (f *wgRecoveryFixture) change(t *testing.T, history, index int, change func(*DeviceReport)) {
	t.Helper()
	report := f.histories[history].Reports[index]
	change(&report)
	f.histories[history].Reports[index] = f.sign(t, report)
}

func TestWGPortRecoveryUsesOriginalSustainedFailureWithoutChangingAuthority(t *testing.T) {
	f := newWGRecoveryFixture(t)
	before, err := json.Marshal(f.p)
	if err != nil {
		t.Fatal(err)
	}
	got, err := WGPortRecovery(f.p, f.histories, []WGPortRecoveryResource{f.input}, f.now)
	want := []WGPortRecoverySuggestion{{ResourceID: f.link.ResourceID, FromPort: 51820, ToPort: 51822, LinkID: f.link.ID, SourceNodeID: "demo-entry", FailureSince: f.now.Add(-41 * time.Second).UnixMilli()}}
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatal("sustained pair failure did not propose the first allowed new port", err, got)
	}
	after, _ := json.Marshal(f.p)
	if string(before) != string(after) {
		t.Fatal("pure recovery proposal changed authority")
	}
	// Historical samples have expired now, but were valid original failures at
	// their report times. Repeated projections and unordered input are identical.
	for i, j := 0, len(f.histories[0].Reports)-1; i < j; i, j = i+1, j-1 {
		f.histories[0].Reports[i], f.histories[0].Reports[j] = f.histories[0].Reports[j], f.histories[0].Reports[i]
	}
	f.histories[0].Reports = append(f.histories[0].Reports, f.histories[0].Reports[0])
	again, err := WGPortRecovery(f.p, f.histories, []WGPortRecoveryResource{f.input}, f.now)
	if err != nil || !reflect.DeepEqual(got, again) {
		t.Fatal("input order, duplicate originals or policy restart changed the proposal", err, again)
	}
}

func TestWGPortRecoveryRejectsInsufficientOrUnqualifiedFailure(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*testing.T, *wgRecoveryFixture)
	}{
		{"unknown breaks streak", func(t *testing.T, f *wgRecoveryFixture) {
			f.change(t, 0, 1, func(r *DeviceReport) { r.Observations[0].Result = "unknown" })
		}},
		{"success breaks streak", func(t *testing.T, f *wgRecoveryFixture) {
			f.change(t, 0, 1, func(r *DeviceReport) { r.Observations[0].Result = "available" })
		}},
		{"absent sample breaks streak", func(t *testing.T, f *wgRecoveryFixture) {
			f.change(t, 0, 1, func(r *DeviceReport) { r.Observations = []Observation{} })
		}},
		{"wrong spec breaks streak", func(t *testing.T, f *wgRecoveryFixture) {
			f.change(t, 0, 1, func(r *DeviceReport) { r.Observations[0].SpecDigest = ReleaseDigest([]byte("demo-old-spec")) })
		}},
		{"wrong view", func(t *testing.T, f *wgRecoveryFixture) {
			f.change(t, 0, 2, func(r *DeviceReport) { r.ViewDigest = ReleaseDigest([]byte("demo-old-view")) })
		}},
		{"source generation changed", func(t *testing.T, f *wgRecoveryFixture) {
			f.change(t, 0, 1, func(r *DeviceReport) {
				r.NetworkGeneration = "demo-other-underlay"
				r.Observations[0].NetworkGeneration = r.NetworkGeneration
			})
		}},
		{"bad original signature", func(t *testing.T, f *wgRecoveryFixture) {
			f.histories[0].Reports[1].Signature = "demo-invalid-signature"
		}},
		{"latest fork cannot fall back", func(t *testing.T, f *wgRecoveryFixture) {
			other := f.histories[0].Reports[2]
			other.Observations = append([]Observation{}, other.Observations...)
			other.Observations[0].Result = "available"
			f.histories[0].Reports = append(f.histories[0].Reports, f.sign(t, other))
		}},
		{"missing highest cannot fall back", func(t *testing.T, f *wgRecoveryFixture) { f.histories[0].Highest++ }},
		{"missing sequence breaks streak", func(t *testing.T, f *wgRecoveryFixture) {
			f.histories[0].Highest = 5
			f.change(t, 0, 2, func(r *DeviceReport) { r.ReportSequence = 5 })
		}},
		{"two failures insufficient", func(t *testing.T, f *wgRecoveryFixture) { f.histories[0].Reports = f.histories[0].Reports[1:] }},
		{"brief burst insufficient", func(t *testing.T, f *wgRecoveryFixture) {
			for i := range f.histories[0].Reports {
				at := f.now.Add(-time.Duration(3-i) * time.Second)
				f.histories[0].Reports[i] = f.report(t, "demo-entry", U64(i+1), at, []Observation{f.sample(t, f.link, at, "unavailable")})
			}
		}},
		{"repeated sample not three failures", func(t *testing.T, f *wgRecoveryFixture) {
			at := f.now.Add(-time.Second)
			for i := range f.histories[0].Reports {
				f.histories[0].Reports[i] = f.report(t, "demo-entry", U64(i+1), at, []Observation{f.sample(t, f.link, at, "unavailable")})
			}
		}},
		{"long gap breaks streak", func(t *testing.T, f *wgRecoveryFixture) {
			at := f.now.Add(-100 * time.Second)
			f.histories[0].Reports[0] = f.report(t, "demo-entry", 1, at, []Observation{f.sample(t, f.link, at, "unavailable")})
		}},
		{"expired latest", func(t *testing.T, f *wgRecoveryFixture) { f.now = f.now.Add(30 * time.Second) }},
		{"source stopped", func(t *testing.T, f *wgRecoveryFixture) {
			f.change(t, 0, 2, func(r *DeviceReport) { r.Runtime = RuntimeReadback{State: "stopped"} })
		}},
		{"receiver stopped", func(t *testing.T, f *wgRecoveryFixture) {
			f.change(t, 1, 0, func(r *DeviceReport) { r.Runtime = RuntimeReadback{State: "stopped"} })
		}},
		{"receiver stale", func(t *testing.T, f *wgRecoveryFixture) {
			f.change(t, 1, 0, func(r *DeviceReport) { r.ReportedAt = f.now.Add(-3 * time.Minute).UnixMilli() })
		}},
		{"receiver old listener port", func(t *testing.T, f *wgRecoveryFixture) {
			f.change(t, 1, 0, func(r *DeviceReport) {
				for i := range *r.Runtime.Resources {
					if (*r.Runtime.Resources)[i].ResourceID == f.input.ResourceID {
						(*r.Runtime.Resources)[i].Listen = "0.0.0.0:51819"
					}
				}
			})
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newWGRecoveryFixture(t)
			tc.change(t, f)
			got, err := WGPortRecovery(f.p, f.histories, []WGPortRecoveryResource{f.input}, f.now)
			if err != nil || len(got) != 0 {
				t.Fatal("unqualified evidence proposed a port update", err, got)
			}
		})
	}
}

func TestWGPortRecoveryLimitsDeriveFromExistingDurableFacts(t *testing.T) {
	for _, tc := range []struct {
		name string
		edit func(*wgRecoveryFixture)
		want bool
	}{
		{"cooldown", func(f *wgRecoveryFixture) {
			f.input.Changes[0].ReceivedAt = f.now.Add(-3*time.Minute + time.Millisecond)
		}, false},
		{"cooldown boundary", func(f *wgRecoveryFixture) { f.input.Changes[0].ReceivedAt = f.now.Add(-3 * time.Minute) }, true},
		{"missing receipt", func(f *wgRecoveryFixture) { f.input.Changes = nil }, false},
		{"zero receipt", func(f *wgRecoveryFixture) { f.input.Changes[0].ReceivedAt = time.Time{} }, false},
		{"future receipt", func(f *wgRecoveryFixture) { f.input.Changes[0].ReceivedAt = f.now.Add(time.Second) }, false},
		{"three automatic attempts", func(f *wgRecoveryFixture) {
			for _, label := range []string{"demo-attempt-one", "demo-attempt-two", "demo-attempt-three"} {
				f.input.Changes = append(f.input.Changes, WGPortRecoveryChange{MaterialID: ReleaseDigest([]byte(label)), ReceivedAt: f.now.Add(-20 * time.Minute), Automatic: true})
			}
		}, false},
		{"manual changes do not consume automatic budget", func(f *wgRecoveryFixture) {
			for _, label := range []string{"demo-manual-one", "demo-manual-two", "demo-manual-three"} {
				f.input.Changes = append(f.input.Changes, WGPortRecoveryChange{MaterialID: ReleaseDigest([]byte(label)), ReceivedAt: f.now.Add(-20 * time.Minute)})
			}
		}, true},
		{"expired attempt and duplicate receipt", func(f *wgRecoveryFixture) {
			change := WGPortRecoveryChange{MaterialID: ReleaseDigest([]byte("demo-attempt")), ReceivedAt: f.now.Add(-time.Hour - time.Millisecond), Automatic: true}
			f.input.Changes = append(f.input.Changes, change, change, change)
		}, true},
		{"no alternate mapped port", func(f *wgRecoveryFixture) { f.input.Ports = []int{51820} }, false},
		{"conflicted current resource", func(f *wgRecoveryFixture) { f.p.Targets[len(f.p.Targets)-1].Conflicted = true }, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newWGRecoveryFixture(t)
			tc.edit(f)
			got, err := WGPortRecovery(f.p, f.histories, []WGPortRecoveryResource{f.input}, f.now)
			if err != nil || (len(got) == 1) != tc.want {
				t.Fatal("existing fact timing did not enforce the durable bound", err, got)
			}
		})
	}
}

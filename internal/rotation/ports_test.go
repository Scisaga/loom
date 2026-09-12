package rotation

import (
	"strings"
	"testing"

	"loom/internal/wire"
)

func TestMappingReservationsQuarantineBeforeDeterministicReuse(t *testing.T) {
	mapping := mappingReservationFixture()
	state, err := NewMappingReservationSet("cluster", mapping)
	if err != nil {
		t.Fatal(err)
	}
	firstIntent := mappingReservationIntent(t, "rotation-a", 2, mapping)
	state, first, err := AllocateMappingReservation(firstIntent, mapping, state,
		"2026-01-01T00:00:00Z", testHash)
	if err != nil || first.PublicTuple.Port != 41000 || first.LocalTuple.Port != 51000 {
		t.Fatalf("first allocation=%#v err=%v", first, err)
	}
	// 同一 rotation 的重试必须返回 first result，不能偷偷换下一个端口。
	replayed, replayedReservation, err := AllocateMappingReservation(firstIntent, mapping, state,
		"2026-01-01T00:00:10Z", strings.Replace(testHash, "11", "22", 1))
	if err != nil || !wire.EqualCanonical(state, replayed) || !wire.EqualCanonical(first, replayedReservation) {
		t.Fatalf("allocation replay changed result: %#v err=%v", replayedReservation, err)
	}
	state, err = QuarantineMappingReservation(state, mapping, "rotation-a",
		"2026-01-01T00:01:00Z", "2026-01-01T00:05:00Z", strings.Replace(testHash, "11", "33", 1))
	if err != nil {
		t.Fatal(err)
	}
	secondIntent := mappingReservationIntent(t, "rotation-b", 3, mapping)
	state, second, err := AllocateMappingReservation(secondIntent, mapping, state,
		"2026-01-01T00:02:00Z", strings.Replace(testHash, "11", "44", 1))
	if err != nil || second.PublicTuple.Port != 41001 || second.LocalTuple.Port != 51001 {
		t.Fatalf("quarantine was reused early: %#v err=%v", second, err)
	}
	thirdIntent := mappingReservationIntent(t, "rotation-c", 4, mapping)
	if _, _, err := AllocateMappingReservation(thirdIntent, mapping, state,
		"2026-01-01T00:04:59Z", strings.Replace(testHash, "11", "55", 1)); err == nil {
		t.Fatal("pool exhaustion before quarantine deadline was accepted")
	}
	state, third, err := AllocateMappingReservation(thirdIntent, mapping, state,
		"2026-01-01T00:05:00Z", strings.Replace(testHash, "11", "55", 1))
	if err != nil || third.PublicTuple != first.PublicTuple || third.LocalTuple != first.LocalTuple {
		t.Fatalf("expired quarantine was not reused deterministically: %#v err=%v", third, err)
	}
	if _, err := MappingReservationSetHash(&state, &mapping); err != nil {
		t.Fatal(err)
	}
}

func TestBlockedMappingReservationCannotBeReusedOrUnblocked(t *testing.T) {
	mapping := mappingReservationFixture()
	state, err := NewMappingReservationSet("cluster", mapping)
	if err != nil {
		t.Fatal(err)
	}
	firstIntent := mappingReservationIntent(t, "rotation-a", 2, mapping)
	state, first, err := AllocateMappingReservation(firstIntent, mapping, state,
		"2026-01-01T00:00:00Z", testHash)
	if err != nil {
		t.Fatal(err)
	}
	blockHead := strings.Replace(testHash, "11", "22", 1)
	state, err = BlockMappingReservation(state, mapping, "rotation-a",
		"2026-01-01T00:01:00Z", blockHead)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := BlockMappingReservation(state, mapping, "rotation-a",
		"2026-01-01T00:01:00Z", blockHead); err != nil {
		t.Fatalf("exact blocked transition replay was not idempotent: %v", err)
	}
	if _, err := QuarantineMappingReservation(state, mapping, "rotation-a",
		"2026-01-01T00:02:00Z", "2026-01-01T00:03:00Z", testHash); err == nil {
		t.Fatal("blocked reservation was unblocked through quarantine")
	}
	secondIntent := mappingReservationIntent(t, "rotation-b", 3, mapping)
	_, second, err := AllocateMappingReservation(secondIntent, mapping, state,
		"2036-01-01T00:00:00Z", strings.Replace(testHash, "11", "33", 1))
	if err != nil || second.PublicTuple == first.PublicTuple || second.LocalTuple == first.LocalTuple {
		t.Fatalf("blocked tuple was reused: first=%#v second=%#v err=%v", first, second, err)
	}
}

func TestMappingReservationRejectsMutableMappingAndOverlappingHistory(t *testing.T) {
	mapping := mappingReservationFixture()
	state, err := NewMappingReservationSet("cluster", mapping)
	if err != nil {
		t.Fatal(err)
	}
	intent := mappingReservationIntent(t, "rotation-a", 2, mapping)
	state, _, err = AllocateMappingReservation(intent, mapping, state,
		"2026-01-01T00:00:00Z", testHash)
	if err != nil {
		t.Fatal(err)
	}
	changed := mapping
	changed.LocalPortStart++
	changed.LocalPortEnd++
	if _, _, err := AllocateMappingReservation(mappingReservationIntent(t, "rotation-b", 3, changed),
		changed, state, "2026-01-01T00:01:00Z", testHash); err == nil {
		t.Fatal("mutable latest mapping replaced frozen reservation set")
	}

	broken := cloneMappingReservationSet(state)
	copy := broken.Reservations[0]
	copy.RotationID = "rotation-b"
	copy.ListenerGeneration++
	copy.AllocatedAt = "2026-01-01T00:01:00Z"
	copy.LastTransitionAt = copy.AllocatedAt
	broken.Reservations = append(broken.Reservations, copy)
	if _, err := MappingReservationSetHash(&broken, &mapping); err == nil {
		t.Fatal("overlapping tuple ownership was accepted")
	}
}

func mappingReservationFixture() wire.PortMappingIntentV1 {
	return wire.PortMappingIntentV1{Schema: 1, MappingID: "hy2-pool", Transport: "udp",
		PublicAddress: "203.0.113.1", PublicPortStart: 41000, PublicPortEnd: 41001,
		LocalAddress: "10.0.0.2", LocalPortStart: 51000, LocalPortEnd: 51001,
		MappingGeneration: 1}
}

func mappingReservationIntent(t *testing.T, rotationID string, generation int64,
	mapping wire.PortMappingIntentV1) IntentV1 {
	t.Helper()
	intent := testIntent(t)
	intent.RotationID = rotationID
	intent.FrozenDependencies.TargetListenerGeneration = generation
	mappingHash, err := wire.PortMappingIntentHash(&mapping)
	if err != nil {
		t.Fatal(err)
	}
	intent.FrozenDependencies.PortMappingIntentHash = mappingHash
	intent.FrozenDependenciesHash, err = wire.HashObject(DomainFrozenDependencies, intent.FrozenDependencies)
	if err != nil {
		t.Fatal(err)
	}
	return intent
}

package report

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"loom/internal/attest"
	"loom/internal/nodepresence"
	"loom/internal/webui"
)

func serverPresenceFixture(t *testing.T) (*table, []byte, time.Time) {
	t.Helper()
	now := time.Date(2026, 9, 14, 8, 30, 0, 0, time.UTC)
	_, key, certificate := reportTestIdentity(t, "demo-peer")
	observation := &Observation{Node: "demo-peer", TS: now.Format(time.RFC3339), Applied: "snapshot-v5"}
	_, claim := claimsForObservation(observation, 5)
	var err error
	observation.Attest, err = attest.Sign(claim, key, certificate)
	if err != nil {
		t.Fatal(err)
	}
	observation.SelfCheck, err = attest.SignSelfCheck(attest.SelfCheckClaim{
		Version: attest.SelfCheckClaimVersion, Node: observation.Node, TS: observation.TS, Healthy: true,
	}, key, certificate)
	if err != nil {
		t.Fatal(err)
	}
	table := newTable(5)
	table.by[observation.Node] = observation
	return table, key, now
}

func postPresenceBatch(t *testing.T, handler http.Handler, body any) *httptest.ResponseRecorder {
	t.Helper()
	wire, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "/presence", bytes.NewReader(wire))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return response
}

func TestServerPresenceRelayUsesPinnedObservationIdentity(t *testing.T) {
	table, key, now := serverPresenceFixture(t)
	receiver := newServerPresenceReceiver(table, &Config{
		Node: "demo-control", ExpectedNodes: []string{"demo-control", "demo-peer"},
	}, func() time.Time { return now })
	heartbeat, err := nodepresence.Sign("demo-peer", now, key)
	if err != nil {
		t.Fatal(err)
	}
	changes := table.changes()
	response := postPresenceBatch(t, receiver, presenceBatch{Heartbeats: []nodepresence.Heartbeat{heartbeat}})
	if response.Code != http.StatusNoContent || response.Body.Len() != 0 {
		t.Fatalf("服务端心跳转发响应=%d %q", response.Code, response.Body.String())
	}
	select {
	case <-changes:
	default:
		t.Fatal("服务端心跳没有唤醒 Device WebSocket")
	}
	view := webui.View{Nodes: []webui.NodeView{{ID: "demo-peer"}}}
	attachPresenceView(table, &view)
	if view.Nodes[0].PresenceAt != heartbeat.TS || table.by["demo-peer"].TS != now.Format(time.RFC3339) {
		t.Fatalf("presence/Observation 时钟被混用: node=%+v observation=%+v", view.Nodes[0], table.by["demo-peer"])
	}
}

func TestServerPresenceRelayRejectsUnknownIdentityTamperAndExtraFields(t *testing.T) {
	table, key, now := serverPresenceFixture(t)
	receiver := newServerPresenceReceiver(table, &Config{
		Node: "demo-control", ExpectedNodes: []string{"demo-control", "demo-peer"},
	}, func() time.Time { return now })
	heartbeat, _ := nodepresence.Sign("demo-peer", now, key)

	tampered := heartbeat
	tampered.Node = "demo-unknown"
	if got := postPresenceBatch(t, receiver, presenceBatch{Heartbeats: []nodepresence.Heartbeat{tampered}}); got.Code != http.StatusForbidden {
		t.Fatalf("未知身份心跳响应=%d %q", got.Code, got.Body.String())
	}
	body := map[string]any{"heartbeats": []map[string]any{{
		"node": heartbeat.Node, "ts": heartbeat.TS, "signature": heartbeat.Signature,
		"health": "healthy",
	}}}
	if got := postPresenceBatch(t, receiver, body); got.Code != http.StatusBadRequest {
		t.Fatalf("夹带观测字段的转发响应=%d %q", got.Code, got.Body.String())
	}
}

func TestPresenceReplayCannotExtendLeaseOrNotifyAgain(t *testing.T) {
	table, key, now := serverPresenceFixture(t)
	heartbeat, _ := nodepresence.Sign("demo-peer", now, key)
	if !table.putPresenceVerified(heartbeat, now) {
		t.Fatal("首个心跳未入表")
	}
	changes := table.changes()
	if table.putPresenceVerified(heartbeat, now.Add(time.Second)) {
		t.Fatal("重放心跳推进了在线租约")
	}
	select {
	case <-changes:
		t.Fatal("重放心跳错误唤醒了 Device WebSocket")
	default:
	}
}

func TestPresenceLeaseUsesAcceptanceTimeInsteadOfDeviceClock(t *testing.T) {
	table, key, now := serverPresenceFixture(t)
	heartbeat, _ := nodepresence.Sign("demo-peer", now.Add(-10*time.Second), key)
	if !table.putPresenceVerified(heartbeat, now) {
		t.Fatal("带合法时钟偏差的心跳未入表")
	}
	if got := table.presenceView()[heartbeat.Node]; got != now.Format(time.RFC3339Nano) {
		t.Fatalf("在线租约时间=%q, want 接受时间 %q", got, now.Format(time.RFC3339Nano))
	}
}

func TestPresenceRelayQueueOnlyReturnsNewLatestHeartbeats(t *testing.T) {
	table, key, now := serverPresenceFixture(t)
	first, _ := nodepresence.Sign("demo-peer", now, key)
	second, _ := nodepresence.Sign("demo-peer", now.Add(time.Second), key)
	if !table.putPresenceVerified(first, now) || !table.putPresenceVerified(second, now.Add(time.Second)) {
		t.Fatal("合法递增心跳未进入转发队列")
	}
	got := table.takePendingPresences(nodepresence.MaxBatchEntries)
	if len(got) != 1 || got[0] != second {
		t.Fatalf("转发队列重复携带旧心跳:%+v", got)
	}
	if got := table.takePendingPresences(nodepresence.MaxBatchEntries); len(got) != 0 {
		t.Fatalf("已转发心跳再次进入批次:%+v", got)
	}
}

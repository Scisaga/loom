package report

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"loom/internal/wire"
)

func TestDeviceObservationSocketPreservesSignedBytesAndRestrictsScope(t *testing.T) {
	h := newClientReportHarnessFor(t, "phone", "android")
	want := seedClientServerObservation(t, &h, "demo-server")
	seedClientServerObservation(t, &h, "demo-other")
	ca, err := h.receiver.readCA("")
	if err != nil {
		t.Fatal(err)
	}
	h.table.caOnce.Do(func() { h.table.ca = ca })
	handler := deviceObservationSocketHandler(http.NotFoundHandler(), h.table, func() time.Time { return h.now }, h.receiver.maxAge)
	query, _ := wire.MarshalCanonical(wire.DeviceObservationQueryV1{Schema: 1, Servers: []string{"demo-server"}})
	request := httptest.NewRequest(http.MethodPost, wire.LocalDeviceObservationsPath, bytes.NewReader(query))
	request.Header.Set("Content-Type", "application/json")
	reply := httptest.NewRecorder()
	handler.ServeHTTP(reply, request)
	var got []Observation
	if reply.Code != http.StatusOK || json.Unmarshal(reply.Body.Bytes(), &got) != nil || len(got) != 1 ||
		!wire.EqualCanonical(got[0], want) {
		t.Fatalf("私有快照丢失签名或超出范围: HTTP %d", reply.Code)
	}
	// 缓存内容损坏不能借由 root-only transport 获得新的观测 authority。
	h.table.by[want.Node].Edges[0].RTTMs++
	reply = httptest.NewRecorder()
	request = httptest.NewRequest(http.MethodPost, wire.LocalDeviceObservationsPath, bytes.NewReader(query))
	request.Header.Set("Content-Type", "application/json")
	handler.ServeHTTP(reply, request)
	if reply.Code != http.StatusOK || reply.Body.String() != "[]" {
		t.Fatal("损坏的签名观测仍被转述")
	}
}

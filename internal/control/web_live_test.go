package control

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

func webDeltaFixture(t *testing.T) ([]byte, []byte, []byte) {
	t.Helper()
	type row struct {
		ID       string  `json:"id"`
		Name     string  `json:"name"`
		Count    string  `json:"count"`
		Optional *string `json:"optional,omitempty"`
	}
	value := "demo-value"
	rows := make([]row, 128)
	for i := range rows {
		rows[i] = row{fmt.Sprintf("demo-device-%03d", i), strings.Repeat("Demo unchanged value ", 32), "18446744073709551615", &value}
	}
	first, _ := json.Marshal(map[string]any{"schema": 3, "devices": rows, "nullable": "demo-before", "list": []int{1, 2}})
	rows[71].Count = "18446744073709551614"
	rows[71].Optional = nil
	second, _ := json.Marshal(map[string]any{"schema": 3, "devices": rows, "nullable": nil, "list": []int{1, 2, 3}})
	delta, err := encodeWebLive(first, second)
	if err != nil {
		t.Fatal(err)
	}
	return first, second, delta
}
func TestWebLiveDeltaBytesAndPrecision(t *testing.T) {
	first, second, delta := webDeltaFixture(t)
	var message webLiveMessage
	if err := json.Unmarshal(delta, &message); err != nil || message.Schema != 3 || len(message.Changes) != 4 || len(message.Snapshot) != 0 {
		t.Fatal("not one canonical live changes envelope", err, string(delta))
	}
	if len(delta) > 700 || len(delta)*100 >= len(second) {
		t.Fatal("small changes resent stable snapshot", len(delta), len(second))
	}
	if !bytes.Contains(delta, []byte("18446744073709551614")) || !bytes.Contains(delta, []byte(`"value":null`)) || !bytes.Contains(delta, []byte(`"remove":true`)) {
		t.Fatal("delta lost exact value or deletion/null distinction")
	}
	if unchanged, err := encodeWebLive(second, second); err != nil || unchanged != nil {
		t.Fatal("unchanged snapshot produced traffic", err)
	}
	for _, previous := range [][]byte{nil, []byte(`{"schema":3}`)} {
		full, err := encodeWebLive(previous, first)
		if err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(full, &message); err != nil || !bytes.Equal(message.Snapshot, first) {
			t.Fatal("initial or larger delta did not send full snapshot", err)
		}
	}
	reserved, err := encodeWebLive([]byte(`{"schema":3,"map":{"constructor":1}}`), []byte(`{"schema":3,"map":{"constructor":2}}`))
	if err != nil || !bytes.Contains(reserved, []byte(`"snapshot":`)) {
		t.Fatal("reserved object key produced an unsafe path", err)
	}
	t.Log("full snapshot bytes", len(second), "delta bytes", len(delta))
}

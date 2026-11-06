package clientadapter

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

func TestWireGuardListenerPortUpdatesPreserveOtherRuntimeFacilities(t *testing.T) {
	const before = `{"endpoints":[{"type":"wireguard","tag":"wg-shared","listen_port":45000,"private_key":"demo-key","execution":{"policies":["demo-policy"]},"peers":[]}],"inbounds":[{"type":"hysteria2","tag":"demo-hy2","listen":"192.0.2.10","listen_port":443,"execution":{"policies":["demo-policy"]},"users":[]}],"route":{"final":"reject"}}`
	after := strings.Replace(before, "45000", "45001", 1)
	changes, hot, err := ReceiverChanges(before, after)
	if err != nil || !hot || len(changes) != 1 || changes[0].Tag != "wg-shared" {
		t.Fatal("WG socket port update replaced unrelated facilities", hot, err)
	}
	listener, ok := changes[0].Projection["wireguard_listener"].(map[string]any)
	if !ok || listener["port"] != float64(45001) || len(changes[0].Projection) != 3 {
		t.Fatal("receiver update omitted its complete local listener")
	}
	updated, err := WithReceiverChanges(before, changes)
	var actual, wanted any
	if err != nil || json.Unmarshal([]byte(updated), &actual) != nil || json.Unmarshal([]byte(after), &wanted) != nil || !reflect.DeepEqual(actual, wanted) {
		t.Fatal("listener update changed Hy2, identity or permissions", err)
	}
	for _, address := range []string{"demo-other-key"} {
		changed := strings.Replace(after, "demo-key", address, 1)
		if _, hot, err := ReceiverChanges(before, changed); err != nil || hot {
			t.Fatal("identity change pretended to be a port-only hot update", hot, err)
		}
	}
	delete(changes[0].Projection, "wireguard_listener")
	if _, err := WithReceiverChanges(before, changes); err == nil {
		t.Fatal("managed receiver update accepted a missing listener")
	}
}

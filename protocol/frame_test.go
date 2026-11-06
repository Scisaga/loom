package protocol

import (
	"bytes"
	"encoding/binary"
	"net/netip"
	"reflect"
	"testing"
)

func TestExecutionFramesPreserveContextTargetAndChallenge(t *testing.T) {
	nonce := [16]byte{1, 2, 3}
	for _, request := range []Request{{Operation: TransportEcho, Nonce: nonce}, {Operation: AdmissionEcho, PolicyID: "demo-policy", Nonce: nonce}, {Operation: ResolveTarget, PolicyID: "demo-policy", Nonce: nonce, Context: &PathContext{"demo-access", "demo-exit", []string{"demo-entry"}}, Host: "demo.example", Port: 8443}, {Operation: ConnectTCP, PolicyID: "demo-policy", Nonce: nonce, Context: &PathContext{"demo-access", "demo-exit", []string{}}, Host: "2001:db8::1", Port: 443}, {Operation: RegisterUDP, PolicyID: "demo-policy", Nonce: nonce, Context: &PathContext{"demo-access", "demo-exit", []string{}}, Host: "demo.example", Port: 443, SessionID: 987}} {
		body, err := request.Marshal(8)
		if err != nil {
			t.Fatal(err)
		}
		var stream bytes.Buffer
		if err := WriteFrame(&stream, body); err != nil {
			t.Fatal(err)
		}
		original, err := ReadFrame(&stream, 1024)
		if err != nil || !bytes.Equal(original, body) {
			t.Fatal("framing changed request", err)
		}
		decoded, err := UnmarshalRequest(original, 8)
		if err != nil || !reflect.DeepEqual(decoded, request) {
			t.Fatal("target or path was lost", decoded, err)
		}
		for _, bad := range [][]byte{body[:len(body)-1], append(append([]byte{}, body...), 0), append([]byte{'L', 'O', 'O', 'M', 4}, body[5:]...)} {
			if _, err := UnmarshalRequest(bad, 8); err == nil {
				t.Fatal("malformed request accepted")
			}
		}
	}
	for _, response := range []Response{{Nonce: nonce, Status: Accepted, ProcessingNanos: 123}, {Nonce: nonce, Status: Accepted, Address: netip.MustParseAddr("fdab::1")}, {Nonce: nonce, Status: Denied}} {
		body, err := response.Marshal()
		if err != nil {
			t.Fatal(err)
		}
		got, err := UnmarshalResponse(body, nonce)
		if err != nil || got != response {
			t.Fatal("response lost its meaning", got, err)
		}
		if _, err := UnmarshalResponse(body, [16]byte{9}); err == nil {
			t.Fatal("another request's response was accepted")
		}
	}
	header := binary.BigEndian.AppendUint32(nil, MaxFrameBytes+1)
	if _, err := ReadFrame(bytes.NewReader(header), 1024); err == nil {
		t.Fatal("oversized frame was allocated")
	}
	malicious := Request{Operation: AdmissionEcho, PolicyID: "demo-policy", Nonce: nonce, Host: "demo.example", Port: 443}
	if _, err := malicious.Marshal(8); err == nil {
		t.Fatal("admission measurement granted business forwarding")
	}
}

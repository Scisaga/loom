package control

import (
	"bytes"
	"encoding/json"
	"io"
	"reflect"
	"strings"
	"testing"
)

type contractMutatingValue struct {
	Value *string `json:"value"`
}

func (value contractMutatingValue) Validate() error {
	if value.Value != nil {
		*value.Value = "demo-normalized"
	}
	return nil
}

func TestContractDecodeStillChecksTypedBytesAfterValidation(t *testing.T) {
	text := "demo-preserved"
	value := contractMutatingValue{Value: &text}
	if err := DecodeCanonical([]byte(`{"value":"demo-original"}`), &value, contractTestLimits); err == nil {
		t.Fatal("a mutating validator bypassed the typed canonical round trip")
	}
	if value.Value != &text || text != "demo-preserved" {
		t.Fatal("failed decoding changed the caller's value")
	}
	if err := DecodeCanonical([]byte(`{"value":"demo-normalized"}`), &value, contractTestLimits); err != nil || *value.Value != "demo-normalized" {
		t.Fatal("unchanged typed bytes were rejected", err)
	}
}

func TestContractByteParserKeepsCanonicalEscapesAndKeyOrder(t *testing.T) {
	text := "\"\\/<>&中文\u2028\u2029"
	for character := byte(0); character < 0x20; character++ {
		text += string(character)
	}
	raw, err := CanonicalEncode(text)
	if err != nil {
		t.Fatal(err)
	}
	var decoded string
	if err := DecodeCanonical(raw, &decoded, ContractDecodeLimits{len(raw), 1, 1}); err != nil || decoded != text {
		t.Fatal("canonical UTF-8 or a required control escape changed", err)
	}
	object := []byte(`{" ":true,"\"":false,"\\":"demo","a":[],"z":{}}`)
	if _, err := parseContractJSON(object, ContractDecodeLimits{len(object), 2, 6}); err != nil {
		t.Fatal("ASCII keys containing quotes or backslashes lost their decoded sort order", err)
	}
	for _, body := range []string{
		`{"a":1,"a":2}`, `{"z":1,"a":2}`, `{"a":1,"\u0061":2}`,
		`{"a":1,}`, `[1,]`, `{"a" :1}`, `{"a": 1}`, `true false`,
		`"\b"`, `"\n"`, `"\/"`, `"\u001F"`, `"\u0020"`, `"\u00af"`,
		`"\ud800"`, `"\u000"`, `"\u000g"`, `"\`, `"`,
		"\"demo\x1f\"", "\"\xff\"", `-0`, `00`, `-01`, `1.0`, `1e1`, `+1`, `null`,
	} {
		if _, err := parseContractJSON([]byte(body), ContractDecodeLimits{4096, 8, 32}); err == nil {
			t.Fatalf("accepted noncanonical JSON %q", body)
		}
	}
}

func TestContractByteParserCountsValuesAndContainersWithoutKeys(t *testing.T) {
	body := []byte(`{"a":[true,{}],"b":0}`)
	if _, err := parseContractJSON(body, ContractDecodeLimits{len(body), 3, 5}); err != nil {
		t.Fatal("exact input limits counted keys or omitted containers", err)
	}
	for _, limits := range []ContractDecodeLimits{
		{len(body) - 1, 3, 5}, {len(body), 2, 5}, {len(body), 3, 4},
	} {
		if _, err := parseContractJSON(body, limits); err == nil {
			t.Fatal("accepted JSON exceeding an entry-point limit", limits)
		}
	}
	for _, suffix := range []string{"\n", " ", strings.Repeat("[]", 2)} {
		if _, err := parseContractJSON(append(append([]byte{}, body...), suffix...), ContractDecodeLimits{4096, 8, 32}); err == nil {
			t.Fatal("accepted bytes after the complete root value")
		}
	}
}

func FuzzContractByteParserMatchesCanonicalJSON(f *testing.F) {
	controls := "中文\u2028\u2029\"\\"
	for character := byte(0); character < 0x20; character++ {
		controls += string(character)
	}
	f.Add(appendContractString(nil, controls))
	for _, seed := range []string{
		`{"a":[true,false,{},[]],"b":"demo","c":-1}`, `{" ":0,"\"":1,"\\":2}`,
		`[]`, `{}`, `0`, `-1`, `18446744073709551615`, `"18446744073709551615"`,
		`"中"`, `"\u001f"`, `"\n"`, `"\u0020"`, `"\ud800"`,
		`{"a":1,"a":2}`, `{"z":0,"a":1}`, `{"a":`, `"\`, `[true,]`,
		`-0`, `1.0`, `01`, `null`, `true false`,
	} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, body []byte) {
		parsed, err := parseContractJSON(body, ContractDecodeLimits{4096, 12, 128})
		if err != nil {
			return
		}
		if !bytes.Equal(body, appendContractJSON(nil, parsed)) {
			t.Fatal("parser accepted bytes differing from the canonical representation")
		}
		decoder := json.NewDecoder(bytes.NewReader(body))
		decoder.UseNumber()
		var independent any
		if err := decoder.Decode(&independent); err != nil {
			t.Fatal("parser accepted input rejected by the independent JSON decoder", err)
		}
		if err := decoder.Decode(new(any)); err != io.EOF {
			t.Fatal("parser accepted additional JSON content", err)
		}
		if !reflect.DeepEqual(parsed, independent) {
			t.Fatal("parser disagreed with the independent JSON value")
		}
	})
}

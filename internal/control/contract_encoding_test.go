package control

import (
	"bytes"
	"encoding/json"
	"errors"
	"math"
	"reflect"
	"strings"
	"testing"
)

var contractTestLimits = ContractDecodeLimits{MaxBytes: 4096, MaxDepth: 12, MaxItems: 64}

type contractUnexpectedEncoder struct {
	Calls *int `json:"calls"`
}

func (value *contractUnexpectedEncoder) MarshalJSON() ([]byte, error) {
	*value.Calls++
	return []byte(`"unexpected"`), nil
}

type contractUnexpectedTextCodec struct {
	Calls *int `json:"calls"`
}

type contractPointerValidator struct {
	Value string `json:"value"`
}

func (*contractPointerValidator) Validate() error {
	return errors.New("pointer-only domain validation must not be skipped")
}

func TestContractCodecRejectsPointerOnlyValidation(t *testing.T) {
	value := contractPointerValidator{Value: "demo"}
	for _, input := range []any{value, &value} {
		if _, err := CanonicalEncode(input); err == nil {
			t.Fatal("skipped pointer-only domain validation")
		}
	}
	if err := DecodeCanonical([]byte(`{"value":"demo"}`), &value, contractTestLimits); err == nil {
		t.Fatal("decoded a type whose domain validation would be skipped")
	}
}

func (value *contractUnexpectedTextCodec) MarshalText() ([]byte, error) {
	*value.Calls++
	return []byte("unexpected"), nil
}

func (value *contractUnexpectedTextCodec) UnmarshalText(_ []byte) error {
	*value.Calls++
	return nil
}

func TestContractCodecRejectsHiddenStateAndCustomMethodsBeforeInvocation(t *testing.T) {
	calls := 0
	custom := &contractUnexpectedEncoder{Calls: &calls}
	textCodec := &contractUnexpectedTextCodec{Calls: &calls}
	for _, value := range []any{custom, *custom, map[string]any{"value": custom}, textCodec,
		struct{ hidden string }{hidden: "demo-hidden"},
		struct {
			Hidden string `json:"-"`
		}{Hidden: "demo-hidden"},
	} {
		if _, err := CanonicalEncode(value); err == nil {
			t.Fatalf("accepted non-roundtrippable %T", value)
		}
		out := reflect.New(reflect.TypeOf(value))
		if err := DecodeCanonical([]byte(`{}`), out.Interface(), contractTestLimits); err == nil {
			t.Fatalf("decoded non-roundtrippable %T", value)
		}
	}
	if calls != 0 {
		t.Fatal("invoked a custom codec before rejecting its type")
	}
}

func TestContractCanonicalEncodingRoundTrip(t *testing.T) {
	type fixture struct {
		Z        []string `json:"z"`
		Text     string   `json:"text"`
		Count    int      `json:"count"`
		Sequence U64      `json:"sequence"`
		Optional *string  `json:"optional,omitempty"`
	}
	value := fixture{Z: []string{"demo-b", "demo-a"}, Text: "\"\\\b\t\n\f\r\x00\x1f/<>&中文\u2028\u2029", Sequence: U64(math.MaxUint64)}
	want := []byte(`{"count":0,"sequence":"18446744073709551615","text":"\"\\\u0008\u0009\u000a\u000c\u000d\u0000\u001f/<>&中文` + "\u2028\u2029" + `","z":["demo-b","demo-a"]}`)
	body, err := CanonicalEncode(value)
	if err != nil || !bytes.Equal(body, want) {
		t.Fatalf("C differs: %q, %v", body, err)
	}
	var decoded fixture
	if err := DecodeCanonical(body, &decoded, contractTestLimits); err != nil || !reflect.DeepEqual(decoded, value) {
		t.Fatalf("typed round trip differs: %#v, %v", decoded, err)
	}
	encoded, err := CanonicalEncode(decoded)
	if err != nil || !bytes.Equal(encoded, body) {
		t.Fatalf("byte round trip differs: %q, %v", encoded, err)
	}
	// Encoding changes object key order, but never repairs an array's order.
	fromMap, err := CanonicalEncode(map[string]any{"z": value.Z, "text": value.Text, "count": 0, "sequence": value.Sequence})
	if err != nil || !bytes.Equal(fromMap, body) {
		t.Fatalf("object representation changes C: %q, %v", fromMap, err)
	}
}

func TestContractDecoderRejectsAmbiguousAndNonCanonicalBytes(t *testing.T) {
	type fixture struct {
		Flag bool   `json:"flag"`
		ID   string `json:"id"`
		N    int64  `json:"n"`
	}
	valid := `{"flag":false,"id":"demo","n":0}`
	for _, body := range []string{
		`{"flag":false,"id":"demo","id":"other","n":0}`,
		`{"flag":false,"id":"demo","\u0069d":"other","n":0}`,
		`{"flag":false,"ID":"demo","n":0}`,
		`{"flag":false,"id":"demo","n":0,"unknown":false}`,
		`{"id":"demo","n":0}`,
		`{"flag":false,"id":"demo","n":null}`,
		`{"flag":false,"id":null,"n":0}`,
		`{"flag":false,"id":"demo","n":"0"}`,
		`{"flag":false,"id":"demo","n":-0}`,
		`{"flag":false,"id":"demo","n":0.0}`,
		`{"flag":false,"id":"demo","n":0e0}`,
		`{"flag":false,"id":"demo","n":01}`,
		`{"flag":false,"id":"demo","n":9223372036854775808}`,
		`{"id":"demo","flag":false,"n":0}`,
		`{"flag":false,"id":"\u0064emo","n":0}`,
		`{"flag":false,"id":"\ud800","n":0}`,
		"{\"flag\":false,\"id\":\"\xff\",\"n\":0}",
		valid + "\n", " " + valid, "\ufeff" + valid, valid + valid,
	} {
		t.Run(body, func(t *testing.T) {
			value := fixture{ID: "demo-preserved", N: 7, Flag: true}
			before := value
			if err := DecodeCanonical([]byte(body), &value, contractTestLimits); err == nil {
				t.Fatal("accepted noncanonical input")
			}
			if value != before {
				t.Fatal("failed decode mutated existing value")
			}
		})
	}
	var value fixture
	if err := DecodeCanonical([]byte(valid), &value, contractTestLimits); err != nil {
		t.Fatal(err)
	}
}

func TestContractDecoderRejectsNonCanonicalStringEscapes(t *testing.T) {
	for _, body := range []string{`"\n"`, `"\t"`, `"\u000A"`, `"\/"`, `"\u003c"`, `"\u4e2d"`, `"\ud83d\ude00"`} {
		var value string
		if err := DecodeCanonical([]byte(body), &value, contractTestLimits); err == nil {
			t.Fatalf("accepted noncanonical string: %s", body)
		}
	}
	for _, body := range []string{`"\u000a"`, `"/"`, `"<"`, `"中"`, `"😀"`, `"\"\\"`} {
		var value string
		if err := DecodeCanonical([]byte(body), &value, contractTestLimits); err != nil {
			t.Fatalf("rejected canonical string: %s: %v", body, err)
		}
	}
}

func TestContractDecoderEnforcesCallerBoundsAndExactTypes(t *testing.T) {
	value := PolicyScope{Mode: "only", NodeIDs: []string{"demo-a"}}
	body, err := CanonicalEncode(value)
	if err != nil {
		t.Fatal(err)
	}
	for _, limits := range []ContractDecodeLimits{
		{}, {MaxBytes: len(body) - 1, MaxDepth: 3, MaxItems: 4},
		{MaxBytes: len(body), MaxDepth: 2, MaxItems: 4},
		{MaxBytes: len(body), MaxDepth: 3, MaxItems: 3},
	} {
		var next PolicyScope
		if err := DecodeCanonical(body, &next, limits); err == nil {
			t.Fatal("accepted value beyond caller bounds")
		}
	}
	var next PolicyScope
	if err := DecodeCanonical(body, &next, ContractDecodeLimits{len(body), 3, 4}); err != nil {
		t.Fatal(err)
	}
	var loose map[string]any
	var anything any
	var decimal float64
	for _, out := range []any{nil, next, (*PolicyScope)(nil), &loose, &anything, &decimal} {
		if err := DecodeCanonical(body, out, contractTestLimits); err == nil {
			t.Fatalf("accepted non-schema output %T", out)
		}
	}
}

func TestContractEncoderRejectsLossyOrUnsupportedValues(t *testing.T) {
	cycle := map[string]any{}
	cycle["cycle"] = cycle
	duplicateFields := reflect.New(reflect.StructOf([]reflect.StructField{
		{Name: "A", Type: reflect.TypeFor[string](), Tag: `json:"id"`},
		{Name: "B", Type: reflect.TypeFor[string](), Tag: `json:"id"`},
	})).Elem()
	duplicateFields.Field(0).SetString("demo-a")
	duplicateFields.Field(1).SetString("demo-b")
	for _, value := range []any{
		nil, []string(nil), map[string]any(nil), []byte{1}, 1.0,
		"\xff", map[string]any{"中文": true}, json.RawMessage(`{"a":1}`), cycle,
		struct{ MissingTag string }{MissingTag: "demo"},
		duplicateFields.Interface(),
		struct {
			Value string `json:"value"`
		}{Value: strings.Repeat("\xff", 2)},
		struct {
			Values []string `json:"values,omitempty"`
		}{Values: []string{}},
		struct {
			Value string `json:"value,omitzero"`
		}{Value: "demo"},
	} {
		if _, err := CanonicalEncode(value); err == nil {
			t.Fatalf("accepted lossy or unsupported %T", value)
		}
	}
}

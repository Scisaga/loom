package control

import (
	"bytes"
	"errors"
	"reflect"
	"testing"
)

type contractTypedChild struct {
	Text string `json:"text"`
	Flag bool   `json:"flag"`
}

type contractTypedFixture struct {
	Texts    *[]string            `json:"texts,omitempty"`
	Pair     [2]uint8             `json:"pair"`
	Optional *U64                 `json:"optional,omitempty"`
	Entries  []contractTypedChild `json:"entries"`
}

type contractTypedKeyFixture struct {
	A      *bool   `json:"a,omitempty"`
	AB     string  `json:"ab"`
	Middle *string `json:"m,omitempty"`
	Z      string  `json:"z"`
	ZZ     *uint8  `json:"zz,omitempty"`
}

type contractTypedEscapedKeys struct {
	Space bool   `json:" "`
	Quote string `json:"\""`
	Slash *bool  `json:"\\,omitempty"`
	A     string `json:"a"`
}

type contractTypedOptionalKeys struct {
	A *int `json:"a,omitempty"`
	Z *int `json:"z,omitempty"`
}

// Keep the previous generic-tree pipeline as a test-only comparison. Both
// paths still validate the actual typed value and compare its canonical bytes.
func genericContractDecode(body []byte, output any, limits ContractDecodeLimits) error {
	codec := newContractCodec()
	target := reflect.ValueOf(output)
	if err := codec.inspectType(target.Type().Elem()); err != nil {
		return err
	}
	parsed, err := parseContractJSON(body, limits)
	if err != nil {
		return err
	}
	next := reflect.New(target.Type().Elem())
	if err := codec.assign(parsed, next.Elem()); err != nil {
		return err
	}
	want, err := codec.encode(next.Elem().Interface())
	if err != nil {
		return err
	}
	if !bytes.Equal(body, want) {
		return errors.New("contract JSON is not canonical")
	}
	target.Elem().Set(next.Elem())
	return nil
}

func TestContractTypedParserKeepsPointersArraysAndExactBounds(t *testing.T) {
	body := []byte(`{"entries":[],"optional":"18446744073709551615","pair":[0,255],"texts":[]}`)
	limits := ContractDecodeLimits{len(body), 3, 7}
	var value contractTypedFixture
	if err := DecodeCanonical(body, &value, limits); err != nil || value.Optional == nil ||
		*value.Optional != ^U64(0) || value.Texts == nil || *value.Texts == nil || value.Entries == nil {
		t.Fatal("direct parsing lost pointer identity, U64, or explicit empty collections", err)
	}
	for _, bound := range []ContractDecodeLimits{{len(body) - 1, 3, 7}, {len(body), 2, 7}, {len(body), 3, 6}} {
		before := value
		if err := DecodeCanonical(body, &value, bound); err == nil || !reflect.DeepEqual(before, value) {
			t.Fatal("pointer allocation changed item/depth limits or a failed output", err)
		}
	}
	for _, raw := range []string{
		`{"entries":[],"pair":[0]}`, `{"entries":[],"pair":[0,1,2]}`,
		`{"entries":[],"pair":[0,256]}`, `{"entries":[],"pair":[-1,0]}`,
		`{"entries":[],"optional":"00","pair":[0,1]}`, `{"entries":[],"optional":null,"pair":[0,1]}`,
		`{"entries":[],"pair":[0,1],"unknown":0}`, `{"entries":[]}`,
	} {
		before := value
		if err := DecodeCanonical([]byte(raw), &value, contractTestLimits); err == nil || !reflect.DeepEqual(before, value) {
			t.Fatal("direct parsing relaxed an exact type/field boundary or changed the output", err)
		}
	}
}

func TestContractTypedKeysKeepExactPrefixesEscapesAndOptionalFields(t *testing.T) {
	for _, item := range []struct {
		name    string
		schema  reflect.Type
		valid   []string
		invalid []string
	}{
		{
			name: "prefixes and optional gaps", schema: reflect.TypeFor[contractTypedKeyFixture](),
			valid: []string{
				`{"ab":"demo-ab","z":"demo-z"}`,
				`{"a":false,"ab":"demo-ab","m":"","z":"demo-z","zz":0}`,
				`{"ab":"demo-ab","m":"demo-middle","z":"demo-z"}`,
			},
			invalid: []string{
				`{}`, `{"a":false,"z":"demo-z"}`, `{"ab":"demo-ab"}`,
				`{"ab":"demo-ab","ab":"again","z":"demo-z"}`,
				`{"a":false,"a":true,"ab":"demo-ab","z":"demo-z"}`,
				`{"z":"demo-z","ab":"demo-ab"}`,
				`{"ab":"demo-ab","m":"demo","a":false,"z":"demo-z"}`,
				`{"0":false,"ab":"demo-ab","z":"demo-z"}`,
				`{"aX":false,"ab":"demo-ab","z":"demo-z"}`,
				`{"ab":"demo-ab","b":false,"z":"demo-z"}`,
				`{"ab":"demo-ab","z":"demo-z","zzz":0}`,
				`{"\u0061b":"demo-ab","z":"demo-z"}`,
				`{"ab" :"demo-ab","z":"demo-z"}`,
				`{"ab": "demo-ab","z":"demo-z"}`,
				`{"ab":0,"z":"demo-z"}`,
				`{"ab":"demo-ab","z":"demo-z",}`, `{`, `{"ab"`,
			},
		},
		{
			name: "canonical escaped schema keys", schema: reflect.TypeFor[contractTypedEscapedKeys](),
			valid: []string{
				`{" ":false,"\"":"demo-quote","a":"demo-a"}`,
				`{" ":true,"\"":"demo-quote","\\":false,"a":"demo-a"}`,
			},
			invalid: []string{
				`{"\u0020":false,"\"":"demo-quote","a":"demo-a"}`,
				`{" ":false,"\u0022":"demo-quote","a":"demo-a"}`,
				`{" ":false,"\"":"demo-quote","\u005c":false,"a":"demo-a"}`,
				`{" ":false,"\\":false,"\"":"demo-quote","a":"demo-a"}`,
				`{" ":false,"\"":"demo-quote","\"":"again","a":"demo-a"}`,
				`{" ":false,"\"":"demo-quote","a":"demo-a","\\":false}`,
			},
		},
		{
			name: "all optional", schema: reflect.TypeFor[contractTypedOptionalKeys](),
			valid: []string{`{}`, `{"a":0}`, `{"z":1}`, `{"a":0,"z":1}`},
			invalid: []string{
				`{"a":0,"a":1}`, `{"z":1,"a":0}`, `{"aX":0}`,
				`{"z":1,"zz":2}`, `{"a":0,}`, `{`,
			},
		},
	} {
		t.Run(item.name, func(t *testing.T) {
			codec := newContractCodec()
			direct := reflect.New(item.schema)
			for _, text := range item.valid {
				body := []byte(text)
				generic := reflect.New(item.schema)
				if err := codec.decode(body, direct.Interface(), contractTestLimits); err != nil {
					t.Fatal("canonical known key was rejected", text, err)
				}
				if err := genericContractDecode(body, generic.Interface(), contractTestLimits); err != nil || !reflect.DeepEqual(direct.Interface(), generic.Interface()) {
					t.Fatal("known-key matching changed the decoded value", text, err)
				}
				// Known key matching must not retain the caller's raw buffer.
				for index := range body {
					body[index] = 0
				}
				encoded, err := codec.encode(direct.Elem().Interface())
				if err != nil || string(encoded) != text {
					t.Fatal("decoded fields retained mutable input bytes", err)
				}
			}
			for _, text := range item.invalid {
				before, err := codec.encode(direct.Elem().Interface())
				if err != nil {
					t.Fatal(err)
				}
				if err := codec.decode([]byte(text), direct.Interface(), contractTestLimits); err == nil {
					t.Fatal("accepted unknown, missing, duplicate or noncanonical key", text)
				}
				after, err := codec.encode(direct.Elem().Interface())
				if err != nil || !bytes.Equal(before, after) {
					t.Fatal("failed key matching changed the output", text, err)
				}
				generic := reflect.New(item.schema)
				if genericContractDecode([]byte(text), generic.Interface(), contractTestLimits) == nil {
					t.Fatal("the previous generic decoder accepted the invalid fixture", text)
				}
			}
		})
	}
}

func FuzzContractTypedParserMatchesGeneric(f *testing.F) {
	for _, seed := range []string{
		`{"entries":[],"pair":[0,255]}`,
		`{"entries":[{"flag":false,"text":"demo-中文\\\""}],"optional":"0","pair":[1,2],"texts":[]}`,
		`{"entries":[],"pair":[0]}`, `{"entries":[],"pair":[0,256]}`,
		`{"entries":[],"pair":[0,1],"texts":null}`, `{"entries":[],"entries":[],"pair":[0,1]}`,
		`[0,-128,127]`, `[]`, `[128]`, `[null]`, `"18446744073709551615"`, `"00"`,
		`true`, `false`, `true false`, `null`, `{"entries":`, `"\u000a"`, `"\n"`,
		`{"ab":"demo-ab","z":"demo-z"}`, `{"a":false,"ab":"demo-ab","m":"","z":"demo-z","zz":0}`,
		`{" ":false,"\"":"demo-quote","\\":true,"a":"demo-a"}`,
		`{" ":false,"\u0022":"demo-quote","a":"demo-a"}`,
		`{"a":0,"z":1}`, `{"z":1,"a":0}`,
	} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, body []byte) {
		limits := ContractDecodeLimits{4096, 12, 128}
		for _, schema := range []reflect.Type{reflect.TypeFor[contractTypedFixture](), reflect.TypeFor[contractTypedKeyFixture](), reflect.TypeFor[contractTypedEscapedKeys](), reflect.TypeFor[contractTypedOptionalKeys](), reflect.TypeFor[[]*int8](), reflect.TypeFor[**U64](), reflect.TypeFor[bool]()} {
			direct, generic := reflect.New(schema), reflect.New(schema)
			directErr := newContractCodec().decode(body, direct.Interface(), limits)
			genericErr := genericContractDecode(body, generic.Interface(), limits)
			if (directErr == nil) != (genericErr == nil) || !reflect.DeepEqual(direct.Interface(), generic.Interface()) {
				t.Fatalf("direct and generic paths disagree for %v: direct=%v generic=%v", schema, directErr, genericErr)
			}
		}
	})
}

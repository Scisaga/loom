package wire

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func TestCanonicalizeStrictRFC8785IntegerProfile(t *testing.T) {
	input := []byte("{\"emoji\":\"😀\",\"€\":\"x\",\"z\":[true,null],\"a\":1,\"\\r\":\"\\n\"}")
	want := []byte("{\"\\r\":\"\\n\",\"a\":1,\"emoji\":\"😀\",\"z\":[true,null],\"€\":\"x\"}")
	got, err := CanonicalizeStrict(input)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("canonical = %s, want %s", got, want)
	}
}

func TestCanonicalizeStrictRejectsAmbiguousAndNonIJSON(t *testing.T) {
	for _, body := range []string{
		`{"a":1,"a":2}`,
		`{"n":1.0}`,
		`{"n":1e2}`,
		`{"n":9223372036854775808}`,
		`{"s":"\ud800"}`,
		`{"s":"\udc00"}`,
		"{\"s\":\"\xff\"}",
		`{"a":1}{"b":2}`,
	} {
		if _, err := CanonicalizeStrict([]byte(body)); err == nil {
			t.Fatalf("accepted invalid input %q", body)
		}
	}
}

func TestFrameHasTypedLengthPrefix(t *testing.T) {
	framed, err := Frame("abc", []byte("{}"))
	if err != nil {
		t.Fatal(err)
	}
	want := []byte{0, 0, 0, 3, 'a', 'b', 'c', '{', '}'}
	if !bytes.Equal(framed, want) {
		t.Fatalf("frame = %x, want %x", framed, want)
	}
}

func TestMerkleUsesRFC6962ShapeAndExactAuditPath(t *testing.T) {
	leaves := [][]byte{[]byte(`{"i":0}`), []byte(`{"i":1}`), []byte(`{"i":2}`)}
	root := MerkleRoot(leaves)
	left := merkleNode(MerkleLeafHash(leaves[0]), MerkleLeafHash(leaves[1]))
	want := merkleNode(left, MerkleLeafHash(leaves[2]))
	if !bytes.Equal(root, want) {
		t.Fatalf("root=%s want=%s", hex.EncodeToString(root), hex.EncodeToString(want))
	}
	path := [][]byte{MerkleLeafHash(leaves[0]), MerkleLeafHash(leaves[2])}
	if err := VerifyMerkleInclusion(leaves[1], 1, 3, path, root); err != nil {
		t.Fatal(err)
	}
	if err := VerifyMerkleInclusion(leaves[1], 1, 3, append(path, make([]byte, 32)), root); err == nil {
		t.Fatal("accepted an audit path with an extra node")
	}
}

func TestCheckedArithmeticDoesNotWrap(t *testing.T) {
	if _, err := CheckedAdd(1<<63-1, 1); err == nil {
		t.Fatal("accepted overflowing addition")
	}
	if got, err := BasisPoints(3, 4); err != nil || got != 7500 {
		t.Fatalf("basis points=%d err=%v", got, err)
	}
}

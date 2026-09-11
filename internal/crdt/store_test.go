package crdt

import (
	"path/filepath"
	"reflect"
	"testing"
)

func TestMergeConvergesIndependentOfArrivalOrder(t *testing.T) {
	a, err := NewObject("op-a", "proposal", []byte(`{"n":1}`))
	if err != nil {
		t.Fatal(err)
	}
	b, err := NewObject("op-b", "receipt", []byte(`{"n":2}`))
	if err != nil {
		t.Fatal(err)
	}
	left, err := Open(filepath.Join(t.TempDir(), "left.json"))
	if err != nil {
		t.Fatal(err)
	}
	right, err := Open(filepath.Join(t.TempDir(), "right.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := left.Merge([]Object{b, a}); err != nil {
		t.Fatal(err)
	}
	if err := right.Merge([]Object{a, b, a}); err != nil {
		t.Fatal(err)
	}
	leftRoot, _ := left.Root()
	rightRoot, _ := right.Root()
	if leftRoot != rightRoot || !reflect.DeepEqual(left.Snapshot(), right.Snapshot()) {
		t.Fatalf("replicas did not converge: %s != %s", leftRoot, rightRoot)
	}
}

func TestSameLogicalIDDifferentBytesFailsClosed(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "objects.json"))
	if err != nil {
		t.Fatal(err)
	}
	one, _ := NewObject("same", "draft", []byte(`{"value":1}`))
	two, _ := NewObject("same", "draft", []byte(`{"value":2}`))
	if err := store.Add(one); err != nil {
		t.Fatal(err)
	}
	if err := store.Add(two); err == nil {
		t.Fatal("conflicting logical ID was silently merged")
	}
}

func TestStoreReopensAndRejectsNonCanonicalPayload(t *testing.T) {
	path := filepath.Join(t.TempDir(), "objects.json")
	store, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	object, _ := NewObject("one", "observation", []byte(`{"a":1,"b":2}`))
	if err := store.Add(object); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(path)
	if err != nil || len(reopened.Snapshot()) != 1 {
		t.Fatalf("reopen failed: %v", err)
	}
	object.Payload = []byte(`{"b":2,"a":1}`)
	if err := reopened.Add(object); err == nil {
		t.Fatal("non-canonical payload accepted")
	}
}

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

func TestMergeConflictRejectsWholeBatch(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "objects.json"))
	if err != nil {
		t.Fatal(err)
	}
	existing, _ := NewObject("same", "draft", []byte(`{"value":1}`))
	beforeConflict, _ := NewObject("before", "draft", []byte(`{"value":2}`))
	conflict, _ := NewObject("same", "draft", []byte(`{"value":3}`))
	if err := store.Add(existing); err != nil {
		t.Fatal(err)
	}
	if err := store.Merge([]Object{beforeConflict, conflict}); err == nil {
		t.Fatal("conflicting batch was accepted")
	}
	if got := store.Snapshot(); len(got) != 1 || got[0].ID != "same" || got[0].ObjectID != existing.ObjectID {
		t.Fatalf("冲突 batch 泄漏了部分对象: %#v", got)
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

func TestSnapshotRootRequiresCanonicalLogicalOrder(t *testing.T) {
	a, _ := NewObject("a", "proposal", []byte(`{"value":1}`))
	b, _ := NewObject("b", "proposal", []byte(`{"value":2}`))
	if _, err := SnapshotRoot([]Object{b, a}); err == nil {
		t.Fatal("anti-entropy root 接受了非规范 object 顺序")
	}
	if _, err := SnapshotRoot(nil); err == nil {
		t.Fatal("anti-entropy root 把 null objects 当成空集合")
	}
	if root, err := SnapshotRoot([]Object{}); err != nil || root == "" {
		t.Fatalf("规范空集合 root 无效: root=%q err=%v", root, err)
	}
}

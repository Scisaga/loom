package control

import (
	"reflect"
	"strings"
	"testing"
)

func TestDeviceConfigHeapCostInlineStorageOnce(t *testing.T) {
	type fixed struct {
		Nested struct{ Number uint64 }
		Values [3]uint64
	}
	value := fixed{}
	if got, want := deviceConfigHeapCost(reflect.ValueOf(value)), int(reflect.TypeOf(value).Size()); got != want {
		t.Fatalf("inline scalar fields and array charged more than enclosing fixed storage: got %d want %d", got, want)
	}
}

func TestDeviceConfigHeapCostSliceBackingAndSpareCapacity(t *testing.T) {
	numbers := make([]uint64, 2, 7)
	if got, want := deviceConfigHeapCost(reflect.ValueOf(numbers)), int(reflect.TypeOf(numbers).Size())+7*int(reflect.TypeOf(uint64(0)).Size()); got != want {
		t.Fatalf("slice inline header/backing storage or spare capacity charged incorrectly: got %d want %d", got, want)
	}
	bytes := make([]byte, 2, 19)
	if got, want := deviceConfigHeapCost(reflect.ValueOf(bytes)), int(reflect.TypeOf(bytes).Size())+19; got != want {
		t.Fatalf("encoded byte body counted twice or spare capacity omitted: got %d want %d", got, want)
	}
	// The backing array includes all five string headers; heap data for each used
	// string is charged separately and rounded as in the existing policy.
	names := make([]string, 2, 5)
	names[0], names[1] = "one", "two"
	if got, want := deviceConfigHeapCost(reflect.ValueOf(names)), int(reflect.TypeOf(names).Size())+5*int(reflect.TypeOf("").Size())+2*16; got != want {
		t.Fatalf("slice element inline bytes repeated or string backing lost: got %d want %d", got, want)
	}
}

func TestDeviceConfigHeapCostSharedReferencesRemainRepeated(t *testing.T) {
	text := "demo-reference"
	pointers := struct{ A, B *string }{&text, &text}
	want := int(reflect.TypeOf(pointers).Size()) + 2*(int(reflect.TypeOf(text).Size())+16)
	if got := deviceConfigHeapCost(reflect.ValueOf(pointers)); got != want {
		t.Fatalf("shared references stopped being conservatively charged twice: got %d want %d", got, want)
	}
	body := make([]byte, 3, 31)
	aliases := struct{ A, B []byte }{body, body}
	want = int(reflect.TypeOf(aliases).Size()) + 2*31
	if got := deviceConfigHeapCost(reflect.ValueOf(aliases)); got != want {
		t.Fatalf("shared byte backing stopped being charged twice: got %d want %d", got, want)
	}
}

func TestDeviceConfigHeapCostStopsAfterCrossingBudget(t *testing.T) {
	huge := strings.Repeat("x", deviceConfigCacheBytes+32)
	values := []string{huge, huge, huge, huge}
	got := deviceConfigHeapCost(reflect.ValueOf(values))
	if got <= deviceConfigCacheBytes || got >= 2*len(huge) {
		t.Fatalf("over-budget traversal did not reject early: got %d budget %d", got, deviceConfigCacheBytes)
	}
}

func TestDeviceConfigHeapCostSpareSlotsRetainReferences(t *testing.T) {
	names := make([]string, 1, 3)
	names[:cap(names)][2] = "demo-tail"
	want := int(reflect.TypeOf(names).Size()) + 3*int(reflect.TypeOf("").Size()) + 16
	if got := deviceConfigHeapCost(reflect.ValueOf(names)); got != want {
		t.Fatalf("spare string reference was omitted: got %d want %d", got, want)
	}
	tail := "demo-tail"
	pointers := make([]*string, 1, 3)
	pointers[:cap(pointers)][2] = &tail
	want = int(reflect.TypeOf(pointers).Size()) + 3*int(reflect.TypeOf((*string)(nil)).Size()) + int(reflect.TypeOf(tail).Size()) + 16
	if got := deviceConfigHeapCost(reflect.ValueOf(pointers)); got != want {
		t.Fatalf("spare pointer reference was omitted: got %d want %d", got, want)
	}
}

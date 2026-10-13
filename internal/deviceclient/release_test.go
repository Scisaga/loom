package deviceclient

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"testing"
)

func TestReleaseBodyExactLengthAndCancellation(t *testing.T) {
	for _, test := range []struct {
		name, body      string
		declared        int64
		canceled, valid bool
	}{
		{"exact", "signed bytes", 12, false, true},
		{"truncated", "signed byte", 12, false, false},
		{"extended", "signed bytes!", 12, false, false},
		{"wrong declaration", "signed bytes", 11, false, false},
		{"canceled", "signed bytes", 12, true, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if test.canceled {
				cancel()
			}
			response := &http.Response{StatusCode: http.StatusOK, ContentLength: test.declared, Body: io.NopCloser(bytes.NewBufferString(test.body))}
			var output bytes.Buffer
			err := copyReleaseBody(ctx, response, 12, &output)
			if (err == nil) != test.valid {
				t.Fatalf("unexpected acceptance: %v", err)
			}
			if test.valid && output.String() != test.body {
				t.Fatal("body differs")
			}
			if test.canceled && !errors.Is(err, context.Canceled) {
				t.Fatalf("cancellation lost: %v", err)
			}
		})
	}
}

type failedReleaseWriter struct{ err error }

func (w failedReleaseWriter) Write([]byte) (int, error) { return 0, w.err }
func TestReleaseBodyPreservesStorageFailure(t *testing.T) {
	want := errors.New("demo storage failure")
	response := &http.Response{StatusCode: http.StatusOK, ContentLength: 12, Body: io.NopCloser(bytes.NewBufferString("signed bytes"))}
	if err := copyReleaseBody(context.Background(), response, 12, failedReleaseWriter{want}); !errors.Is(err, want) {
		t.Fatalf("storage failure lost: %v", err)
	}
}

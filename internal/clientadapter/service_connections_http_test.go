package clientadapter

import (
	"context"
	"io"
	"net/http"
	"reflect"
	"strings"
	"testing"
)

type serviceRebuildTransport func(*http.Request) (*http.Response, error)

func (f serviceRebuildTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
}

func TestServiceRebuildHTTPClosesOnlyPinnedService(t *testing.T) {
	const first = "00000000-0000-0000-0000-000000000001"
	const second = "00000000-0000-0000-0000-000000000002"
	const snapshot = `{"connections":[` +
		`{"id":"` + first + `","chains":["demo-shared-exit","access"],"metadata":{"serviceID":"demo-service-a"}},` +
		`{"id":"` + second + `","chains":["demo-new-exit","access"],"metadata":{"serviceID":"demo-service-a"}},` +
		`{"id":"00000000-0000-0000-0000-000000000003","chains":["demo-shared-exit","access"],"metadata":{"serviceID":"demo-service-b"}},` +
		`{"id":"00000000-0000-0000-0000-000000000004","chains":["demo-shared-exit"],"metadata":{"serviceID":"demo-service-a"}}]}`
	for _, tc := range []struct {
		name string
		body string
		want []string
	}{
		{"exact Service within source", snapshot, []string{"GET /connections/", "DELETE /connections/" + first, "DELETE /connections/" + second}},
		{"unclassified source closes nothing", strings.Replace(snapshot, `"serviceID":"demo-service-b"`, `"serviceID":""`, 1), []string{"GET /connections/"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var calls []string
			selector := &HTTPSelector{secret: "demo-secret", client: &http.Client{Transport: serviceRebuildTransport(func(request *http.Request) (*http.Response, error) {
				calls = append(calls, request.Method+" "+request.URL.Path)
				body := ""
				if request.Method == http.MethodGet {
					body = tc.body
				}
				return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(body)), Header: make(http.Header)}, nil
			})}}
			err := selector.CloseServiceConnections(context.Background(), "demo-service-a", "access")
			if (err != nil) != (len(tc.want) == 1) || !reflect.DeepEqual(calls, tc.want) {
				t.Fatal("rebuild crossed Service/source boundaries or deleted before complete validation", calls, err)
			}
		})
	}
}

package clientreport

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestEndpointExactOriginAndPath(t *testing.T) {
	for _, root := range []string{"https://control.example", "https://control.example:8443"} {
		got, err := Endpoint(root + "/loom-client/enroll")
		if err != nil || got != root+"/loom-client/report" {
			t.Fatalf("endpoint=%s err=%v", got, err)
		}
	}
	for _, raw := range []string{"http://control.example/loom-client/enroll", "https://control.example/api/client/enroll", "https://control.example/loom-client/enroll/", "https://user@control.example/loom-client/enroll", "https://control.example/loom-client/enroll?", "https://control.example/loom-client/enroll#", "https://control.example/loom-client/enroll?a=b", "https://control.example/loom-client/enroll#fragment", "https://control.example/loom-client/%65nroll", "https://control.example/other/../loom-client/enroll"} {
		if _, err := Endpoint(raw); err == nil {
			t.Errorf("accepted unsafe endpoint %q", raw)
		}
	}
}

func TestHTTPClassificationAndRedirectRefusal(t *testing.T) {
	followed := 0
	destination := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { followed++; w.WriteHeader(204) }))
	defer destination.Close()
	for _, code := range []int{200, 201, 202, 204, 205, 301, 302, 303, 307, 308, 400, 403, 405, 413, 415, 429, 500, 503} {
		t.Run(http.StatusText(code), func(t *testing.T) {
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != "POST" || r.URL.Path != "/loom-client/report" || r.Header.Get("Content-Type") != "application/json" || r.Header.Get("Authorization") != "" {
					t.Error("incorrect upload contract")
				}
				body, _ := io.ReadAll(r.Body)
				if strings.Contains(string(body), "observation") || strings.Contains(string(body), "learned") {
					t.Error("unexpected envelope")
				}
				w.Header().Set("Location", destination.URL+"/loom-client/report")
				w.Header().Set("Retry-After", "120")
				w.WriteHeader(code)
				if code != 204 {
					_, _ = w.Write([]byte("server-private-diagnostic"))
				}
			}))
			defer server.Close()
			got := Send(context.Background(), server.Client(), server.URL+"/loom-client/report", &Observation{Node: "demo-client"})
			if got.Status != code || (got.Err == nil) != (code == 204) {
				t.Fatalf("result=%+v", got)
			}
			if code == 429 && got.RetryAfter != 120*time.Second {
				t.Fatal("Retry-After ignored")
			}
			if got.Err != nil && strings.Contains(got.Err.Error(), "private") {
				t.Fatal("server error exposed")
			}
		})
	}
	if followed != 0 {
		t.Fatal("redirect leaked a report")
	}
}

type responseTransport func(*http.Request) (*http.Response, error)

func (f responseTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestNetworkErrorsAreRedacted(t *testing.T) {
	client := &http.Client{Transport: responseTransport(func(*http.Request) (*http.Response, error) {
		return nil, errors.New("demo-private-token demo-certificate demo-report-body")
	})}
	result := Send(context.Background(), client, "https://control.example/loom-client/report", &Observation{Node: "demo-client"})
	if result.Err == nil || strings.Contains(result.Err.Error(), "demo-") || strings.Contains(result.Err.Error(), "control.example") {
		t.Fatal("transport error was accepted or disclosed raw network diagnostics")
	}
}

func TestNonempty204AndBodyLimit(t *testing.T) {
	called := 0
	client := &http.Client{Transport: responseTransport(func(*http.Request) (*http.Response, error) {
		called++
		return &http.Response{StatusCode: 204, Body: io.NopCloser(strings.NewReader("x")), ContentLength: 1, Header: http.Header{}}, nil
	})}
	got := Send(context.Background(), client, "https://control.example/loom-client/report", &Observation{})
	if got.Err == nil {
		t.Fatal("nonempty 204 accepted")
	}
	got = Send(context.Background(), client, "https://control.example/loom-client/report", &Observation{Node: strings.Repeat("x", MaxBody)})
	if got.Err == nil || called != 1 {
		t.Fatal("oversized body sent")
	}
}

func TestRetryAfterOnAnyHTTPResponse(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	if got := retryAfter(now.Add(time.Minute).Format(http.TimeFormat), now); got != time.Minute {
		t.Fatal("date Retry-After ignored")
	}
	client := &http.Client{Transport: responseTransport(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 503, Body: io.NopCloser(strings.NewReader("")), Header: http.Header{"Retry-After": []string{"120"}}}, nil
	})}
	got := Send(context.Background(), client, "https://control.example/loom-client/report", &Observation{})
	if got.RetryAfter != 2*time.Minute || got.Err == nil {
		t.Fatal("503 Retry-After ignored")
	}
}

func TestObservationReadKeepsReportAcceptedAndRawSignedObjects(t *testing.T) {
	for _, test := range []struct {
		name              string
		status            int
		contentType, body string
		want              int
		bad               bool
	}{
		{"old server", 204, "", "", 0, false},
		{"empty", 200, "application/json", "[]", 0, false},
		{"raw object", 200, "application/json; charset=utf-8", `[{"node":"demo-server","targets":[{"target":"https://service.example/"}],"attest":{"sig":"synthetic-only"}}]`, 1, false},
		{"null", 200, "application/json", "null", 0, true},
		{"object", 200, "application/json", `{"node":"demo-server"}`, 0, true},
		{"trailing", 200, "application/json", "[] []", 0, true},
		{"truncated", 200, "application/json", "[{", 0, true},
		{"wrong type", 200, "text/html", "[]", 0, true},
		{"too large", 200, "application/json", "[" + strings.Repeat(" ", MaxBody) + "]", 0, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			client := &http.Client{Transport: responseTransport(func(r *http.Request) (*http.Response, error) {
				if r.URL.RawQuery != "observations=1" || r.Method != http.MethodPost || r.URL.Path != "/loom-client/report" {
					t.Fatal("observation read changed the report boundary")
				}
				return &http.Response{StatusCode: test.status, Header: http.Header{"Content-Type": []string{test.contentType}}, Body: io.NopCloser(strings.NewReader(test.body)), ContentLength: int64(len(test.body))}, nil
			})}
			result, raw := SendWithObservations(context.Background(), client, "https://control.example/loom-client/report", &Observation{Node: "demo-client"})
			if result.Err != nil || result.Status != test.status || (result.ObservationsErr != nil) != test.bad || len(raw) != test.want {
				t.Fatalf("result=%+v raw=%d", result, len(raw))
			}
			if len(raw) == 1 && string(raw[0]) != test.body[1:len(test.body)-1] {
				t.Fatal("transport rewrote signed observation")
			}
		})
	}
	for _, endpoint := range []string{"https://control.example/loom-client/report?observations=1", "https://control.example/loom-client/report?other=1", "https://control.example/loom-client/report#fragment"} {
		result, _ := SendWithObservations(context.Background(), http.DefaultClient, endpoint, &Observation{})
		if result.Err == nil {
			t.Fatal("caller supplied query or fragment bypassed the fixed endpoint")
		}
	}
}

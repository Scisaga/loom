package report

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
)

type geoRoundTripFunc func(*http.Request) (*http.Response, error)

func (f geoRoundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestLookupIPWhoIsReturnsBoundedAdvisoryLocation(t *testing.T) {
	client := &http.Client{Transport: geoRoundTripFunc(func(r *http.Request) (*http.Response, error) {
		if r.Method != http.MethodGet || r.URL.Scheme != "https" || r.URL.Host != "ipwho.is" ||
			r.URL.Path != "/8.8.8.8" || !strings.Contains(r.URL.Query().Get("fields"), "country_code") ||
			r.Header.Get("Accept") != "application/json" || r.Header.Get("User-Agent") != "loom-control/geoip" {
			t.Fatalf("unexpected GeoIP request: %#v", r)
		}
		return &http.Response{
			StatusCode: http.StatusOK,
			Body: io.NopCloser(strings.NewReader(
				`{"ip":"8.8.8.8","success":true,"country_code":"us","city":" Mountain View "}`)),
			Header: make(http.Header),
		}, nil
	})}
	got, err := lookupIPWhoIs(context.Background(), client, "8.8.8.8")
	if err != nil {
		t.Fatal(err)
	}
	if got.Country != "US" || got.City != "Mountain View" ||
		!strings.Contains(got.Evidence, "ipwho.is") || !strings.Contains(got.Evidence, "not trusted") {
		t.Fatalf("GeoIP location = %#v", got)
	}
}

func TestLookupIPWhoIsRejectsUnboundOrInvalidAnswers(t *testing.T) {
	for _, tc := range []struct {
		name, ip, body, want string
	}{
		{name: "private query", ip: "10.0.0.1", want: "not public"},
		{name: "provider failure", ip: "8.8.8.8", body: `{"success":false,"message":"rate limit exceeded"}`, want: "rate limit"},
		{name: "wrong response ip", ip: "8.8.8.8", body: `{"ip":"1.1.1.1","success":true,"country_code":"US","city":"X"}`, want: "does not match"},
		{name: "bad country", ip: "8.8.8.8", body: `{"ip":"8.8.8.8","success":true,"country_code":"USA","city":"X"}`, want: "invalid country"},
		{name: "bad city", ip: "8.8.8.8", body: `{"ip":"8.8.8.8","success":true,"country_code":"US","city":"X\nY"}`, want: "invalid city"},
		{name: "oversized response", ip: "8.8.8.8", body: strings.Repeat("x", maxGeoIPResponse+1), want: "response exceeds"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client := &http.Client{Transport: geoRoundTripFunc(func(*http.Request) (*http.Response, error) {
				return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(tc.body)), Header: make(http.Header)}, nil
			})}
			if _, err := lookupIPWhoIs(context.Background(), client, tc.ip); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("lookup error = %v, want %q", err, tc.want)
			}
		})
	}
}

func TestFirstEndpointAddressUsesDeterministicFirstResolution(t *testing.T) {
	got, err := firstEndpointAddress("1.1.1.1,8.8.8.8")
	if err != nil || got != "1.1.1.1" {
		t.Fatalf("firstEndpointAddress = %q, %v", got, err)
	}
	for _, value := range []string{"", "10.0.0.1", "not-an-ip"} {
		if _, err := firstEndpointAddress(value); err == nil {
			t.Errorf("firstEndpointAddress(%q) succeeded", value)
		}
	}
}

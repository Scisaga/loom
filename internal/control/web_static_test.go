package control

import (
	"bytes"
	"compress/gzip"
	"io"
	"net/http"
	"net/http/httptest"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
)

func TestWebModulePreloadsMatchEntryDependencies(t *testing.T) {
	entry, err := staticFiles.ReadFile("static/app.js")
	if err != nil {
		t.Fatal(err)
	}
	index, err := staticFiles.ReadFile("static/index.html")
	if err != nil {
		t.Fatal(err)
	}
	imports := regexp.MustCompile(`from\s*['"]\./([^'"]+\.js)['"]`).FindAllSubmatch(entry, -1)
	preloads := regexp.MustCompile(`<link rel="modulepreload" href="/assets/([^"]+)">`).FindAllSubmatch(index, -1)
	want, got := []string{}, []string{}
	for _, match := range imports {
		want = append(want, string(match[1]))
	}
	for _, match := range preloads {
		got = append(got, string(match[1]))
	}
	slices.Sort(want)
	if len(want) == 0 || !slices.Equal(got, want) || len(slices.Compact(slices.Clone(got))) != len(got) {
		t.Fatalf("preloads must name exactly the existing entry dependencies in stable order: got %v, want %v", got, want)
	}
	if !bytes.Contains(index, []byte(`<script type="module" src="/assets/app.js"></script>`)) {
		t.Fatal("the normal module entry changed")
	}
}

func TestWebStaticGzipPreservesBytesAndHTTPBehavior(t *testing.T) {
	handler := (&Server{}).AdminHandler()
	read := func(method, target, encoding, byteRange string) *httptest.ResponseRecorder {
		t.Helper()
		request := httptest.NewRequest(method, target, nil)
		request.Header.Set("Accept-Encoding", encoding)
		request.Header.Set("Range", byteRange)
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		return response
	}
	entries, err := staticFiles.ReadDir("static")
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || name == "index.html" {
			continue
		}
		t.Run(name, func(t *testing.T) {
			target := "/assets/" + name
			raw := read(http.MethodGet, target, "identity", "")
			compressed := read(http.MethodGet, target, "br, gzip;q=0.7", "")
			if raw.Code != http.StatusOK || compressed.Code != http.StatusOK || compressed.Header().Get("Content-Encoding") != "gzip" || compressed.Header().Get("Vary") != "Accept-Encoding" || raw.Header().Get("Vary") != "Accept-Encoding" {
				t.Fatal("static negotiation failed", raw.Code, compressed.Code, compressed.Header())
			}
			reader, err := gzip.NewReader(bytes.NewReader(compressed.Body.Bytes()))
			if err != nil {
				t.Fatal(err)
			}
			decoded, err := io.ReadAll(reader)
			_ = reader.Close()
			original, readErr := staticFiles.ReadFile("static/" + name)
			if err != nil || readErr != nil || !bytes.Equal(decoded, original) || !bytes.Equal(raw.Body.Bytes(), original) {
				t.Fatal("static compression changed embedded bytes", err, readErr)
			}
			again := read(http.MethodGet, target, "gzip", "")
			if !bytes.Equal(again.Body.Bytes(), compressed.Body.Bytes()) {
				t.Fatal("gzip bytes depend on request time or state")
			}
			for _, header := range []string{"Content-Type", "Cache-Control", "X-Content-Type-Options", "Accept-Ranges"} {
				if raw.Header().Get(header) != compressed.Header().Get(header) {
					t.Fatalf("gzip changed %s", header)
				}
			}
			head := read(http.MethodHead, target, "gzip", "")
			if head.Code != http.StatusOK || head.Body.Len() != 0 || head.Header().Get("Content-Length") != strconv.Itoa(compressed.Body.Len()) || head.Header().Get("Content-Encoding") != "gzip" || head.Header().Get("Content-Type") != compressed.Header().Get("Content-Type") {
				t.Fatal("HEAD does not describe the compressed GET")
			}
			for _, encoding := range []string{"", "identity", "gzip;q=0", "gzip;q=NaN"} {
				response := read(http.MethodGet, target, encoding, "")
				if response.Header().Get("Content-Encoding") != "" || !bytes.Equal(response.Body.Bytes(), original) {
					t.Fatalf("unexpected compression for %q", encoding)
				}
			}
			for _, byteRange := range []string{"bytes=1-7", "bytes=99999999-"} {
				identity := read(http.MethodGet, target, "identity", byteRange)
				response := read(http.MethodGet, target, "gzip", byteRange)
				if response.Code != identity.Code || response.Header().Get("Content-Encoding") != "" || response.Header().Get("Content-Range") != identity.Header().Get("Content-Range") || !bytes.Equal(response.Body.Bytes(), identity.Body.Bytes()) {
					t.Fatal("compression changed the existing byte-range response")
				}
			}
			for _, encoding := range []string{"identity", "gzip"} {
				request := httptest.NewRequest(http.MethodGet, target, nil)
				request.Header.Set("Accept-Encoding", encoding)
				request.Header.Set("If-None-Match", "*")
				response := httptest.NewRecorder()
				handler.ServeHTTP(response, request)
				if response.Code != http.StatusNotModified || response.Body.Len() != 0 {
					t.Fatal("compression changed the existing conditional response")
				}
			}
		})
	}
	for _, target := range []string{"/", "/topology", "/favicon.svg"} {
		raw, compressed := read(http.MethodGet, target, "identity", ""), read(http.MethodGet, target, "gzip", "")
		reader, err := gzip.NewReader(bytes.NewReader(compressed.Body.Bytes()))
		if err != nil {
			t.Fatal(target, err)
		}
		decoded, err := io.ReadAll(reader)
		_ = reader.Close()
		if err != nil || !bytes.Equal(decoded, raw.Body.Bytes()) || compressed.Header().Get("Content-Security-Policy") != raw.Header().Get("Content-Security-Policy") || compressed.Header().Get("Cache-Control") != raw.Header().Get("Cache-Control") {
			t.Fatal("compression changed the existing page or favicon response", target, err)
		}
		head := read(http.MethodHead, target, "gzip", "")
		if head.Body.Len() != 0 || head.Header().Get("Content-Length") != strconv.Itoa(compressed.Body.Len()) {
			t.Fatal("embedded HEAD differs from GET", target)
		}
		ranged := read(http.MethodGet, target, "gzip", "bytes=1-7")
		if ranged.Code != raw.Code || ranged.Header().Get("Content-Encoding") != "" || !bytes.Equal(ranged.Body.Bytes(), raw.Body.Bytes()) {
			t.Fatal("embedded page range behavior changed", target)
		}
	}
	for _, target := range []string{"/api/demo.js", "/assets/missing.js", "/assets/index.html", "/assets/demo/../app.js"} {
		identity, compressed := read(http.MethodGet, target, "identity", ""), read(http.MethodGet, target, "gzip", "")
		if identity.Code != compressed.Code || compressed.Header().Get("Content-Encoding") != "" || !bytes.Equal(identity.Body.Bytes(), compressed.Body.Bytes()) {
			t.Fatal("compression intercepted a non-asset or a redirect", target)
		}
	}
	request := httptest.NewRequest(http.MethodGet, "/assets/app.js", nil)
	request.Header.Set("Accept-Encoding", "gzip")
	response := httptest.NewRecorder()
	(&Server{}).Handler().ServeHTTP(response, request)
	if response.Code != http.StatusNotFound || strings.Contains(response.Header().Get("Content-Encoding"), "gzip") {
		t.Fatal("static compression bypassed the private TLS entry")
	}
}

package clientadapter

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestIndependentCandidateHTTPSUsesAuthenticatedExistingEntryAndOriginalTarget(t *testing.T) {
	endpoint := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/demo-target" {
			t.Error("original target path changed")
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer endpoint.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	candidate := "sha256:" + strings.Repeat("a", 64)
	finished := make(chan error, 1)
	diagnostic, err := NativeDiagnosticContext(ctx, "demo-secret", func(_ context.Context, network, address string) (net.Conn, error) {
		if network != "tcp" || address != NativeProbeAddress {
			return nil, errors.New("request escaped the existing diagnostic entry")
		}
		client, server := net.Pipe()
		go func() {
			finished <- func() error {
				defer server.Close()
				server.SetDeadline(time.Now().Add(3 * time.Second))
				read := func(n int) ([]byte, error) { b := make([]byte, n); _, err := io.ReadFull(server, b); return b, err }
				hello, err := read(2)
				if err != nil {
					return err
				}
				if _, err = read(int(hello[1])); err != nil {
					return err
				}
				if _, err = server.Write([]byte{5, 2}); err != nil {
					return err
				}
				header, err := read(2)
				if err != nil {
					return err
				}
				user, err := read(int(header[1]))
				if err != nil {
					return err
				}
				length, err := read(1)
				if err != nil {
					return err
				}
				password, err := read(int(length[0]))
				if err != nil {
					return err
				}
				if string(user) != candidate || string(password) != "demo-secret" {
					return errors.New("candidate local authentication mismatch")
				}
				if _, err = server.Write([]byte{1, 0}); err != nil {
					return err
				}
				if _, err = read(3); err != nil {
					return err
				}
				target, err := readSOCKSAddress(server)
				if err != nil {
					return err
				}
				if target != strings.TrimPrefix(endpoint.URL, "https://") {
					return errors.New("candidate target changed")
				}
				remote, err := net.Dial("tcp", target)
				if err != nil {
					return err
				}
				defer remote.Close()
				if _, err = server.Write([]byte{5, 0, 0, 1, 127, 0, 0, 1, 0, 0}); err != nil {
					return err
				}
				copied := make(chan struct{})
				go func() { io.Copy(remote, server); remote.Close(); close(copied) }()
				io.Copy(server, remote)
				server.Close()
				<-copied
				return nil
			}()
		}()
		return client, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	result := probeCandidateBusiness(diagnostic, candidate, endpoint.URL+"/demo-target", endpoint.Client().Transport.(*http.Transport).TLSClientConfig)
	if !result.Available || result.Action != "https_request" || result.Target != endpoint.URL+"/demo-target" {
		t.Fatal("actual candidate request did not complete", result)
	}
	if err := <-finished; err != nil {
		t.Fatal(err)
	}
}

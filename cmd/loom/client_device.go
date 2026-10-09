package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"runtime"
	"time"

	"loom/internal/control"
	"loom/internal/deviceclient"
)

const defaultDeviceState = "/var/lib/loom-device/state.json"

func readBoundedRegular(path string, maximum int64, private bool) ([]byte, error) {
	if path == "-" {
		body, err := io.ReadAll(io.LimitReader(os.Stdin, maximum+1))
		if err != nil || int64(len(body)) == 0 || int64(len(body)) > maximum {
			return nil, errors.New("stdin input is empty or exceeds boundary")
		}
		return body, nil
	}
	before, err := os.Lstat(path)
	if err != nil || !before.Mode().IsRegular() || before.Mode()&os.ModeSymlink != 0 || before.Size() <= 0 || before.Size() > maximum ||
		private && runtime.GOOS != "windows" && before.Mode().Perm()&0o077 != 0 {
		return nil, errors.New("input must be a bounded regular file with safe permissions")
	}
	body, err := os.ReadFile(path)
	after, statErr := os.Lstat(path)
	if err != nil || statErr != nil || !os.SameFile(before, after) || int64(len(body)) != before.Size() {
		return nil, errors.New("input changed while reading")
	}
	return body, nil
}

func cmdClientEnrollMinimal(args []string) error {
	fs := flag.NewFlagSet("client enroll", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	inviteFile := fs.String("invite-file", "", "owner-only invite file")
	stdin := fs.Bool("stdin", false, "read invite from stdin")
	statePath := fs.String("state", defaultDeviceState, "atomic device identity/LKG state")
	wait := fs.Duration("wait", 0, "retry the same enrollment transaction")
	retry := fs.Duration("retry", 2*time.Second, "resume interval while waiting")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 || (*inviteFile == "") == !*stdin || *wait < 0 || *retry <= 0 {
		return errors.New("client enroll requires exactly one of -invite-file or -stdin")
	}
	source := *inviteFile
	if *stdin {
		source = "-"
	}
	body, err := readBoundedRegular(source, 8<<20, true)
	if err != nil {
		return err
	}
	invite, err := control.DecodeInvite(string(bytes.TrimSpace(body)))
	if err != nil {
		return errors.New("enrollment invite is invalid")
	}
	store, err := deviceclient.Open(*statePath, invite)
	if err != nil {
		return err
	}
	deadline := time.Now().Add(*wait)
	// A saved View resumes with device authentication. The original bootstrap
	// endpoint may already be retired; it must not be needed to reinstall.
	claimed := store.LKG() != nil
	for {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		var response control.EnrollmentResponse
		var claimErr error
		if claimed {
			response, claimErr = deviceclient.Resume(ctx, store)
		} else {
			response, claimErr = deviceclient.Claim(ctx, store)
		}
		cancel()
		if claimErr != nil {
			return claimErr
		}
		if response.State == "completed" {
			if response.DeviceView == nil {
				return errors.New("completed enrollment response has no certified device view")
			}
			fmt.Printf("device enrollment completed: device=%s view=%s\n", response.DeviceView.View.DeviceID, response.DeviceView.ViewDigest)
			return nil
		}
		fmt.Printf("device enrollment %s: transaction=%s device=%s\n", response.State,
			response.TransactionID, invite.Material.Payload.(control.Invite).DeviceID)
		claimed = true
		if *wait == 0 || time.Now().Add(*retry).After(deadline) {
			return nil
		}
		time.Sleep(*retry)
	}
}

func cmdClientSync(args []string) error {
	fs := flag.NewFlagSet("client sync", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	statePath := fs.String("state", defaultDeviceState, "atomic device identity/LKG state")
	viewPath := fs.String("view", "", "explicit owner-only current signed DeviceView file")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 || *viewPath == "-" {
		return errors.New("client sync accepts an optional private -view file, not positional arguments or stdin")
	}
	store, err := deviceclient.Load(*statePath)
	if err != nil {
		return err
	}
	var envelope control.DeviceViewEnvelope
	if *viewPath == "" {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		envelope, err = deviceclient.Sync(ctx, store)
	} else {
		body, readErr := readBoundedRegular(*viewPath, 5<<20, true)
		if readErr != nil {
			return readErr
		}
		defer clear(body)
		envelope, err = deviceclient.ImportView(store, body)
	}
	if err != nil {
		return err
	}
	fmt.Printf("authenticated device view saved; runtime application requires separate readback: device=%s view=%s endpoints=%d routes=%d\n", envelope.View.DeviceID, envelope.ViewDigest, len(envelope.View.Endpoints), len(envelope.View.Routes))
	return nil
}

func cmdClientMigrateTransport(args []string) error {
	fs := flag.NewFlagSet("client migrate-transport", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	statePath := fs.String("state", defaultDeviceState, "existing device identity")
	viewPath := fs.String("view", "", "new canonical certified View, owner-only")
	evidence := fs.String("evidence", "", "protected original-state evidence file")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 || *viewPath == "" || *evidence == "" {
		return errors.New("client migrate-transport requires -view and -evidence")
	}
	body, err := readBoundedRegular(*viewPath, 5<<20, true)
	if err != nil {
		return err
	}
	defer clear(body)
	var envelope control.DeviceViewEnvelope
	if err := control.DecodeCanonical(body, &envelope, control.ContractDecodeLimits{MaxBytes: 5 << 20, MaxDepth: 128, MaxItems: 1 << 20}); err != nil {
		return err
	}
	if err := deviceclient.MigrateTransportFile(*statePath, *evidence, envelope, nil); err != nil {
		return err
	}
	fmt.Println("transport configuration advanced; identity, authenticated floors and original signed evidence preserved; runtime activation requires separate readback")
	return nil
}

func cmdClientInspect(args []string) error {
	fs := flag.NewFlagSet("client inspect", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	statePath := fs.String("state", defaultDeviceState, "atomic device identity/LKG state")
	identityOnly := fs.Bool("identity", false, "read public identity coordinates, including an unclaimed identity")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return errors.New("client inspect does not accept positional arguments")
	}
	store, err := deviceclient.Load(*statePath)
	if err != nil {
		return err
	}
	identity, err := store.IdentityReadback()
	if err != nil {
		return err
	}
	if *identityOnly {
		body, err := control.CanonicalEncode(identity)
		if err != nil {
			return err
		}
		_, err = os.Stdout.Write(append(body, '\n'))
		return err
	}
	lkg := store.LKG()
	result := struct {
		PossiblePermissionRestoration bool                     `json:"possible_permission_restoration"`
		Joined                        bool                     `json:"joined"`
		DeviceID                      string                   `json:"device_id,omitempty"`
		ViewDigest                    string                   `json:"view_digest,omitempty"`
		FactFrontier                  []control.FactFrontier   `json:"fact_frontier"`
		Endpoints                     int                      `json:"endpoints,omitempty"`
		Routes                        int                      `json:"routes,omitempty"`
		Candidates                    []control.RouteCandidate `json:"route_candidates"`
	}{PossiblePermissionRestoration: store.PossiblePermissionRestoration(), Joined: lkg != nil, DeviceID: identity.DeviceID, Candidates: []control.RouteCandidate{}}
	if lkg != nil {
		result.DeviceID, result.ViewDigest, result.FactFrontier = lkg.View.DeviceID, lkg.ViewDigest, lkg.FactFrontier
		result.Endpoints, result.Routes = len(lkg.View.Endpoints), len(lkg.View.Routes)
		result.Candidates = append(result.Candidates, lkg.View.Routes...)
	}
	return json.NewEncoder(os.Stdout).Encode(result)
}

func cmdClientWebsiteRoot(args []string) error {
	fs := flag.NewFlagSet("client website-root", flag.ContinueOnError)
	statePath := fs.String("state", defaultDeviceState, "atomic device identity/LKG state")
	id := fs.String("id", "", "explicit certified website root identity")
	output := fs.String("o", "", "public PEM output in an existing private directory")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 || (*id == "") != (*output == "") {
		return errors.New("website-root lists roots, or requires both id and output for export")
	}
	store, err := deviceclient.Load(*statePath)
	if err != nil {
		return err
	}
	view := store.LKG()
	if view == nil {
		return errors.New("website roots require an authenticated device View")
	}
	if *id == "" {
		return json.NewEncoder(os.Stdout).Encode(append([]control.PublicTrust{}, view.View.PublicTrust...))
	}
	for _, value := range view.View.PublicTrust {
		if value.ID != *id {
			continue
		}
		body, err := control.WebsiteTrustPEM(value, time.Now())
		if err != nil {
			return err
		}
		if err := putWebsitePublicFile(*output, body); err != nil {
			return err
		}
		return json.NewEncoder(os.Stdout).Encode(map[string]any{"id": value.ID, "public_certificate_exported": true, "system_trust_installed": false})
	}
	return errors.New("selected website root is absent from the authenticated View")
}

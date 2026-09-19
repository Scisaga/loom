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
	wait := fs.Duration("wait", 0, "wait for administrator approval")
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
	body, err := readBoundedRegular(source, 64<<10, true)
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
	claimed := false
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
		if response.Transaction.State == "completed" {
			if response.DeviceView == nil {
				return errors.New("completed enrollment response has no certified device view")
			}
			fmt.Printf("device enrollment completed: device=%s head=%s floor=%d\n", response.Transaction.Intent.DeviceID,
				control.HeadID(response.DeviceView.Head), response.DeviceView.View.Floor)
			return nil
		}
		fmt.Printf("device enrollment %s: transaction=%s device=%s\n", response.Transaction.State,
			response.Transaction.ID, response.Transaction.Intent.DeviceID)
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
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return errors.New("client sync does not accept positional arguments")
	}
	store, err := deviceclient.Load(*statePath)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	envelope, err := deviceclient.Sync(ctx, store)
	if err != nil {
		return err
	}
	fmt.Printf("device view synchronized: device=%s head=%s floor=%d endpoints=%d routes=%d\n",
		envelope.View.DeviceID, control.HeadID(envelope.Head), envelope.Head.Index, len(envelope.View.Endpoints), len(envelope.View.Routes))
	return nil
}

func cmdClientInspect(args []string) error {
	fs := flag.NewFlagSet("client inspect", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	statePath := fs.String("state", defaultDeviceState, "atomic device identity/LKG state")
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
	lkg := store.LKG()
	result := struct {
		Joined    bool   `json:"joined"`
		DeviceID  string `json:"device_id,omitempty"`
		Head      string `json:"head,omitempty"`
		Floor     uint64 `json:"floor,omitempty"`
		Endpoints int    `json:"endpoints,omitempty"`
		Routes    int    `json:"routes,omitempty"`
	}{Joined: lkg != nil}
	if lkg != nil {
		result.DeviceID, result.Head, result.Floor = lkg.View.DeviceID, control.HeadID(lkg.Head), lkg.Head.Index
		result.Endpoints, result.Routes = len(lkg.View.Endpoints), len(lkg.View.Routes)
	}
	return json.NewEncoder(os.Stdout).Encode(result)
}

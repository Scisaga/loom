package linuxclient

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestWireGuardViewTransitionPreservesOnlyLiveOwnedExecution(t *testing.T) {
	for _, change := range []string{"unchanged", "changed", "withdrawn", "replacement", "missing-route", "cleanup-failure"} {
		t.Run(change, func(t *testing.T) {
			options, profile, identity, load, save := wireGuardFixture(t)
			options.Config = filepath.Join(t.TempDir(), "config.json")
			current, err := applyWireGuard(profile, nil, identity, options)
			if err != nil {
				t.Fatal(err)
			}
			original := current
			journal, err := os.ReadFile(options.Config + ".wg-ownership")
			if err != nil {
				t.Fatal(err)
			}
			host := load()
			alias := host.Link.Alias
			host.Calls = nil
			switch change {
			case "changed", "cleanup-failure":
				profile.WireGuard[0].LinkID = "demo-replacement-link"
				if change == "cleanup-failure" {
					host.Fail = "delete"
				}
			case "withdrawn":
				profile.WireGuard = nil
			case "replacement":
				host.Link.Index++
			case "missing-route":
				host.Routes = nil
			}
			save(host)
			err = replaceWireGuard(&current, *profile, identity, options)
			host = load()
			switch change {
			case "unchanged":
				after, readErr := os.ReadFile(options.Config + ".wg-ownership")
				if err != nil || current != original || host.Link.Alias != alias || readErr != nil || !bytes.Equal(journal, after) {
					t.Fatal("unchanged execution replaced its live handle or crash-cleanup evidence", err)
				}
			case "changed":
				if err != nil || current == original || host.Link == nil || host.Link.Alias == alias {
					t.Fatal("changed execution retained the old generation", err)
				}
				deleted := false
				for _, call := range host.Calls {
					command := strings.Join(call, " ")
					if strings.Contains(command, "link delete") {
						deleted = true
					}
					if strings.Contains(command, "link add") && !deleted {
						t.Fatal("new execution was applied before old execution was removed")
					}
				}
			case "withdrawn":
				if err != nil || host.Link != nil {
					t.Fatal("withdrawal retained the old execution", err)
				}
			case "replacement":
				if !errors.Is(err, ErrWireGuardOwnership) || host.Link == nil {
					t.Fatal("replacement interface was adopted or deleted", err)
				}
			case "missing-route":
				if err == nil || host.Link == nil {
					t.Fatal("incomplete kernel execution was accepted or silently repaired")
				}
			case "cleanup-failure":
				if !errors.Is(err, ErrWireGuardCleanup) || current != original || host.Link == nil || host.Link.Alias != alias {
					t.Fatal("cleanup failure lost ownership or applied a replacement", err)
				}
			}
			if change == "unchanged" || change == "replacement" || change == "missing-route" || change == "cleanup-failure" {
				for _, call := range host.Calls {
					command := strings.Join(call, " ")
					if strings.Contains(command, "link add") || strings.Contains(command, "address add") || strings.Contains(command, "route add") || strings.Contains(command, "wg set") || change != "cleanup-failure" && strings.Contains(command, "link delete") {
						t.Fatal("reuse mutated kernel execution", command)
					}
				}
			}
		})
	}
}

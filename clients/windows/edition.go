package main

import "fmt"

type clientEdition string

const (
	editionInstalled     clientEdition = "installed"
	editionPortableMixed clientEdition = "portable-mixed"
	editionPortableTUN   clientEdition = "portable-tun"
)

// buildEdition is fixed by the release build with -X main.buildEdition=....
// Keeping the default on installed preserves the behavior of ordinary
// `go build ./clients/windows` and existing Service development builds.
var buildEdition = string(editionInstalled)

// buildPlatformPublicKey is the public, non-secret deployment trust root
// embedded by the Windows packaging script. It lets the client reject a
// corrupt or foreign sidecar before sending a one-time join code to the
// control plane.
var buildPlatformPublicKey string

func configuredEdition() (clientEdition, error) {
	edition := clientEdition(buildEdition)
	switch edition {
	case editionInstalled, editionPortableMixed, editionPortableTUN:
		return edition, nil
	default:
		return "", fmt.Errorf("unsupported Windows client edition %q", buildEdition)
	}
}

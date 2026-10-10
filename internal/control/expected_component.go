package control

import (
	"errors"
	"sort"
	"strings"
)

// ExpectedComponent names one program in an immutable, independently signed
// package. Program versions and hashes are resolved, never copied into facts.
type ExpectedComponent struct {
	ID             string `json:"id"`
	NodeID         string `json:"node_id"`
	ComponentID    string `json:"component_id"`
	Platform       string `json:"platform"`
	CatalogDigest  string `json:"catalog_digest"`
	ManifestDigest string `json:"manifest_digest"`
}

func ExpectedComponentID(node, component, platform string) (string, error) {
	return digestContractValue("loom-expected-component-v3\x00", map[string]any{"node_id": node, "component_id": component, "platform": platform})
}

func expectedComponentSupported(component, platform string) bool {
	switch platform {
	case "linux-amd64", "linux-arm64", "android-amd64", "android-arm64":
		return component == "agent" || component == "sing-box"
	case "windows-amd64", "windows-arm64":
		return component == "agent" || component == "sing-box" || component == "wintun"
	}
	return false
}

func (value ExpectedComponent) Validate() error {
	id, err := ExpectedComponentID(value.NodeID, value.ComponentID, value.Platform)
	if err != nil || value.ID != id || ValidateID(value.NodeID) != nil || value.NodeID == "direct" || !expectedComponentSupported(value.ComponentID, value.Platform) || ValidateDigest(value.CatalogDigest) != nil || ValidateDigest(value.ManifestDigest) != nil {
		return errors.New("expected component coordinates are invalid")
	}
	return nil
}

func expectedComponentLess(a, b ExpectedComponent) bool {
	if a.NodeID != b.NodeID {
		return a.NodeID < b.NodeID
	}
	return a.ComponentID < b.ComponentID || a.ComponentID == b.ComponentID && a.Platform < b.Platform
}

var errExpectedRelease = errors.New("expected component release is unavailable or does not match its reference")

// The caller supplies sets from the independent release verifier. This mapping
// is pure and never reads the mutable release current pointer.
func resolveExpectedComponent(value ExpectedComponent, sets []ReleaseSet) (ComponentReadback, error) {
	var result ComponentReadback
	matches := 0
	for _, set := range sets {
		if set.ID != value.CatalogDigest {
			continue
		}
		for _, pkg := range set.Packages {
			androidAPK := pkg.Entry.ComponentID == "android-application" && pkg.Entry.Platform == "android-any" && (value.Platform == "android-amd64" || value.Platform == "android-arm64")
			if pkg.Entry.ManifestDigest != value.ManifestDigest || pkg.Entry.Platform != value.Platform && !androidAPK {
				continue
			}
			for _, actual := range pkg.Components {
				if actual.ComponentID == value.ComponentID && actual.Platform == value.Platform && actual.Validate() == nil {
					result, matches = actual, matches+1
				}
			}
		}
	}
	if value.Validate() != nil || matches != 1 {
		return ComponentReadback{}, errExpectedRelease
	}
	return result, nil
}

func deviceExpectedComponents(projection Projection, node string, sets []ReleaseSet) ([]ComponentReadback, error) {
	result := []ComponentReadback{}
	// Conflicts have no projected value. Their stable identity still identifies
	// the affected device, so absence cannot silently become an empty expectation.
	for _, platform := range []string{"linux-amd64", "linux-arm64", "windows-amd64", "windows-arm64", "android-amd64", "android-arm64"} {
		for _, component := range []string{"agent", "sing-box", "wintun"} {
			if !expectedComponentSupported(component, platform) {
				continue
			}
			id, _ := ExpectedComponentID(node, component, platform)
			if target, found := projection.CurrentTarget("expected_component", id); found && target.Conflicted {
				return nil, errors.New("component expectation is conflicted")
			}
		}
	}
	for _, value := range projection.NetworkIntent.ExpectedComponents {
		if value.NodeID != node {
			continue
		}
		component, err := resolveExpectedComponent(value, sets)
		if err != nil {
			return nil, err
		}
		result = append(result, component)
	}
	sort.Slice(result, func(i, j int) bool {
		return result[i].ComponentID < result[j].ComponentID || result[i].ComponentID == result[j].ComponentID && result[i].Platform < result[j].Platform
	})
	return result, nil
}

func validateExpectedNode(value ExpectedComponent, projection Projection) error {
	node, found := identityFor(projection, value.NodeID)
	if !found || !strings.HasPrefix(value.Platform, node.Platform+"-") {
		return errors.New("expected component has no matching authorized device platform")
	}
	return nil
}

// Missing signed release metadata does not invalidate or erase a reference. Only its
// affected executable projection fails; restored original files permit retry.
func (server *Server) expectedReleaseSets(projection Projection, verified ...ReleaseSet) []ReleaseSet {
	sets := []ReleaseSet{}
	if server.Releases == nil {
		return sets
	}
	seen := map[string]bool{}
	for _, value := range projection.NetworkIntent.ExpectedComponents {
		if seen[value.CatalogDigest] || validateExpectedNode(value, projection) != nil {
			continue
		}
		seen[value.CatalogDigest] = true
		found := false
		for _, set := range verified {
			if set.ID == value.CatalogDigest {
				sets = append(sets, set)
				found = true
				break
			}
		}
		if found {
			continue
		}
		if set, err := server.Releases.ReadCatalog(value.CatalogDigest); err == nil {
			sets = append(sets, set)
		}
	}
	return sets
}

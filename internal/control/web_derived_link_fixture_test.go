package control

import "testing"

func webRelayLink(t *testing.T, projection Projection, from, to string) NetworkLink {
	t.Helper()
	links, err := DerivedNetworkLinks(projection)
	if err != nil {
		t.Fatal(err)
	}
	for _, link := range links {
		if link.FromNodeID == from && link.ToNodeID == to {
			return link
		}
	}
	t.Fatal("fixture has no eligible derived relay", from, to)
	return NetworkLink{}
}

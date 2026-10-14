package control

import "testing"

func testDerivedLink(t *testing.T, projection Projection, from, to string) NetworkLink {
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
	t.Fatalf("no authorized derived relay from %s to %s", from, to)
	return NetworkLink{}
}

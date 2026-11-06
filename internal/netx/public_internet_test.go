package netx

import (
	"net"
	"net/netip"
	"testing"
)

func TestPublicInternetCaptureAgreesWithFinalAddressGuard(t *testing.T) {
	var allowed []netip.Prefix
	for _, text := range PublicInternetPrefixes() {
		prefix := netip.MustParsePrefix(text)
		if prefix.Bits() == 0 || prefix != prefix.Masked() || !IsPublicInternetAddress(prefix.Addr()) {
			t.Fatal("capture has an implicit default or a non-public boundary")
		}
		for _, denied := range publicInternetExclusions {
			if prefix.Overlaps(denied) {
				t.Fatal("capture contains an address rejected by the final guard")
			}
		}
		allowed = append(allowed, prefix)
	}
	contains := func(address netip.Addr) bool {
		for _, prefix := range allowed {
			if prefix.Contains(address) {
				return true
			}
		}
		return false
	}
	// Check both sides of every exclusion boundary, rather than relying on
	// a few websites or on the number of prefixes produced by the projector.
	for _, prefix := range publicInternetExclusions {
		address := prefix.Addr()
		raw := address.AsSlice()
		mask := net.CIDRMask(prefix.Bits(), address.BitLen())
		for i := range raw {
			raw[i] |= ^mask[i]
		}
		last, _ := netip.AddrFromSlice(raw)
		for _, sample := range []netip.Addr{address.Prev(), address, address.Next(), last, last.Next()} {
			if sample.IsValid() && contains(sample) != IsPublicInternetAddress(sample) {
				t.Fatal("capture and the final address guard disagree at an exclusion boundary")
			}
		}
	}
	if len(allowed) == 0 {
		t.Fatal("ordinary Internet has no positive capture ranges")
	}
}

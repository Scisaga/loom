package model

const maxNodeIDLen = 63

// ValidNodeID reports whether id is safe to use as a node's canonical identity.
//
// Node IDs cross several boundaries: they become a DNS label, a snapshot path,
// a systemd/unit fragment and a routing tag.  Keep one deliberately small ASCII
// grammar at the model boundary so those consumers cannot disagree about which
// separators or aliases are meaningful.  Lowercase is intentional: DNS/SNI
// compares names case-insensitively while paths and tags do not.
func ValidNodeID(id string) bool {
	if len(id) == 0 || len(id) > maxNodeIDLen {
		return false
	}
	for i := 0; i < len(id); i++ {
		c := id[i]
		if (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') {
			continue
		}
		if c != '-' || i == 0 || i == len(id)-1 {
			return false
		}
	}
	return true
}

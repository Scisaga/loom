package publish

// Bundle is the immutable per-device configuration payload referenced by a
// signed snapshot manifest. It is deliberately available on every platform;
// the publisher itself remains a non-Windows control-plane component.
type Bundle struct {
	Owner string            `json:"owner"`
	Files map[string]string `json:"files"`
}

// Current is the narrowly supported unsigned legacy pointer. New clients must
// consume DeploymentCurrent; this shape remains for the one-way fleet migration.
type Current struct {
	Snapshot    string `json:"snapshot"`
	PublishedAt string `json:"published_at"`
}

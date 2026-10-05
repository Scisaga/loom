package publish

// Bundle is the original payload shape used only to verify archived signed
// snapshots. It cannot supply current runtime or control inputs.
type Bundle struct {
	Owner string            `json:"owner"`
	Files map[string]string `json:"files"`
}

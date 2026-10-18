package control

import (
	"bytes"
	"encoding/json"
	"reflect"
	"sort"
	"strconv"
	"time"
)

type webChange struct {
	Path   []string        `json:"path"`
	Value  json.RawMessage `json:"value,omitempty"`
	Remove bool            `json:"remove,omitempty"`
}
type webLiveMessage struct {
	Schema   int             `json:"schema"`
	Snapshot json.RawMessage `json:"snapshot,omitempty"`
	Changes  []webChange     `json:"changes,omitempty"`
}

func appendWebChange(changes *[]webChange, path []string, value any, remove bool) error {
	change := webChange{Path: append([]string{}, path...), Remove: remove}
	if !remove {
		body, err := json.Marshal(value)
		if err != nil {
			return err
		}
		change.Value = body
	}
	*changes = append(*changes, change)
	return nil
}
func diffWebValue(previous, current any, path []string, changes *[]webChange) error {
	if reflect.DeepEqual(previous, current) {
		return nil
	}
	if before, ok := previous.(map[string]any); ok {
		if after, ok := current.(map[string]any); ok {
			keys := map[string]bool{}
			for key := range before {
				keys[key] = true
			}
			for key := range after {
				keys[key] = true
			}
			ordered := make([]string, 0, len(keys))
			for key := range keys {
				ordered = append(ordered, key)
			}
			sort.Strings(ordered)
			for _, key := range ordered {
				a, had := before[key]
				b, has := after[key]
				next := append(append([]string{}, path...), key)
				if !has {
					if err := appendWebChange(changes, next, nil, true); err != nil {
						return err
					}
				} else if !had {
					if err := appendWebChange(changes, next, b, false); err != nil {
						return err
					}
				} else if err := diffWebValue(a, b, next, changes); err != nil {
					return err
				}
			}
			return nil
		}
	}
	if before, ok := previous.([]any); ok {
		if after, ok := current.([]any); ok && len(before) == len(after) {
			for i := range before {
				if err := diffWebValue(before[i], after[i], append(append([]string{}, path...), strconv.Itoa(i)), changes); err != nil {
					return err
				}
			}
			return nil
		}
	}
	return appendWebChange(changes, path, current, false)
}
func encodeWebLive(previous, current []byte) ([]byte, error) {
	if bytes.Equal(previous, current) {
		return nil, nil
	}
	full, err := json.Marshal(webLiveMessage{Schema: 3, Snapshot: current})
	if err != nil {
		return nil, err
	}
	if previous == nil {
		return full, nil
	}
	values := [2]any{}
	for i, body := range [][]byte{previous, current} {
		decoder := json.NewDecoder(bytes.NewReader(body))
		decoder.UseNumber()
		if err := decoder.Decode(&values[i]); err != nil {
			return nil, err
		}
	}
	changes := []webChange{}
	if err := diffWebValue(values[0], values[1], nil, &changes); err != nil {
		return nil, err
	}
	if len(changes) == 0 {
		return nil, nil
	}
	for _, change := range changes {
		for _, key := range change.Path {
			if key == "__proto__" || key == "prototype" || key == "constructor" {
				return full, nil
			}
		}
	}
	delta, err := json.Marshal(webLiveMessage{Schema: 3, Changes: changes})
	if err != nil {
		return nil, err
	}
	if len(delta) >= len(full) {
		return full, nil
	}
	return delta, nil
}

// Browsers derive the countdown from the authenticated absolute validity dates.
// The CLI's diagnosis retains its remaining-seconds value.
func webEndpointCertificates(root, owner string, projection Projection, now time.Time) []EndpointCertificateReadback {
	values := EndpointCertificateReadbacks(root, owner, projection, now)
	for i := range values {
		values[i].RemainingSeconds = nil
	}
	return values
}

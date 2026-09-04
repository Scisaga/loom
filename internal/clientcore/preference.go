// Package clientcore contains platform-independent client state machines.
//
// Platform hosts may persist preferences and expose UI, but they must not grow
// a second matcher, policy, or route model. Everything accepted here is bounded
// by the last verified policy supplied by the control plane.
package clientcore

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"

	"loom/internal/model"
)

const (
	PreferenceSchema = 1
	PolicySchema     = 1
	maxPreference    = 16 << 10
)

// Mode is the only client-writable routing preference.
type Mode string

const (
	Direct    Mode = "direct"
	Auto      Mode = "auto"
	FixedExit Mode = "fixed_exit"
)

// Preference is local state, not SSOT. Exit is set only for FixedExit.
type Preference struct {
	Schema int    `json:"schema"`
	Mode   Mode   `json:"mode"`
	Exit   string `json:"exit,omitempty"`
}

// Exit is one server the last verified configuration authorizes this device
// to use as a final egress. The client may select IDs from this list only.
type Exit struct {
	ID   string `json:"id"`
	Name string `json:"name,omitempty"`
}

// Policy is the minimal signed-policy projection needed by local preference
// handling. It deliberately contains no mutable matcher or Service fields.
type Policy struct {
	Schema int    `json:"schema"`
	Exits  []Exit `json:"exits,omitempty"`
}

// Decision is the effective top-level behavior. Blocked preserves the user's
// choice for display while preventing a removed exit from silently becoming
// Direct or Auto.
type Decision struct {
	Mode        Mode
	Exit        string
	Blocked     bool
	BlockReason string
}

var ErrExitNotAuthorized = errors.New("requested exit is not authorized by the verified policy")

func (p Preference) Validate() error {
	if p.Schema != PreferenceSchema {
		return fmt.Errorf("unsupported preference schema %d", p.Schema)
	}
	switch p.Mode {
	case Direct, Auto:
		if p.Exit != "" {
			return fmt.Errorf("mode %s must not carry exit %q", p.Mode, p.Exit)
		}
	case FixedExit:
		if !model.ValidNodeID(p.Exit) {
			return fmt.Errorf("fixed_exit requires a valid exit node id, got %q", p.Exit)
		}
	default:
		return fmt.Errorf("unsupported route mode %q", p.Mode)
	}
	return nil
}

func (p Policy) Validate() error {
	if p.Schema != PolicySchema {
		return fmt.Errorf("unsupported policy schema %d", p.Schema)
	}
	seen := make(map[string]struct{}, len(p.Exits))
	for _, exit := range p.Exits {
		if !model.ValidNodeID(exit.ID) {
			return fmt.Errorf("policy contains invalid exit node id %q", exit.ID)
		}
		if _, duplicate := seen[exit.ID]; duplicate {
			return fmt.Errorf("policy contains duplicate exit %q", exit.ID)
		}
		seen[exit.ID] = struct{}{}
	}
	return nil
}

// AuthorizeChange validates a new user choice against the last verified
// policy. It prevents a UI or local caller from expanding the signed exit set.
func AuthorizeChange(next Preference, policy Policy) error {
	if err := next.Validate(); err != nil {
		return err
	}
	if err := policy.Validate(); err != nil {
		return err
	}
	if next.Mode != FixedExit {
		return nil
	}
	for _, exit := range policy.Exits {
		if exit.ID == next.Exit {
			return nil
		}
	}
	return fmt.Errorf("%w: %s", ErrExitNotAuthorized, next.Exit)
}

// Evaluate applies an already-persisted preference to a newer verified
// policy. A removed fixed exit is retained but blocked, never rewritten.
func Evaluate(saved Preference, policy Policy) (Decision, error) {
	if err := saved.Validate(); err != nil {
		return Decision{}, err
	}
	if err := policy.Validate(); err != nil {
		return Decision{}, err
	}
	decision := Decision{Mode: saved.Mode, Exit: saved.Exit}
	if saved.Mode != FixedExit {
		return decision, nil
	}
	for _, exit := range policy.Exits {
		if exit.ID == saved.Exit {
			return decision, nil
		}
	}
	decision.Blocked = true
	decision.BlockReason = "selected exit is no longer authorized by the verified policy"
	return decision, nil
}

// SortedExits returns a UI-safe copy. Sorting here prevents platform shells
// from inventing different ordering rules for the same signed policy.
func SortedExits(policy Policy) ([]Exit, error) {
	if err := policy.Validate(); err != nil {
		return nil, err
	}
	out := append([]Exit(nil), policy.Exits...)
	sort.Slice(out, func(i, j int) bool {
		if out[i].Name != out[j].Name {
			return out[i].Name < out[j].Name
		}
		return out[i].ID < out[j].ID
	})
	return out, nil
}

// ParsePreference strictly accepts exactly one small JSON object.
func ParsePreference(body []byte) (Preference, error) {
	var out Preference
	if len(body) == 0 || len(body) > maxPreference {
		return out, errors.New("preference must be between 1 byte and 16 KiB")
	}
	if err := rejectDuplicateJSONKeys(body); err != nil {
		return out, fmt.Errorf("invalid preference JSON: %w", err)
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&out); err != nil {
		return Preference{}, fmt.Errorf("decode preference: %w", err)
	}
	var trailing any
	if err := dec.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			err = errors.New("additional JSON value")
		}
		return Preference{}, fmt.Errorf("decode preference trailing content: %w", err)
	}
	if err := out.Validate(); err != nil {
		return Preference{}, err
	}
	return out, nil
}

func EncodePreference(p Preference) ([]byte, error) {
	if err := p.Validate(); err != nil {
		return nil, err
	}
	body, err := json.MarshalIndent(&p, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(body, '\n'), nil
}

func rejectDuplicateJSONKeys(body []byte) error {
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()
	if err := walkJSONValue(dec); err != nil {
		return err
	}
	var trailing any
	if err := dec.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("additional JSON value")
		}
		return err
	}
	return nil
}

func walkJSONValue(dec *json.Decoder) error {
	token, err := dec.Token()
	if err != nil {
		return err
	}
	delim, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delim {
	case '{':
		seen := map[string]struct{}{}
		for dec.More() {
			keyToken, err := dec.Token()
			if err != nil {
				return err
			}
			key, ok := keyToken.(string)
			if !ok {
				return errors.New("object key is not a string")
			}
			if _, duplicate := seen[key]; duplicate {
				return fmt.Errorf("duplicate field %q", key)
			}
			seen[key] = struct{}{}
			if err := walkJSONValue(dec); err != nil {
				return err
			}
		}
		end, err := dec.Token()
		if err != nil || end != json.Delim('}') {
			return errors.New("object did not terminate")
		}
	case '[':
		for dec.More() {
			if err := walkJSONValue(dec); err != nil {
				return err
			}
		}
		end, err := dec.Token()
		if err != nil || end != json.Delim(']') {
			return errors.New("array did not terminate")
		}
	default:
		return fmt.Errorf("unexpected delimiter %q", delim)
	}
	return nil
}

package loomcore

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

const (
	maxInviteBytes   = 16 << 10
	maxResponseBytes = 4 << 20
	maxCurrentBytes  = 1 << 20
	maxManifestBytes = 4 << 20
	maxBundleBytes   = 16 << 20
	maxBundleFiles   = 64
)

// decodeStrictJSON is shared by every authenticated or persisted JSON
// boundary in this package. encoding/json normally accepts duplicate keys and
// keeps the last value, which lets different readers disagree about what was
// signed. Walking first makes that ambiguity fail closed at every depth.
func decodeStrictJSON(body []byte, maximum int, target any) error {
	if len(body) == 0 || len(body) > maximum {
		return fmt.Errorf("JSON size must be between 1 and %d bytes", maximum)
	}
	if err := rejectDuplicateJSONKeys(body); err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			err = errors.New("additional JSON value")
		}
		return fmt.Errorf("trailing content: %w", err)
	}
	return nil
}

func rejectDuplicateJSONKeys(body []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.UseNumber()
	if err := walkJSONValue(decoder); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			err = errors.New("additional JSON value")
		}
		return err
	}
	return nil
}

func walkJSONValue(decoder *json.Decoder) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delimiter {
	case '{':
		seen := map[string]bool{}
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return err
			}
			key, ok := keyToken.(string)
			if !ok {
				return errors.New("JSON object key is not a string")
			}
			if seen[key] {
				return fmt.Errorf("duplicate JSON field %q", key)
			}
			seen[key] = true
			if err := walkJSONValue(decoder); err != nil {
				return err
			}
		}
		end, err := decoder.Token()
		if err != nil {
			return err
		}
		if end != json.Delim('}') {
			return errors.New("JSON object did not terminate")
		}
	case '[':
		for decoder.More() {
			if err := walkJSONValue(decoder); err != nil {
				return err
			}
		}
		end, err := decoder.Token()
		if err != nil {
			return err
		}
		if end != json.Delim(']') {
			return errors.New("JSON array did not terminate")
		}
	default:
		return fmt.Errorf("unexpected JSON delimiter %q", delimiter)
	}
	return nil
}

func validNodeID(id string) bool {
	if len(id) == 0 || len(id) > 63 {
		return false
	}
	for i := 0; i < len(id); i++ {
		character := id[i]
		if (character >= 'a' && character <= 'z') || (character >= '0' && character <= '9') {
			continue
		}
		if character != '-' || i == 0 || i == len(id)-1 {
			return false
		}
	}
	return true
}

func validLowerHex(value string, length int) bool {
	if len(value) != length {
		return false
	}
	for i := 0; i < len(value); i++ {
		character := value[i]
		if (character < '0' || character > '9') && (character < 'a' || character > 'f') {
			return false
		}
	}
	return true
}

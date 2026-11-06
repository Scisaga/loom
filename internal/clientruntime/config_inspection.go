package clientruntime

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

// HasServerInbound reports whether an already-installed sing-box configuration
// owns a server-facing listener.  Linux client installation uses this before it
// retires the old units: a client-only RuntimeProfile is not a replacement for
// a server data-plane listener on the same host.
//
// The inspection is deliberately narrow. TUN and mixed are the two local
// capture shapes used by clients. Hysteria2 and Trojan are server listeners.
// An unknown inbound fails closed instead of being guessed to be disposable.
func HasServerInbound(body []byte) (bool, error) {
	if len(body) == 0 || len(body) > maxSingBoxBytes {
		return false, errors.New("sing-box config has invalid size")
	}
	if err := rejectDuplicateJSONKeys(body); err != nil {
		return false, err
	}
	var config struct {
		Endpoints []struct {
			Type       string `json:"type"`
			System     bool   `json:"system"`
			ListenPort int    `json:"listen_port"`
		} `json:"endpoints"`
		Inbounds []struct {
			Type string `json:"type"`
		} `json:"inbounds"`
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	if err := decoder.Decode(&config); err != nil {
		return false, fmt.Errorf("decode sing-box config: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return false, errors.New("sing-box config has trailing content")
	}
	for _, endpoint := range config.Endpoints {
		if endpoint.System || endpoint.ListenPort != 0 {
			return true, nil
		}
	}
	for _, inbound := range config.Inbounds {
		switch inbound.Type {
		case "tun", "mixed", "socks":
		case "hysteria2", "trojan":
			return true, nil
		default:
			return false, fmt.Errorf("cannot prove ownership of inbound type %q", inbound.Type)
		}
	}
	return false, nil
}

func rejectDuplicateJSONKeys(body []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.UseNumber()
	if err := walkJSONValue(decoder); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return errors.New("JSON contains trailing content")
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
		_, err = decoder.Token()
		return err
	case '[':
		for decoder.More() {
			if err := walkJSONValue(decoder); err != nil {
				return err
			}
		}
		_, err = decoder.Token()
		return err
	default:
		return errors.New("unexpected JSON delimiter")
	}
}

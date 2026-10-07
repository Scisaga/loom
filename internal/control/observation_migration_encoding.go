package control

import (
	"bytes"
	"encoding/json"
	"errors"
)

// Only the explicitly invoked, one-time schema 3 container migration reads this
// bounded input. Normal report persistence has no aggregate JSON file.
const maxObservationStateBytes = maxControlInputBytes

// This schema 3 container is decoded only by the explicit offline migration.
type observationState struct {
	Schema  int            `json:"schema"`
	Reports []DeviceReport `json:"reports"`
}

func (state observationState) Validate() error {
	if state.Schema != 3 || state.Reports == nil {
		return errors.New("observation collection schema is invalid")
	}
	var previous []byte
	for index, report := range state.Reports {
		body, err := CanonicalEncode(report)
		if err != nil {
			return err
		}
		if index > 0 && !reportBefore(state.Reports[index-1], previous, report, body) {
			return errors.New("signed observations are not uniquely sorted")
		}
		previous = body
	}
	return nil
}

const observationPrefix = `{"reports":[`
const observationSuffix = `],"schema":3}`

func decodeObservationState(body []byte) (observationState, error) {
	state, _, err := decodeObservationStateWithBytes(body)
	return state, err
}

func decodeObservationStateWithBytes(body []byte) (observationState, [][]byte, error) {
	if len(body) < len(observationPrefix)+len(observationSuffix) || len(body) > maxObservationStateBytes || !bytes.HasPrefix(body, []byte(observationPrefix)) || !bytes.HasSuffix(body, []byte(observationSuffix)) {
		return observationState{}, nil, errors.New("observation collection is not canonical")
	}
	// Include the array delimiters. Checking exact consumed spans rejects the
	// whitespace and separators that json.Decoder would otherwise normalize.
	array := body[len(observationPrefix)-1 : len(body)-len(observationSuffix)+1]
	decoder := json.NewDecoder(bytes.NewReader(array))
	if token, err := decoder.Token(); err != nil || token != json.Delim('[') {
		return observationState{}, nil, errors.New("observation array is invalid")
	}
	next := observationState{Schema: 3, Reports: []DeviceReport{}}
	var rawReports [][]byte
	offset := 1
	var previous []byte
	for decoder.More() {
		var raw json.RawMessage
		if err := decoder.Decode(&raw); err != nil {
			return observationState{}, nil, err
		}
		end := int(decoder.InputOffset())
		if end < offset || !bytes.Equal(array[offset:end], raw) {
			return observationState{}, nil, errors.New("observation separators are not canonical")
		}
		var report DeviceReport
		if err := DecodeCanonical(raw, &report, ContractDecodeLimits{MaxBytes: maxObservationStateBytes, MaxDepth: 126, MaxItems: len(raw)}); err != nil {
			return observationState{}, nil, err
		}
		if len(next.Reports) > 0 && !reportBefore(next.Reports[len(next.Reports)-1], previous, report, raw) {
			return observationState{}, nil, errors.New("signed observations are not uniquely sorted")
		}
		next.Reports = append(next.Reports, report)
		rawReports = append(rawReports, array[offset:end])
		previous = raw
		offset = end
		if offset < len(array) && array[offset] == ',' {
			offset++
		}
	}
	if token, err := decoder.Token(); err != nil || token != json.Delim(']') || int(decoder.InputOffset()) != len(array) || offset != len(array)-1 {
		return observationState{}, nil, errors.New("observation array termination is not canonical")
	}
	return next, rawReports, nil
}

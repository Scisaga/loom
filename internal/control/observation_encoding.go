package control

import (
	"bytes"
	"encoding/json"
	"errors"
)

const observationPrefix = `{"reports":[`
const observationSuffix = `],"schema":3}`

// raw contains either slices returned by the strict decoder for the exact
// protected snapshot, or newly verified CanonicalEncode output. Copy original
// signed bytes verbatim. The returned spans all reference the new buffer, so
// subsequent writes cannot pin an ever-growing chain of old file buffers.
func encodeOriginalObservationReports(state observationState, raw [][]byte) ([]byte, [][]byte, error) {
	if state.Schema != 3 || state.Reports == nil || len(raw) != len(state.Reports) {
		return nil, nil, errors.New("original report spans do not match the decoded collection")
	}
	capacity := len(observationPrefix) + len(observationSuffix)
	for i, body := range raw {
		if len(body) == 0 || i > 0 && !reportBefore(state.Reports[i-1], raw[i-1], state.Reports[i], body) {
			return nil, nil, errors.New("original reports are empty or not uniquely sorted")
		}
		capacity += len(body)
		if i > 0 {
			capacity++
		}
		if capacity > maxObservationStateBytes {
			return nil, nil, errors.New("observation history exceeds the current reader resource bound")
		}
	}
	encoded := append(make([]byte, 0, capacity), observationPrefix...)
	spans := make([][]byte, len(raw))
	for i, body := range raw {
		if i > 0 {
			encoded = append(encoded, ',')
		}
		start := len(encoded)
		encoded = append(encoded, body...)
		spans[i] = encoded[start:len(encoded)]
	}
	return append(encoded, observationSuffix...), spans, nil
}

// The collection has exactly the same canonical bytes as CanonicalEncode.
// Only one report's temporary JSON tree is needed at a time.
func encodeObservationState(state observationState, capacity int) ([]byte, error) {
	if state.Schema != 3 || state.Reports == nil {
		return nil, errors.New("observation collection schema is invalid")
	}
	if capacity < 0 || capacity > maxObservationStateBytes {
		return nil, errors.New("observation history exceeds the current reader resource bound")
	}
	body := append(make([]byte, 0, capacity), observationPrefix...)
	var previous []byte
	for i, report := range state.Reports {
		raw, err := CanonicalEncode(report)
		if err != nil {
			return nil, err
		}
		if i > 0 && !reportBefore(state.Reports[i-1], previous, report, raw) {
			return nil, errors.New("signed observations are not uniquely sorted")
		}
		separator := 0
		if i > 0 {
			separator = 1
		}
		if len(body)+len(raw)+separator+len(observationSuffix) > maxObservationStateBytes {
			return nil, errors.New("observation history exceeds the current reader resource bound")
		}
		if i > 0 {
			body = append(body, ',')
		}
		body = append(body, raw...)
		previous = raw
	}
	return append(body, observationSuffix...), nil
}

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

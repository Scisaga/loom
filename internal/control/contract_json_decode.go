package control

import (
	"encoding/json"
	"errors"
	"unicode/utf8"
)

// This parser accepts the byte grammar emitted by the contract encoder. The
// typed assignment, every value validator and the final typed round trip still
// decide whether these bytes represent the requested domain value.
func parseContractJSON(body []byte, limits ContractDecodeLimits) (any, error) {
	if limits.MaxBytes <= 0 || limits.MaxDepth <= 0 || limits.MaxItems <= 0 || len(body) > limits.MaxBytes {
		return nil, errors.New("contract input exceeds entry-point bounds")
	}
	if !utf8.Valid(body) {
		return nil, errors.New("contract input is not UTF-8")
	}
	parser := contractJSONParser{body: body, limits: limits}
	value, err := parser.value(1)
	if err != nil {
		return nil, err
	}
	if parser.offset != len(body) {
		return nil, errors.New("contract JSON has trailing content")
	}
	return value, nil
}

type contractJSONParser struct {
	body   []byte
	limits ContractDecodeLimits
	offset int
	items  int
}

func (parser *contractJSONParser) value(depth int) (any, error) {
	parser.items++
	if depth > parser.limits.MaxDepth || parser.items > parser.limits.MaxItems {
		return nil, errors.New("contract input exceeds entry-point bounds")
	}
	if parser.offset >= len(parser.body) {
		return nil, errors.New("contract JSON is incomplete")
	}
	switch parser.body[parser.offset] {
	case '{':
		return parser.object(depth)
	case '[':
		return parser.array(depth)
	case '"':
		return parser.text()
	case 't':
		if len(parser.body)-parser.offset >= 4 && string(parser.body[parser.offset:parser.offset+4]) == "true" {
			parser.offset += 4
			return true, nil
		}
	case 'f':
		if len(parser.body)-parser.offset >= 5 && string(parser.body[parser.offset:parser.offset+5]) == "false" {
			parser.offset += 5
			return false, nil
		}
	case '-', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9':
		return parser.number()
	}
	return nil, errors.New("contract null or JSON value is not permitted")
}

func (parser *contractJSONParser) object(depth int) (any, error) {
	parser.offset++
	object := map[string]any{}
	if parser.take('}') {
		return object, nil
	}
	previous := ""
	for {
		if parser.offset >= len(parser.body) || parser.body[parser.offset] != '"' {
			return nil, errors.New("contract object key is invalid")
		}
		key, err := parser.text()
		if err != nil || !contractJSONKey(key) || key <= previous {
			return nil, errors.New("contract object keys are not canonical and uniquely sorted")
		}
		previous = key
		if !parser.take(':') {
			return nil, errors.New("contract object field is incomplete")
		}
		child, err := parser.value(depth + 1)
		if err != nil {
			return nil, err
		}
		object[key] = child
		if parser.take('}') {
			return object, nil
		}
		if !parser.take(',') {
			return nil, errors.New("contract object is incomplete")
		}
	}
}

func (parser *contractJSONParser) array(depth int) (any, error) {
	parser.offset++
	array := []any{}
	if parser.take(']') {
		return array, nil
	}
	for {
		child, err := parser.value(depth + 1)
		if err != nil {
			return nil, err
		}
		array = append(array, child)
		if parser.take(']') {
			return array, nil
		}
		if !parser.take(',') {
			return nil, errors.New("contract array is incomplete")
		}
	}
}

func (parser *contractJSONParser) take(character byte) bool {
	if parser.offset < len(parser.body) && parser.body[parser.offset] == character {
		parser.offset++
		return true
	}
	return false
}

func (parser *contractJSONParser) text() (string, error) {
	parser.offset++ // The caller has established the opening quote.
	start := parser.offset
	var decoded []byte
	for parser.offset < len(parser.body) {
		character := parser.body[parser.offset]
		switch {
		case character == '"':
			end := parser.offset
			parser.offset++
			if decoded == nil {
				return string(parser.body[start:end]), nil
			}
			decoded = append(decoded, parser.body[start:end]...)
			return string(decoded), nil
		case character == '\\':
			if decoded == nil {
				decoded = make([]byte, 0, parser.offset-start+16)
			}
			decoded = append(decoded, parser.body[start:parser.offset]...)
			parser.offset++
			if parser.offset >= len(parser.body) {
				return "", errors.New("contract string escape is incomplete")
			}
			switch parser.body[parser.offset] {
			case '"', '\\':
				decoded = append(decoded, parser.body[parser.offset])
				parser.offset++
			case 'u':
				if len(parser.body)-parser.offset < 5 || parser.body[parser.offset+1] != '0' || parser.body[parser.offset+2] != '0' {
					return "", errors.New("contract string escape is not canonical")
				}
				high, low := contractHexNibble(parser.body[parser.offset+3]), contractHexNibble(parser.body[parser.offset+4])
				if high < 0 || high > 1 || low < 0 {
					return "", errors.New("contract string escape is not canonical")
				}
				decoded = append(decoded, byte(high<<4|low))
				parser.offset += 5
			default:
				return "", errors.New("contract string escape is not canonical")
			}
			start = parser.offset
		case character < 0x20:
			return "", errors.New("contract string contains an unescaped control character")
		default:
			parser.offset++
		}
	}
	return "", errors.New("contract string is incomplete")
}

func contractHexNibble(character byte) int {
	switch {
	case character >= '0' && character <= '9':
		return int(character - '0')
	case character >= 'a' && character <= 'f':
		return int(character-'a') + 10
	}
	return -1
}

func (parser *contractJSONParser) number() (any, error) {
	start := parser.offset
	negative := parser.take('-')
	if parser.offset >= len(parser.body) {
		return nil, errors.New("contract integer is incomplete")
	}
	if parser.body[parser.offset] == '0' {
		parser.offset++
		if negative || parser.offset < len(parser.body) && parser.body[parser.offset] >= '0' && parser.body[parser.offset] <= '9' {
			return nil, errors.New("contract integer is not canonical")
		}
	} else {
		if parser.body[parser.offset] < '1' || parser.body[parser.offset] > '9' {
			return nil, errors.New("contract integer is not canonical")
		}
		for parser.offset < len(parser.body) && parser.body[parser.offset] >= '0' && parser.body[parser.offset] <= '9' {
			parser.offset++
		}
	}
	return json.Number(string(parser.body[start:parser.offset])), nil
}

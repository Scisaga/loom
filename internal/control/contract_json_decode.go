package control

import (
	"bytes"
	"encoding/json"
	"errors"
	"reflect"
	"strconv"
	"unicode/utf8"
)

// This parser accepts the byte grammar emitted by the contract encoder. The
// typed assignment, every value validator and the final typed round trip still
// decide whether these bytes represent the requested domain value.
func parseContractJSON(body []byte, limits ContractDecodeLimits) (any, error) {
	parser, err := newContractJSONParser(body, limits)
	if err != nil {
		return nil, err
	}
	value, err := parser.value(1)
	if err != nil {
		return nil, err
	}
	if err := parser.complete(); err != nil {
		return nil, err
	}
	return value, nil
}

// The same parser writes ordinary exact schemas directly into a fresh output.
// The fixed domain sums retain their existing generic payload dispatch.
func parseContractJSONInto(body []byte, destination reflect.Value, codec *contractCodec, limits ContractDecodeLimits) error {
	parser, err := newContractJSONParser(body, limits)
	if err != nil {
		return err
	}
	if err := parser.typed(destination, codec, 1); err != nil {
		return err
	}
	return parser.complete()
}

func newContractJSONParser(body []byte, limits ContractDecodeLimits) (contractJSONParser, error) {
	if limits.MaxBytes <= 0 || limits.MaxDepth <= 0 || limits.MaxItems <= 0 || len(body) > limits.MaxBytes {
		return contractJSONParser{}, errors.New("contract input exceeds entry-point bounds")
	}
	if !utf8.Valid(body) {
		return contractJSONParser{}, errors.New("contract input is not UTF-8")
	}
	return contractJSONParser{body: body, limits: limits}, nil
}

func (parser *contractJSONParser) complete() error {
	if parser.offset != len(parser.body) {
		return errors.New("contract JSON has trailing content")
	}
	return nil
}

type contractJSONParser struct {
	body   []byte
	limits ContractDecodeLimits
	offset int
	items  int
}

func (parser *contractJSONParser) enter(depth int) error {
	parser.items++
	if depth > parser.limits.MaxDepth || parser.items > parser.limits.MaxItems {
		return errors.New("contract input exceeds entry-point bounds")
	}
	if parser.offset >= len(parser.body) {
		return errors.New("contract JSON is incomplete")
	}
	return nil
}

func (parser *contractJSONParser) value(depth int) (any, error) {
	if err := parser.enter(depth); err != nil {
		return nil, err
	}
	switch parser.body[parser.offset] {
	case '{':
		return parser.object(depth)
	case '[':
		return parser.array(depth)
	case '"':
		return parser.text()
	case 't', 'f':
		return parser.boolean()
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
		key, err := parser.objectKey(previous)
		if err != nil {
			return nil, err
		}
		previous = key
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

func (parser *contractJSONParser) objectKey(previous string) (string, error) {
	if parser.offset >= len(parser.body) || parser.body[parser.offset] != '"' {
		return "", errors.New("contract object key is invalid")
	}
	key, err := parser.text()
	if err != nil || !contractJSONKey(key) || key <= previous {
		return "", errors.New("contract object keys are not canonical and uniquely sorted")
	}
	if !parser.take(':') {
		return "", errors.New("contract object field is incomplete")
	}
	return key, nil
}

func (parser *contractJSONParser) boolean() (bool, error) {
	if len(parser.body)-parser.offset >= 4 && string(parser.body[parser.offset:parser.offset+4]) == "true" {
		parser.offset += 4
		return true, nil
	}
	if len(parser.body)-parser.offset >= 5 && string(parser.body[parser.offset:parser.offset+5]) == "false" {
		parser.offset += 5
		return false, nil
	}
	return false, errors.New("contract scalar must be a boolean")
}

func (parser *contractJSONParser) typed(destination reflect.Value, codec *contractCodec, depth int) error {
	if destination.Kind() == reflect.Pointer {
		next := reflect.New(destination.Type().Elem())
		if err := parser.typed(next.Elem(), codec, depth); err != nil {
			return err
		}
		destination.Set(next)
		return nil
	}
	if destination.Type() == reflect.TypeFor[Material]() || destination.Type() == reflect.TypeFor[Operation]() {
		value, err := parser.value(depth)
		if err != nil {
			return err
		}
		return codec.assign(value, destination)
	}
	if err := parser.enter(depth); err != nil {
		return err
	}
	if destination.Type() == contractU64Type {
		if parser.body[parser.offset] != '"' {
			return errors.New("U64 must be a decimal string")
		}
		text, err := parser.text()
		if err != nil {
			return err
		}
		number, err := ParseU64(text)
		if err != nil {
			return err
		}
		destination.SetUint(uint64(number))
		return nil
	}
	switch destination.Kind() {
	case reflect.Struct:
		if !parser.take('{') {
			return errors.New("contract value must be an object")
		}
		fields := codec.typePlan(destination.Type()).sorted
		fieldIndex := 0
		if !parser.take('}') {
			for {
				// The plan contains each exact, canonically escaped key and colon.
				// Advancing only forwards also rejects duplicates and wrong order,
				// without allocating a decoded string for every known field name.
				for fieldIndex < len(fields) && !bytes.HasPrefix(parser.body[parser.offset:], fields[fieldIndex].prefix) {
					if !fields[fieldIndex].optional {
						return errors.New("required contract field is missing")
					}
					fieldIndex++
				}
				if fieldIndex == len(fields) {
					return errors.New("unknown contract field")
				}
				parser.offset += len(fields[fieldIndex].prefix)
				if err := parser.typed(destination.Field(fields[fieldIndex].index), codec, depth+1); err != nil {
					return err
				}
				fieldIndex++
				if parser.take('}') {
					break
				}
				if !parser.take(',') {
					return errors.New("contract object is incomplete")
				}
			}
		}
		for _, field := range fields[fieldIndex:] {
			if !field.optional {
				return errors.New("required contract field is missing")
			}
		}
		return nil
	case reflect.Slice, reflect.Array:
		if !parser.take('[') {
			return errors.New("contract collection must be an array")
		}
		if destination.Kind() == reflect.Slice {
			destination.Set(reflect.MakeSlice(destination.Type(), 0, 0))
		}
		length := 0
		if !parser.take(']') {
			for {
				if destination.Kind() == reflect.Slice {
					destination.Grow(1)
					destination.SetLen(length + 1)
				} else if length >= destination.Len() {
					return errors.New("contract array has the wrong length")
				}
				if err := parser.typed(destination.Index(length), codec, depth+1); err != nil {
					return err
				}
				length++
				if parser.take(']') {
					break
				}
				if !parser.take(',') {
					return errors.New("contract array is incomplete")
				}
			}
		}
		if destination.Kind() == reflect.Array && length != destination.Len() {
			return errors.New("contract array has the wrong length")
		}
		return nil
	case reflect.String:
		if parser.body[parser.offset] != '"' {
			return errors.New("contract scalar must be a string")
		}
		text, err := parser.text()
		if err != nil {
			return err
		}
		destination.SetString(text)
		return nil
	case reflect.Bool:
		value, err := parser.boolean()
		if err != nil {
			return err
		}
		destination.SetBool(value)
		return nil
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		value, err := parser.number()
		if err != nil {
			return err
		}
		number, err := strconv.ParseInt(string(value), 10, destination.Type().Bits())
		if err != nil {
			return errors.New("contract integer is out of range")
		}
		destination.SetInt(number)
		return nil
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		value, err := parser.number()
		if err != nil {
			return err
		}
		number, err := strconv.ParseUint(string(value), 10, destination.Type().Bits())
		if err != nil {
			return errors.New("contract integer is out of range")
		}
		destination.SetUint(number)
		return nil
	default:
		return errors.New("unsupported contract decode target")
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

func (parser *contractJSONParser) number() (json.Number, error) {
	start := parser.offset
	negative := parser.take('-')
	if parser.offset >= len(parser.body) {
		return "", errors.New("contract integer is incomplete")
	}
	if parser.body[parser.offset] == '0' {
		parser.offset++
		if negative || parser.offset < len(parser.body) && parser.body[parser.offset] >= '0' && parser.body[parser.offset] <= '9' {
			return "", errors.New("contract integer is not canonical")
		}
	} else {
		if parser.body[parser.offset] < '1' || parser.body[parser.offset] > '9' {
			return "", errors.New("contract integer is not canonical")
		}
		for parser.offset < len(parser.body) && parser.body[parser.offset] >= '0' && parser.body[parser.offset] <= '9' {
			parser.offset++
		}
	}
	return json.Number(string(parser.body[start:parser.offset])), nil
}

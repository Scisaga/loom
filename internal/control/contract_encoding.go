package control

import (
	"bytes"
	"encoding"
	"encoding/json"
	"errors"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"
)

// ContractDecodeLimits bounds one complete input. Callers choose all three
// positive limits for their entry point; they are not protocol maxima.
type ContractDecodeLimits struct {
	MaxBytes int
	MaxDepth int
	MaxItems int // Total JSON values, including the root and containers.
}

var contractU64Type = reflect.TypeFor[U64]()

var contractValidatorType = reflect.TypeFor[interface{ Validate() error }]()

// CanonicalEncode implements C in docs/core/current-contract.md. Collections
// retain their domain order. A value's Validate method, when present, runs
// before encoding; the codec never sorts a domain set to repair invalid input.
// Types whose Validate method exists only on a pointer are unsupported.
// The wrapper creates one codec; a query may instead reuse a codec's static type
// plans in sequence. Every concrete value still runs its validator and
// cycle/null/collection checks.
func CanonicalEncode(value any) ([]byte, error) {
	return newContractCodec().encode(value)
}

// A codec owns only finite static Go type metadata. It may be reused in sequence
// during one query, and is discarded with that query; it is not concurrent-safe.
// It keeps no input bytes, decoded values, concrete validation results, or
// authorization.
type contractCodec struct {
	types map[reflect.Type]*contractTypePlan
}

func newContractCodec() *contractCodec {
	return &contractCodec{types: map[reflect.Type]*contractTypePlan{}}
}

func (codec *contractCodec) encode(value any) ([]byte, error) {
	return codec.encodeCapacity(value, 0)
}

func (codec *contractCodec) encodeCapacity(value any, capacity int) ([]byte, error) {
	if err := codec.inspect(reflect.ValueOf(value), map[contractVisit]bool{}); err != nil {
		return nil, err
	}
	return codec.append(make([]byte, 0, capacity), reflect.ValueOf(value))
}

// DecodeCanonical accepts only exact, typed contract bytes. The output is not
// changed on failure. Maps and interfaces are not decoding schemas: they cannot
// specify the exact permitted field set. Optional fields use omitempty; all
// other fields must occur, even when their value is false, zero, or an empty set.
func DecodeCanonical(body []byte, out any, limits ContractDecodeLimits) error {
	return newContractCodec().decode(body, out, limits)
}

func (codec *contractCodec) decode(body []byte, out any, limits ContractDecodeLimits) error {
	target := reflect.ValueOf(out)
	if !target.IsValid() || target.Kind() != reflect.Pointer || target.IsNil() {
		return errors.New("contract decode requires a non-nil output pointer")
	}
	if err := codec.inspectType(target.Type().Elem()); err != nil {
		return err
	}
	next := reflect.New(target.Type().Elem())
	if err := parseContractJSONInto(body, next.Elem(), codec, limits); err != nil {
		return err
	}
	want, err := codec.encodeCapacity(next.Elem().Interface(), len(body))
	if err != nil {
		return err
	}
	if !bytes.Equal(body, want) {
		return errors.New("contract JSON is not canonical")
	}
	target.Elem().Set(next.Elem())
	return nil
}

func (codec *contractCodec) inspectType(value reflect.Type) error {
	plan := codec.typePlan(value)
	if plan.schemaChecked {
		return plan.schemaErr
	}
	seen := map[reflect.Type]bool{}
	err := codec.inspectTypeIn(value, seen)
	if err != nil {
		// A recursive type may have been seen before an invalid descendant.
		// Only a completely successful walk can certify all visited types.
		plan.schemaChecked, plan.schemaErr = true, err
		return err
	}
	for kind := range seen {
		codec.types[kind].schemaChecked = true
	}
	return nil
}

func (codec *contractCodec) inspectTypeIn(value reflect.Type, seen map[reflect.Type]bool) error {
	plan := codec.typePlan(value)
	if plan.schemaChecked {
		return plan.schemaErr
	}
	if seen[value] {
		return nil
	}
	seen[value] = true
	if value == reflect.TypeFor[Material]() || value == reflect.TypeFor[Operation]() ||
		value == contractU64Type || value == reflect.PointerTo(contractU64Type) {
		return nil
	}
	if plan.methodErr != nil {
		return plan.methodErr
	}
	switch value.Kind() {
	case reflect.Pointer, reflect.Slice, reflect.Array:
		return codec.inspectTypeIn(value.Elem(), seen)
	case reflect.Struct:
		if plan.fieldsErr != nil {
			return plan.fieldsErr
		}
		for _, field := range plan.fields {
			if err := codec.inspectTypeIn(field.kind, seen); err != nil {
				return err
			}
		}
		return nil
	case reflect.Bool, reflect.String, reflect.Int, reflect.Int8, reflect.Int16,
		reflect.Int32, reflect.Int64, reflect.Uint, reflect.Uint8, reflect.Uint16,
		reflect.Uint32, reflect.Uint64:
		return nil
	default:
		return errors.New("contract decode requires exact field and scalar types")
	}
}

type contractVisit struct {
	kind    reflect.Type
	pointer uintptr
	length  int
}

func contractCustomMethods(value reflect.Type) bool {
	for _, method := range []reflect.Type{reflect.TypeFor[json.Marshaler](), reflect.TypeFor[json.Unmarshaler](),
		reflect.TypeFor[encoding.TextMarshaler](), reflect.TypeFor[encoding.TextUnmarshaler]()} {
		if value.Implements(method) || reflect.PointerTo(value).Implements(method) {
			return true
		}
	}
	return false
}

func contractPointerOnlyValidator(value reflect.Type) bool {
	for value.Kind() == reflect.Pointer {
		value = value.Elem()
	}
	return !value.Implements(contractValidatorType) && reflect.PointerTo(value).Implements(contractValidatorType)
}

func (codec *contractCodec) inspect(value reflect.Value, active map[contractVisit]bool) error {
	if !value.IsValid() {
		return errors.New("contract null is not permitted")
	}
	if value.Type() == reflect.TypeFor[Material]() {
		return value.Interface().(Material).Validate()
	}
	if value.Type() == reflect.TypeFor[Operation]() {
		return value.Interface().(Operation).Validate()
	}
	if value.Type() == reflect.TypeFor[ConflictResolution]() {
		return codec.inspect(reflect.ValueOf(value.Interface().(ConflictResolution).contractObject()), active)
	}
	if value.Type() == contractU64Type || value.Type() == reflect.PointerTo(contractU64Type) {
		return nil
	}
	plan := codec.typePlan(value.Type())
	if plan.methodErr != nil {
		return plan.methodErr
	}
	if value.Kind() == reflect.Pointer || value.Kind() == reflect.Map || value.Kind() == reflect.Slice {
		visit := contractVisit{kind: value.Type(), pointer: value.Pointer()}
		if value.Kind() == reflect.Slice {
			visit.length = value.Len()
		}
		if active[visit] {
			return errors.New("contract value contains a cycle")
		}
		active[visit] = true
		defer delete(active, visit)
	}
	if value.Kind() == reflect.Pointer || value.Kind() == reflect.Interface {
		if value.IsNil() {
			// An optional pointer may be omitted. A required null is rejected by
			// append after this inspection.
			if value.Kind() == reflect.Pointer {
				return codec.inspectType(value.Type().Elem())
			}
			return nil
		}
		return codec.inspect(value.Elem(), active)
	}
	if plan.validator && value.CanInterface() {
		if validator, ok := value.Interface().(interface{ Validate() error }); ok {
			if err := validator.Validate(); err != nil {
				return err
			}
		}
	}
	switch value.Kind() {
	case reflect.String:
		if !utf8.ValidString(value.String()) {
			return errors.New("contract string is not UTF-8")
		}
	case reflect.Struct:
		if err := codec.inspectType(value.Type()); err != nil {
			return err
		}
		for _, field := range plan.fields {
			fieldValue := value.Field(field.index)
			if field.optional && (fieldValue.Kind() == reflect.Slice || fieldValue.Kind() == reflect.Map) && fieldValue.Len() == 0 {
				if fieldValue.IsNil() {
					continue
				}
				return errors.New("omitting an empty contract collection would lose its domain value")
			}
			if err := codec.inspect(fieldValue, active); err != nil {
				return err
			}
		}
	case reflect.Map:
		if value.IsNil() || value.Type().Key().Kind() != reflect.String {
			return errors.New("contract objects require non-nil string-keyed maps")
		}
		if plan.mapKeyErr != nil {
			return plan.mapKeyErr
		}
		iter := value.MapRange()
		for iter.Next() {
			if !contractJSONKey(iter.Key().String()) {
				return errors.New("contract object key is not ASCII")
			}
			if err := codec.inspect(iter.Value(), active); err != nil {
				return err
			}
		}
	case reflect.Slice, reflect.Array:
		if value.Kind() == reflect.Slice && value.IsNil() {
			return errors.New("contract collections must be explicit")
		}
		// encoding/json treats []byte as base64, which is not the collection
		// representation. Public keys and secrets have explicit string codecs.
		if value.Type().Elem().Kind() == reflect.Uint8 && value.Kind() == reflect.Slice {
			return errors.New("contract byte strings require an explicit scalar encoding")
		}
		for index := range value.Len() {
			if err := codec.inspect(value.Index(index), active); err != nil {
				return err
			}
		}
	case reflect.Bool, reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32,
		reflect.Int64, reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
	default:
		return errors.New("contract scalar type is unsupported")
	}
	return nil
}

// Only the fixed domain sums select a concrete payload branch. This is not a
// custom codec registry: ordinary interface/map targets remain unsupported.
func contractJSONValue(value reflect.Value) (any, error) {
	if value.Kind() == reflect.Pointer || value.Kind() == reflect.Interface {
		if value.IsNil() {
			return nil, errors.New("contract null is not permitted")
		}
		return contractJSONValue(value.Elem())
	}
	if value.Type() == reflect.TypeFor[Material]() {
		return contractJSONValue(reflect.ValueOf(value.Interface().(Material).contractObject(true)))
	}
	if value.Type() == reflect.TypeFor[Operation]() {
		return contractJSONValue(reflect.ValueOf(value.Interface().(Operation).contractObject()))
	}
	if value.Type() == reflect.TypeFor[ConflictResolution]() {
		return contractJSONValue(reflect.ValueOf(value.Interface().(ConflictResolution).contractObject()))
	}
	if value.Type() == contractU64Type {
		return strconv.FormatUint(value.Uint(), 10), nil
	}
	switch value.Kind() {
	case reflect.String:
		return value.String(), nil
	case reflect.Bool:
		return value.Bool(), nil
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return json.Number(strconv.FormatInt(value.Int(), 10)), nil
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return json.Number(strconv.FormatUint(value.Uint(), 10)), nil
	case reflect.Struct:
		object := map[string]any{}
		for index := range value.NumField() {
			field := value.Type().Field(index)
			name, options, _ := strings.Cut(field.Tag.Get("json"), ",")
			child := value.Field(index)
			if options == "omitempty" && contractEmptyValue(child) {
				continue
			}
			encoded, err := contractJSONValue(child)
			if err != nil {
				return nil, err
			}
			object[name] = encoded
		}
		return object, nil
	case reflect.Slice, reflect.Array:
		array := make([]any, value.Len())
		for index := range value.Len() {
			child, err := contractJSONValue(value.Index(index))
			if err != nil {
				return nil, err
			}
			array[index] = child
		}
		return array, nil
	case reflect.Map:
		object := map[string]any{}
		iter := value.MapRange()
		for iter.Next() {
			child, err := contractJSONValue(iter.Value())
			if err != nil {
				return nil, err
			}
			object[iter.Key().String()] = child
		}
		return object, nil
	default:
		return nil, errors.New("unsupported contract value")
	}
}

func contractEmptyValue(value reflect.Value) bool {
	switch value.Kind() {
	case reflect.Array, reflect.Map, reflect.Slice, reflect.String:
		return value.Len() == 0
	case reflect.Bool, reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
		reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Pointer, reflect.Interface:
		return value.IsZero()
	default:
		return false
	}
}

func assignContractJSON(source any, destination reflect.Value) error {
	return newContractCodec().assign(source, destination)
}

func (codec *contractCodec) assign(source any, destination reflect.Value) error {
	if destination.Kind() == reflect.Pointer {
		next := reflect.New(destination.Type().Elem())
		if err := codec.assign(source, next.Elem()); err != nil {
			return err
		}
		destination.Set(next)
		return nil
	}
	if destination.Type() == reflect.TypeFor[Material]() {
		object, ok := source.(map[string]any)
		if !ok {
			return errors.New("Material must be an object")
		}
		material, err := decodeMaterialObject(object)
		if err != nil {
			return err
		}
		destination.Set(reflect.ValueOf(material))
		return nil
	}
	if destination.Type() == reflect.TypeFor[Operation]() {
		object, ok := source.(map[string]any)
		if !ok {
			return errors.New("Operation must be an object")
		}
		operation, err := decodeOperationObject(object)
		if err != nil {
			return err
		}
		destination.Set(reflect.ValueOf(operation))
		return nil
	}
	if destination.Type() == contractU64Type {
		text, ok := source.(string)
		if !ok {
			return errors.New("U64 must be a decimal string")
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
		object, ok := source.(map[string]any)
		if !ok {
			return errors.New("contract value must be an object")
		}
		plan := codec.typePlan(destination.Type())
		if plan.fieldsErr != nil {
			return plan.fieldsErr
		}
		for _, field := range plan.fields {
			child, found := object[field.name]
			if !found {
				if field.optional {
					continue
				}
				return errors.New("required contract field is missing")
			}
			if err := codec.assign(child, destination.Field(field.index)); err != nil {
				return err
			}
		}
		for name := range object {
			if _, known := plan.byName[name]; !known {
				return errors.New("unknown contract field")
			}
		}
		return nil
	case reflect.Slice, reflect.Array:
		array, ok := source.([]any)
		if !ok {
			return errors.New("contract collection must be an array")
		}
		if destination.Kind() == reflect.Array && destination.Len() != len(array) {
			return errors.New("contract array has the wrong length")
		}
		if destination.Kind() == reflect.Slice {
			destination.Set(reflect.MakeSlice(destination.Type(), len(array), len(array)))
		}
		for index, child := range array {
			if err := codec.assign(child, destination.Index(index)); err != nil {
				return err
			}
		}
		return nil
	case reflect.String:
		value, ok := source.(string)
		if !ok {
			return errors.New("contract scalar must be a string")
		}
		destination.SetString(value)
		return nil
	case reflect.Bool:
		value, ok := source.(bool)
		if !ok {
			return errors.New("contract scalar must be a boolean")
		}
		destination.SetBool(value)
		return nil
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		value, ok := source.(json.Number)
		if !ok {
			return errors.New("contract scalar must be an integer")
		}
		number, err := strconv.ParseInt(string(value), 10, destination.Type().Bits())
		if err != nil {
			return errors.New("contract integer is out of range")
		}
		destination.SetInt(number)
		return nil
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		value, ok := source.(json.Number)
		if !ok {
			return errors.New("contract scalar must be an unsigned integer")
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

func contractJSONKey(value string) bool {
	if value == "" {
		return false
	}
	for index := range len(value) {
		if value[index] < 0x20 || value[index] > 0x7e {
			return false
		}
	}
	return true
}

func appendContractJSON(body []byte, value any) []byte {
	switch value := value.(type) {
	case map[string]any:
		keys := make([]string, 0, len(value))
		for key := range value {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		body = append(body, '{')
		for index, key := range keys {
			if index != 0 {
				body = append(body, ',')
			}
			body = appendContractString(body, key)
			body = append(body, ':')
			body = appendContractJSON(body, value[key])
		}
		return append(body, '}')
	case []any:
		body = append(body, '[')
		for index, item := range value {
			if index != 0 {
				body = append(body, ',')
			}
			body = appendContractJSON(body, item)
		}
		return append(body, ']')
	case string:
		return appendContractString(body, value)
	case json.Number:
		return append(body, string(value)...)
	case bool:
		return strconv.AppendBool(body, value)
	default:
		panic("unvalidated contract JSON value")
	}
}

func appendContractString(body []byte, value string) []byte {
	const hex = "0123456789abcdef"
	body = append(body, '"')
	start := 0
	for index := range len(value) {
		character := value[index]
		switch {
		case character == '"' || character == '\\':
			body = append(body, value[start:index]...)
			body = append(body, '\\', character)
		case character < 0x20:
			body = append(body, value[start:index]...)
			body = append(body, '\\', 'u', '0', '0', hex[character>>4], hex[character&15])
		default:
			continue
		}
		start = index + 1
	}
	body = append(body, value[start:]...)
	return append(body, '"')
}

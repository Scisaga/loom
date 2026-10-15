package control

import (
	"errors"
	"reflect"
	"sort"
	"strconv"
	"strings"
)

type contractField struct {
	index    int
	name     string
	kind     reflect.Type
	prefix   []byte
	optional bool
}

type contractTypePlan struct {
	fields        []contractField // Declaration order preserves validator order.
	sorted        []contractField // ASCII field order for canonical emission.
	byName        map[string]int
	validator     bool
	methodErr     error
	fieldsErr     error
	mapKeyErr     error
	schemaChecked bool
	schemaErr     error
}

func (codec *contractCodec) typePlan(kind reflect.Type) *contractTypePlan {
	if plan := codec.types[kind]; plan != nil {
		return plan
	}
	plan := &contractTypePlan{}
	codec.types[kind] = plan
	if kind == reflect.TypeFor[Material]() || kind == reflect.TypeFor[Operation]() ||
		kind == contractU64Type || kind == reflect.PointerTo(contractU64Type) {
		return plan
	}
	if contractPointerOnlyValidator(kind) {
		plan.methodErr = errors.New("contract validation requires a value receiver")
	} else if contractCustomMethods(kind) {
		plan.methodErr = errors.New("custom contract codecs are not permitted")
	}
	plan.validator = kind.Implements(contractValidatorType)
	if kind.Kind() == reflect.Map && contractCustomMethods(kind.Key()) {
		plan.mapKeyErr = errors.New("custom contract key codecs are not permitted")
	}
	if kind.Kind() != reflect.Struct {
		return plan
	}
	plan.fields = make([]contractField, kind.NumField())
	plan.byName = make(map[string]int, kind.NumField())
	for index := range kind.NumField() {
		field := kind.Field(index)
		name, options, hasOptions := strings.Cut(field.Tag.Get("json"), ",")
		_, duplicate := plan.byName[name]
		if field.PkgPath != "" || name == "-" || field.Anonymous || !contractJSONKey(name) || duplicate || hasOptions && options != "omitempty" {
			plan.fieldsErr = errors.New("contract fields require unique explicit ASCII JSON names")
		}
		plan.fields[index] = contractField{index, name, field.Type, append(appendContractString(nil, name), ':'), options == "omitempty"}
		plan.byName[name] = index
	}
	plan.sorted = append([]contractField(nil), plan.fields...)
	sort.Slice(plan.sorted, func(i, j int) bool { return plan.sorted[i].name < plan.sorted[j].name })
	return plan
}

// Emit from a validated value using the same static fields as inspect/assign,
// without constructing a second generic map/array tree.
func (codec *contractCodec) append(body []byte, value reflect.Value) ([]byte, error) {
	if value.Kind() == reflect.Pointer || value.Kind() == reflect.Interface {
		if value.IsNil() {
			return nil, errors.New("contract null is not permitted")
		}
		return codec.append(body, value.Elem())
	}
	if value.Type() == reflect.TypeFor[Material]() {
		return codec.append(body, reflect.ValueOf(value.Interface().(Material).contractObject(true)))
	}
	if value.Type() == reflect.TypeFor[Operation]() {
		return codec.append(body, reflect.ValueOf(value.Interface().(Operation).contractObject()))
	}
	if value.Type() == reflect.TypeFor[ConflictResolution]() {
		return codec.append(body, reflect.ValueOf(value.Interface().(ConflictResolution).contractObject()))
	}
	if value.Type() == contractU64Type {
		body = append(body, '"')
		body = strconv.AppendUint(body, value.Uint(), 10)
		return append(body, '"'), nil
	}
	switch value.Kind() {
	case reflect.String:
		return appendContractString(body, value.String()), nil
	case reflect.Bool:
		return strconv.AppendBool(body, value.Bool()), nil
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return strconv.AppendInt(body, value.Int(), 10), nil
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return strconv.AppendUint(body, value.Uint(), 10), nil
	case reflect.Struct:
		fields := codec.typePlan(value.Type()).sorted
		body = append(body, '{')
		first := true
		for _, field := range fields {
			child := value.Field(field.index)
			if field.optional && contractEmptyValue(child) {
				continue
			}
			if !first {
				body = append(body, ',')
			}
			first = false
			body = append(body, field.prefix...)
			var err error
			body, err = codec.append(body, child)
			if err != nil {
				return nil, err
			}
		}
		return append(body, '}'), nil
	case reflect.Slice, reflect.Array:
		body = append(body, '[')
		for index := range value.Len() {
			if index != 0 {
				body = append(body, ',')
			}
			var err error
			body, err = codec.append(body, value.Index(index))
			if err != nil {
				return nil, err
			}
		}
		return append(body, ']'), nil
	case reflect.Map:
		keys := value.MapKeys()
		sort.Slice(keys, func(i, j int) bool { return keys[i].String() < keys[j].String() })
		body = append(body, '{')
		for index, key := range keys {
			if index != 0 {
				body = append(body, ',')
			}
			body = append(appendContractString(body, key.String()), ':')
			var err error
			body, err = codec.append(body, value.MapIndex(key))
			if err != nil {
				return nil, err
			}
		}
		return append(body, '}'), nil
	default:
		return nil, errors.New("unsupported contract value")
	}
}

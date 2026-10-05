// Package androidrelease binds the signed application artifact to the exact APK
// and native files reported by the Android runtime.
package androidrelease

import (
	"bytes"
	"crypto/sha1"
	"encoding/binary"
	"errors"
	"hash/adler32"
)

var errDEX = errors.New("APK BuildConfig DEX is invalid or unsupported")

type dexTable struct{ offset, count, stride uint32 }
type dexReader struct {
	body                            []byte
	strings, types, fields, classes dexTable
}

func (d dexReader) table(at, stride uint32) (dexTable, error) {
	count, offset := binary.LittleEndian.Uint32(d.body[at:]), binary.LittleEndian.Uint32(d.body[at+4:])
	if count == 0 && offset == 0 {
		return dexTable{stride: stride}, nil
	}
	if offset < 112 || offset%4 != 0 || uint64(offset)+uint64(count)*uint64(stride) > uint64(len(d.body)) {
		return dexTable{}, errDEX
	}
	return dexTable{offset, count, stride}, nil
}

func (d dexReader) item(table dexTable, index uint32) ([]byte, error) {
	if index >= table.count {
		return nil, errDEX
	}
	at := table.offset + index*table.stride
	return d.body[at : at+table.stride], nil
}

func (d dexReader) uleb(at *uint32) (uint32, error) {
	var value uint32
	for n := uint(0); n < 5; n++ {
		if uint64(*at) >= uint64(len(d.body)) {
			return 0, errDEX
		}
		b := d.body[*at]
		*at++
		if n == 4 && b > 15 {
			return 0, errDEX
		}
		value |= uint32(b&127) << (7 * n)
		if b&128 == 0 {
			return value, nil
		}
	}
	return 0, errDEX
}

func (d dexReader) text(index uint32) (string, error) {
	item, err := d.item(d.strings, index)
	if err != nil {
		return "", err
	}
	at := binary.LittleEndian.Uint32(item)
	length, err := d.uleb(&at)
	if err != nil || length > 65536 {
		return "", errDEX
	}
	end, ascii := at, true
	for uint64(end) < uint64(len(d.body)) && end-at <= 3*65536 && d.body[end] != 0 {
		ascii = ascii && d.body[end] < 128
		end++
	}
	if uint64(end) >= uint64(len(d.body)) || end-at > 3*65536 || ascii && end-at != length {
		return "", errDEX
	}
	// Only ASCII BuildConfig names/values are interpreted. Other classes may
	// contain MUTF-8 names, which cannot equal the ASCII descriptor we seek.
	return string(d.body[at:end]), nil
}

func (d dexReader) typeName(index uint32) (string, error) {
	item, err := d.item(d.types, index)
	if err != nil {
		return "", err
	}
	return d.text(binary.LittleEndian.Uint32(item))
}

func (d dexReader) value(at *uint32, fieldType string) (any, error) {
	if uint64(*at) >= uint64(len(d.body)) {
		return nil, errDEX
	}
	header := d.body[*at]
	*at++
	kind, extra := header&31, header>>5
	if kind == 0x1f {
		if fieldType != "Z" || extra > 1 {
			return nil, errDEX
		}
		return extra == 1, nil
	}
	if extra > 3 || uint64(*at)+uint64(extra)+1 > uint64(len(d.body)) {
		return nil, errDEX
	}
	var value uint32
	for n := uint8(0); n <= extra; n++ {
		value |= uint32(d.body[*at]) << (8 * n)
		*at++
	}
	switch {
	case kind == 0x17 && fieldType == "Ljava/lang/String;":
		return d.text(value)
	case kind == 0x04 && fieldType == "I":
		shift := 8 * (3 - extra)
		return int(int32(value<<shift) >> shift), nil
	default:
		return nil, errDEX
	}
}

func (d dexReader) buildConfig(class []byte) (map[string]any, error) {
	classIndex := binary.LittleEndian.Uint32(class)
	data, values := binary.LittleEndian.Uint32(class[24:]), binary.LittleEndian.Uint32(class[28:])
	if data < 112 || values < 112 {
		return nil, errDEX
	}
	count, err := d.uleb(&data)
	if err != nil || count != 7 {
		return nil, errDEX
	}
	for n := 0; n < 3; n++ {
		if _, err = d.uleb(&data); err != nil {
			return nil, err
		}
	}
	encoded, err := d.uleb(&values)
	if err != nil || encoded != count {
		return nil, errDEX
	}
	result := map[string]any{}
	var fieldIndex uint32
	for n := uint32(0); n < count; n++ {
		delta, err := d.uleb(&data)
		if err != nil || n > 0 && delta == 0 || delta > ^uint32(0)-fieldIndex {
			return nil, errDEX
		}
		fieldIndex += delta
		flags, err := d.uleb(&data)
		if err != nil || flags != 0x19 { // public static final
			return nil, errDEX
		}
		field, err := d.item(d.fields, fieldIndex)
		if err != nil || uint32(binary.LittleEndian.Uint16(field)) != classIndex {
			return nil, errDEX
		}
		name, err := d.text(binary.LittleEndian.Uint32(field[4:]))
		if err != nil || result[name] != nil {
			return nil, errDEX
		}
		fieldType, err := d.typeName(uint32(binary.LittleEndian.Uint16(field[2:])))
		if err != nil {
			return nil, err
		}
		value, err := d.value(&values, fieldType)
		if err != nil {
			return nil, err
		}
		result[name] = value
	}
	return result, nil
}

func readBuildConfig(body []byte) (map[string]any, error) {
	if len(body) < 112 || len(body) > 64<<20 || !bytes.Equal(body[:4], []byte("dex\n")) || body[7] != 0 {
		return nil, errDEX
	}
	switch string(body[4:7]) {
	case "035", "037", "038", "039", "040":
	default:
		return nil, errDEX
	}
	sum := sha1.Sum(body[32:])
	if !bytes.Equal(body[12:32], sum[:]) || binary.LittleEndian.Uint32(body[8:]) != adler32.Checksum(body[12:]) || binary.LittleEndian.Uint32(body[32:]) != uint32(len(body)) || binary.LittleEndian.Uint32(body[36:]) != 112 || binary.LittleEndian.Uint32(body[40:]) != 0x12345678 {
		return nil, errDEX
	}
	d := dexReader{body: body}
	for _, entry := range []struct {
		table      *dexTable
		at, stride uint32
	}{{&d.strings, 56, 4}, {&d.types, 64, 4}, {&d.fields, 80, 8}, {&d.classes, 96, 32}} {
		var err error
		*entry.table, err = d.table(entry.at, entry.stride)
		if err != nil {
			return nil, err
		}
	}
	var result map[string]any
	for n := uint32(0); n < d.classes.count; n++ {
		class, _ := d.item(d.classes, n)
		name, err := d.typeName(binary.LittleEndian.Uint32(class))
		if err != nil {
			return nil, err
		}
		if name != "Lio/github/scisaga/loom/BuildConfig;" {
			continue
		}
		if result != nil {
			return nil, errDEX
		}
		result, err = d.buildConfig(class)
		if err != nil {
			return nil, err
		}
	}
	return result, nil
}

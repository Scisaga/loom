// Package wire 实现分布式控制协议共享的严格 wire 基础。
//
// 这里刻意只接受 Loom v2 使用的 I-JSON 子集：UTF-8、无重复对象键、int64
// 整数，以及 RFC 8785 的对象键/字符串规范化。协议禁止浮点，所以不需要让
// 各平台分别复刻 ECMAScript 的浮点格式化边界。
package wire

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"sort"
	"strconv"
	"unicode/utf16"
	"unicode/utf8"
)

const (
	// EmptyHashV1 是 v2 日志/头链唯一允许的空前项。
	EmptyHashV1 = "sha256:0000000000000000000000000000000000000000000000000000000000000000"
	maxDepth    = 128
)

// CanonicalizeStrict 把严格 I-JSON 整数子集编码为 RFC 8785 canonical bytes。
// 输入歧义在规范化前失败，避免签名者与 reader 对同一字节作不同解释。
func CanonicalizeStrict(body []byte) ([]byte, error) {
	if len(body) == 0 || !utf8.Valid(body) {
		return nil, errors.New("[wire] JSON 必须是非空 UTF-8")
	}
	if err := validateJSONStringEscapes(body); err != nil {
		return nil, err
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()
	value, err := decodeValue(dec, 0)
	if err != nil {
		return nil, err
	}
	if token, err := dec.Token(); !errors.Is(err, io.EOF) {
		if err == nil {
			err = fmt.Errorf("多余 JSON token %v", token)
		}
		return nil, fmt.Errorf("[wire] JSON 尾部内容无效: %w", err)
	}
	var out bytes.Buffer
	appendCanonical(&out, value)
	return out.Bytes(), nil
}

// MarshalCanonical 先用结构体的 json tags 建立 wire，再执行严格 canonicalize。
func MarshalCanonical(value any) ([]byte, error) {
	body, err := json.Marshal(value)
	if err != nil {
		return nil, fmt.Errorf("[wire] JSON 编码失败: %w", err)
	}
	return CanonicalizeStrict(body)
}

// DecodeStrict 同时拒绝重复键、非整数数值、未知字段和尾随值。
func DecodeStrict(body []byte, maximum int, target any) ([]byte, error) {
	if maximum <= 0 || len(body) == 0 || len(body) > maximum {
		return nil, fmt.Errorf("[wire] JSON 大小必须在 1..%d bytes", maximum)
	}
	canonical, err := CanonicalizeStrict(body)
	if err != nil {
		return nil, err
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	if err := dec.Decode(target); err != nil {
		return nil, fmt.Errorf("[wire] schema/字段无效: %w", err)
	}
	var trailing any
	if err := dec.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			err = errors.New("存在第二个 JSON value")
		}
		return nil, fmt.Errorf("[wire] JSON 尾部内容无效: %w", err)
	}
	return canonical, nil
}

// Frame 使用 uint32 大端 domain 长度，禁止无边界字符串拼接。
func Frame(domain string, canonical []byte) ([]byte, error) {
	if domain == "" || !utf8.ValidString(domain) || len(domain) > int(^uint32(0)) {
		return nil, errors.New("[wire] hash/signature domain 无效")
	}
	framed := make([]byte, 4+len(domain)+len(canonical))
	binary.BigEndian.PutUint32(framed[:4], uint32(len(domain)))
	copy(framed[4:], domain)
	copy(framed[4+len(domain):], canonical)
	return framed, nil
}

// HashCanonical 对带类型 domain 的 canonical bytes 计算规范摘要。
func HashCanonical(domain string, canonical []byte) (string, error) {
	framed, err := Frame(domain, canonical)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(framed)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

// HashBytes 对证书/SPKI 等协议明确指定的原始字节使用同一 typed framing。
// 它不尝试把 binary payload 当作 JSON 重新规范化。
func HashBytes(domain string, raw []byte) (string, error) {
	return HashCanonical(domain, raw)
}

// HashObject 对结构化对象进行 canonicalize 与带类型摘要。
func HashObject(domain string, value any) (string, error) {
	canonical, err := MarshalCanonical(value)
	if err != nil {
		return "", err
	}
	return HashCanonical(domain, canonical)
}

// ParseHash 验证规范小写 sha256 摘要并返回 raw bytes。
func ParseHash(value string) ([]byte, error) {
	if len(value) != len("sha256:")+sha256.Size*2 || value[:len("sha256:")] != "sha256:" {
		return nil, errors.New("[wire] hash 必须是规范 sha256:lowercase-hex")
	}
	raw, err := hex.DecodeString(value[len("sha256:"):])
	if err != nil || "sha256:"+hex.EncodeToString(raw) != value {
		return nil, errors.New("[wire] hash 必须是规范 sha256:lowercase-hex")
	}
	return raw, nil
}

type objectMember struct {
	key   string
	value any
}

func decodeValue(dec *json.Decoder, depth int) (any, error) {
	if depth > maxDepth {
		return nil, errors.New("[wire] JSON 嵌套过深")
	}
	token, err := dec.Token()
	if err != nil {
		return nil, fmt.Errorf("[wire] JSON 无效: %w", err)
	}
	switch value := token.(type) {
	case json.Delim:
		switch value {
		case '{':
			seen := make(map[string]struct{})
			members := make([]objectMember, 0)
			for dec.More() {
				keyToken, err := dec.Token()
				if err != nil {
					return nil, fmt.Errorf("[wire] JSON object key 无效: %w", err)
				}
				key, ok := keyToken.(string)
				if !ok {
					return nil, errors.New("[wire] JSON object key 必须是字符串")
				}
				if _, duplicate := seen[key]; duplicate {
					return nil, fmt.Errorf("[wire] JSON 含重复字段 %q", key)
				}
				seen[key] = struct{}{}
				child, err := decodeValue(dec, depth+1)
				if err != nil {
					return nil, err
				}
				members = append(members, objectMember{key: key, value: child})
			}
			end, err := dec.Token()
			if err != nil || end != json.Delim('}') {
				return nil, errors.New("[wire] JSON object 未正常结束")
			}
			sort.Slice(members, func(i, j int) bool { return lessUTF16(members[i].key, members[j].key) })
			return members, nil
		case '[':
			items := make([]any, 0)
			for dec.More() {
				child, err := decodeValue(dec, depth+1)
				if err != nil {
					return nil, err
				}
				items = append(items, child)
			}
			end, err := dec.Token()
			if err != nil || end != json.Delim(']') {
				return nil, errors.New("[wire] JSON array 未正常结束")
			}
			return items, nil
		default:
			return nil, fmt.Errorf("[wire] 非法 JSON delimiter %q", value)
		}
	case json.Number:
		lexical := value.String()
		if bytes.ContainsAny([]byte(lexical), ".eE") {
			return nil, errors.New("[wire] v2 wire 禁止浮点数")
		}
		integer := new(big.Int)
		if _, ok := integer.SetString(lexical, 10); !ok || !integer.IsInt64() {
			return nil, errors.New("[wire] 整数超出 int64")
		}
		return integer.Int64(), nil
	case string, bool, nil:
		return value, nil
	default:
		return nil, fmt.Errorf("[wire] 不支持的 JSON value %T", token)
	}
}

func appendCanonical(out *bytes.Buffer, value any) {
	switch value := value.(type) {
	case []objectMember:
		out.WriteByte('{')
		for i, member := range value {
			if i > 0 {
				out.WriteByte(',')
			}
			appendJSONString(out, member.key)
			out.WriteByte(':')
			appendCanonical(out, member.value)
		}
		out.WriteByte('}')
	case []any:
		out.WriteByte('[')
		for i, item := range value {
			if i > 0 {
				out.WriteByte(',')
			}
			appendCanonical(out, item)
		}
		out.WriteByte(']')
	case string:
		appendJSONString(out, value)
	case int64:
		out.WriteString(strconv.FormatInt(value, 10))
	case bool:
		out.WriteString(strconv.FormatBool(value))
	case nil:
		out.WriteString("null")
	default:
		panic(fmt.Sprintf("unexpected canonical value %T", value))
	}
}

func appendJSONString(out *bytes.Buffer, value string) {
	const hexDigits = "0123456789abcdef"
	out.WriteByte('"')
	for _, r := range value {
		switch r {
		case '"', '\\':
			out.WriteByte('\\')
			out.WriteRune(r)
		case '\b':
			out.WriteString(`\b`)
		case '\t':
			out.WriteString(`\t`)
		case '\n':
			out.WriteString(`\n`)
		case '\f':
			out.WriteString(`\f`)
		case '\r':
			out.WriteString(`\r`)
		default:
			if r < 0x20 {
				out.WriteString(`\u00`)
				out.WriteByte(hexDigits[byte(r)>>4])
				out.WriteByte(hexDigits[byte(r)&0xf])
			} else {
				out.WriteRune(r)
			}
		}
	}
	out.WriteByte('"')
}

func lessUTF16(a, b string) bool {
	left, right := utf16.Encode([]rune(a)), utf16.Encode([]rune(b))
	for i := 0; i < len(left) && i < len(right); i++ {
		if left[i] != right[i] {
			return left[i] < right[i]
		}
	}
	return len(left) < len(right)
}

// encoding/json 会把 lone surrogate 替换为 U+FFFD；在 decoder 前扫描才能
// 保证不同 reader 不会把同一恶意输入归约成相同签名对象。
func validateJSONStringEscapes(body []byte) error {
	for i := 0; i < len(body); i++ {
		if body[i] != '"' {
			continue
		}
		for i++; i < len(body); i++ {
			switch body[i] {
			case '"':
				goto stringDone
			case '\\':
				i++
				if i >= len(body) {
					return errors.New("[wire] JSON string escape 截断")
				}
				if body[i] != 'u' {
					continue
				}
				unit, ok := parseHexUnit(body, i+1)
				if !ok {
					return errors.New("[wire] JSON unicode escape 无效")
				}
				i += 4
				if unit >= 0xd800 && unit <= 0xdbff {
					if i+6 >= len(body) || body[i+1] != '\\' || body[i+2] != 'u' {
						return errors.New("[wire] JSON high surrogate 缺少配对")
					}
					low, ok := parseHexUnit(body, i+3)
					if !ok || low < 0xdc00 || low > 0xdfff {
						return errors.New("[wire] JSON surrogate 配对无效")
					}
					i += 6
				} else if unit >= 0xdc00 && unit <= 0xdfff {
					return errors.New("[wire] JSON lone low surrogate 无效")
				}
			}
		}
		return errors.New("[wire] JSON string 未结束")
	stringDone:
	}
	return nil
}

func parseHexUnit(body []byte, start int) (uint16, bool) {
	if start+4 > len(body) {
		return 0, false
	}
	var value uint16
	for _, c := range body[start : start+4] {
		value <<= 4
		switch {
		case c >= '0' && c <= '9':
			value += uint16(c - '0')
		case c >= 'a' && c <= 'f':
			value += uint16(c-'a') + 10
		case c >= 'A' && c <= 'F':
			value += uint16(c-'A') + 10
		default:
			return 0, false
		}
	}
	return value, true
}

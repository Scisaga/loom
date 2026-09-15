package wire

import (
	"bytes"
	"testing"
)

func TestRuntimeJSONNumbersDoNotChangeProtocolEncoding(t *testing.T) {
	input := []byte(` {"threshold": 0.2, "weight": 1.25e-2, "count": 4} `)
	normalized, err := NormalizeRuntimeJSON(input)
	if err != nil || !bytes.Equal(normalized, []byte(`{"count":4,"threshold":0.2,"weight":1.25e-2}`)) {
		t.Fatal("第三方运行配置未保留 renderer 小数", string(normalized), err)
	}
	if _, err := CanonicalizeStrict(input); err == nil {
		t.Fatal("放宽了协议的整数约束")
	}
	if _, err := MarshalCanonical(struct {
		Threshold float64 `json:"threshold"`
	}{0.2}); err == nil {
		t.Fatal("协议编码接受浮点数")
	}
	for _, raw := range []string{`{"x":0.2,"x":0.3}`, `{"x":1e9999}`, `{"x":"\ud800"}`, `{"x":0.2} {}`} {
		if _, err := NormalizeRuntimeJSON([]byte(raw)); err == nil {
			t.Fatal("runtime JSON 接受歧义或无效输入", raw)
		}
	}
	outer, err := MarshalCanonical(struct {
		Content string `json:"content"`
	}{string(normalized)})
	if err != nil {
		t.Fatal("运行配置不能作为字节字符串绑定到协议 artifact", err)
	}
	if _, err := CanonicalizeStrict(outer); err != nil {
		t.Fatal(err)
	}
}

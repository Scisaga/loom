package agent

import (
	"bytes"
	"io"
)

// newTrimReader 让配置能带 UTF-8 BOM —— 有些编辑器会加,而 encoding/json
// 会因此报一个和真实原因毫不相干的错。
func newTrimReader(b []byte) io.Reader {
	return bytes.NewReader(bytes.TrimPrefix(b, []byte("\xef\xbb\xbf")))
}

package agent

import (
	"net/url"
	"strings"
)

// EquivalentTargetURL 只在消费观测时把 HTTP(S) 空路径视为根路径(§16.1.2)。
// 保留其余原始字符，尤其是转义路径、查询顺序和空查询；不改写签名正文。
func EquivalentTargetURL(a, b string) bool {
	key := func(raw string) string {
		u, err := url.Parse(raw)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.Opaque != "" || u.Path != "" {
			return raw
		}
		end := strings.IndexAny(raw, "?#")
		if end < 0 {
			end = len(raw)
		}
		return raw[:end] + "/" + raw[end:]
	}
	return key(a) == key(b)
}

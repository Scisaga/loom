package publish

import "testing"

// D77 让"没放行 = 不发二进制"成为合法状态,于是 binSum 可以是空串。
// 原先的守卫 `lastBin != ""` 会**吞掉 "" → sha 这个转换** ——
// 发布器认了放行,却不重推。实测踩到,肉眼看代码没看出来。
func TestInputsChanged(t *testing.T) {
	for _, c := range []struct {
		name                           string
		first                          bool
		cur, lastSSOT, binSum, lastBin string
		want                           bool
	}{
		{"首轮:总是要发", true, "aaa", "", "", "", true},
		{"首轮:有二进制也一样", true, "aaa", "", "bin1", "", true},
		{"什么都没变", false, "aaa", "aaa", "bin1", "bin1", false},
		{"SSOT 变了", false, "bbb", "aaa", "bin1", "bin1", true},
		{"二进制变了", false, "aaa", "aaa", "bin2", "bin1", true},

		// 这两条是本测试存在的理由。
		{"刚放行:没有 → 有", false, "aaa", "aaa", "bin1", "", true},
		{"刚停发:有 → 没有", false, "aaa", "aaa", "", "bin1", true},

		{"一直没有二进制", false, "aaa", "aaa", "", "", false},
	} {
		got := inputsChanged(c.first, c.cur, c.lastSSOT, c.binSum, c.lastBin)
		if got != c.want {
			t.Errorf("%s:inputsChanged=%v,想要 %v", c.name, got, c.want)
		}
	}
}

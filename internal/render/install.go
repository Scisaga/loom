package render

import (
	"sort"
	"strings"
)

// 配置包里的相对路径与机器上绝对路径的对应关系。
//
// 这个映射以前只存在于 README 的表格和我的手上 —— 结果是"机器上那个文件
// 到底该长什么样"没有任何代码能回答,漂移只能靠人工 diff。把它写成代码,
// hydrate 才能产出按绝对路径索引的清单,节点上的 report 才能自检。
var installRoots = []struct{ prefix, root string }{
	{"sing-box/", "/etc/loom/sing-box/"},
	{"agent/", "/etc/loom/agent/"},
	{"report/", "/etc/loom/report/"},
	// systemd 不认 /etc/loom 下的 unit。
	{"systemd/", "/etc/systemd/system/"},
	// WireGuard 必须在 /etc/wireguard 下:Ubuntu 的 AppArmor 只允许 wg 读
	// 这个目录,放别处 wg-quick 会失败却仍然 exit 0(D16)。
	{"wireguard/", "/etc/wireguard/"},
}

// InstallPath 把配置包里的相对路径映射成机器上的绝对路径。
// 没有约定的前缀返回空字符串 —— 调用方必须处理,不能猜一个位置写下去。
func InstallPath(bundlePath string) string {
	for _, r := range installRoots {
		if strings.HasPrefix(bundlePath, r.prefix) {
			return r.root + strings.TrimPrefix(bundlePath, r.prefix)
		}
	}
	return ""
}

// InstallRoots 返回全部前缀映射,按前缀排序。给文档和错误消息用。
func InstallRoots() [][2]string {
	out := make([][2]string, 0, len(installRoots))
	for _, r := range installRoots {
		out = append(out, [2]string{r.prefix, r.root})
	}
	sort.Slice(out, func(i, j int) bool { return out[i][0] < out[j][0] })
	return out
}

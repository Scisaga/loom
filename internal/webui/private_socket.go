package webui

// Control UI 的两个 Unix socket 是 report 与 private control runtime 之间的
// 本机信任边界。两者都是 root-only；网络请求不能选择后端。
const (
	ReadOnlySocketPath = "/run/loom-control-ui-read.sock"
	AdminSocketPath    = "/run/loom-control-ui-admin.sock"
)

// Package deploy 把渲染产物变成一次可验证、可回滚的安装。
//
// 设计上这一步该由节点上的 Agent 拉取执行(§14、D9)—— 但控制平面还没有
// (附录 C #14),所以现在是从工作站 ssh 推。**推和拉的语义要一致**:
// 先校验、失败就回滚、装完必须验证,这些不因传输方式而变。
package deploy

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"

	"loom/internal/render"
)

// Plan 是一个节点的安装计划。
type Plan struct {
	Node string
	// Files 是绝对路径 → 内容。由 render.InstallPath 映射,映射不到的
	// 不会出现在这里。
	Files map[string]string
	// Triggers 是"这个文件变了要重启哪些服务"。
	//
	// 按文件触发而不是一律全重启:只改了 sing-box 配置却把隧道也重启一遍,
	// 会白白断一次线。
	Triggers map[string][]string
	// Verify 是装完必须处于 active 的服务。
	//
	// **不是所有被重启的都该验证**:loom-wg-reresolve 是 oneshot,跑完就
	// inactive,拿 is-active 去验它必然失败。
	Verify []string
	// PreCheck 是安装**之前**在暂存目录上跑的检查命令。
	//
	// 上一轮就是漏了这步:配置非法 → sing-box 崩溃重启循环,而我只测了
	// 新功能没看服务起没起来。检查必须在覆盖线上文件之前做。
	PreCheck []string
}

// Unmapped 是配置包里没有约定安装位置的文件。
//
// 它们不会被安装,也不会进自检清单 —— 静默跳过等于让人以为装全了。
type Unmapped []string

// 重启顺序有依赖:隧道先起来,sing-box 的出站才绑得上;上报者要先于 Agent,
// 因为 Agent 第一轮就要问它拿全网观测(§16.1.2)。
func restartOrder(s string) int {
	switch {
	case strings.HasPrefix(s, "wg-quick@"):
		return 0
	case s == "sing-box":
		return 1
	case s == "loom-report":
		return 2
	case s == "loom-agent":
		return 3
	case strings.HasSuffix(s, ".timer"):
		return 4
	}
	return 5
}

// BuildPlan 把一个渲染好的配置包变成安装计划。
func BuildPlan(node string, files map[string]string) (*Plan, Unmapped) {
	p := &Plan{Node: node, Files: map[string]string{}, Triggers: map[string][]string{}}
	var unmapped Unmapped
	verify := map[string]bool{}

	for bundlePath, content := range files {
		abs := render.InstallPath(bundlePath)
		if abs == "" {
			unmapped = append(unmapped, bundlePath)
			continue
		}
		p.Files[abs] = content

		var svcs []string
		switch {
		case strings.HasPrefix(bundlePath, "wireguard/") && strings.HasSuffix(bundlePath, ".conf"):
			iface := strings.TrimSuffix(strings.TrimPrefix(bundlePath, "wireguard/"), ".conf")
			svcs = []string{"wg-quick@" + iface}
		case bundlePath == "sing-box/config.json":
			svcs = []string{"sing-box"}
			p.PreCheck = append(p.PreCheck, "sing-box check -c "+stagingPath(abs))
		case bundlePath == "agent/config.json":
			svcs = []string{"loom-agent"}
		case bundlePath == "report/config.json":
			svcs = []string{"loom-report"}
		case bundlePath == "report/manifest.json":
			// 清单只被读取,改了不必重启谁。
		case strings.HasSuffix(bundlePath, ".timer"):
			svcs = []string{strings.TrimPrefix(bundlePath, "systemd/")}
		case strings.HasSuffix(bundlePath, ".service"):
			// unit 文件本身只需要 daemon-reload。真正要重启的那个服务,
			// 由它的**配置文件**触发 —— 换句话说 unit 变了而配置没变时,
			// 新 unit 会在下次重启时生效。这是有意的:改一行 Description
			// 不该断一次线。
			svcs = unitSelfRestart(bundlePath)
		}
		if len(svcs) > 0 {
			p.Triggers[abs] = svcs
			for _, s := range svcs {
				if verifiable(s) {
					verify[s] = true
				}
			}
		}
	}

	for s := range verify {
		p.Verify = append(p.Verify, s)
	}
	sort.Slice(p.Verify, func(i, j int) bool {
		if a, b := restartOrder(p.Verify[i]), restartOrder(p.Verify[j]); a != b {
			return a < b
		}
		return p.Verify[i] < p.Verify[j]
	})
	sort.Strings(unmapped)
	sort.Strings(p.PreCheck)
	return p, unmapped
}

// unitSelfRestart 决定一个 unit 文件变化时要不要顺带重启它自己。
//
// 有配置文件的服务由配置触发,这里返回空。没有配置文件的(reresolve 的
// service 与 timer)只能由 unit 自己触发。
func unitSelfRestart(bundlePath string) []string {
	name := strings.TrimSuffix(strings.TrimPrefix(bundlePath, "systemd/"), ".service")
	switch name {
	case "sing-box", "loom-agent", "loom-report":
		return nil
	case "loom-wg-reresolve":
		// oneshot,由 timer 拉起。unit 改了不必现在跑一次。
		return nil
	}
	return []string{name}
}

// verifiable 报告这个单元装完之后是否应当处于 active。
//
// oneshot 跑完就 inactive,拿 is-active 验它必然失败 —— 那会让每次部署都
// "失败并回滚",而实际上一切正常。
func verifiable(s string) bool {
	return !strings.HasPrefix(s, "loom-wg-reresolve") || strings.HasSuffix(s, ".timer")
}

// Services 返回全部可能被触发的服务,按重启顺序去重排序。
func (p *Plan) Services() []string {
	seen := map[string]bool{}
	var out []string
	for _, svcs := range p.Triggers {
		for _, s := range svcs {
			if !seen[s] {
				seen[s] = true
				out = append(out, s)
			}
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if a, b := restartOrder(out[i]), restartOrder(out[j]); a != b {
			return a < b
		}
		return out[i] < out[j]
	})
	return out
}

// stagingPath 是文件在暂存目录里的位置。
//
// 先装到暂存目录、检查通过再挪到位:直接覆盖线上文件的话,检查失败时
// 已经晚了 —— 旧配置没了,新配置是坏的。
func stagingPath(abs string) string {
	return StagingRoot + strings.ReplaceAll(strings.TrimPrefix(abs, "/"), "/", "%")
}

const (
	// StagingRoot 放待安装的文件,PreviousRoot 放被替换掉的那一份。
	StagingRoot  = "/var/lib/loom/staging/"
	PreviousRoot = "/var/lib/loom/previous/"
)

// Hash 是计划的内容哈希,用来判断这个节点需不需要重装。
func (p *Plan) Hash() string {
	paths := make([]string, 0, len(p.Files))
	for k := range p.Files {
		paths = append(paths, k)
	}
	sort.Strings(paths)
	h := sha256.New()
	for _, k := range paths {
		fmt.Fprintf(h, "%s\x00%d\x00%s\x00", k, len(p.Files[k]), p.Files[k])
	}
	return hex.EncodeToString(h.Sum(nil))
}

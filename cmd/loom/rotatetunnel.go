package main

import (
	"flag"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"loom/internal/model"
)

// cmdRotateTunnel 给一条隧道换一个监听端口,并把旧端口记进退役名单。
//
// **为什么需要它。** 实测过一次:hz01 ↔ ber01 在 61654 上被单向丢包丢了
// 15.8 小时 —— ber01 的握手包到得了 hz01、hz01 也在回,但回包到不了 ber01。
// 配置逐字对上、TCP 通、换个端口的临时 UDP 流全通、WG 特征包在新五元组上
// 也全通、同样是 WireGuard 的另外两条隧道都好着。换成 61691 之后七分钟就通了。
//
// **它只算不写。** 打印出替换后的那一行,由人粘回 SSOT —— 与 `loom addnode`
// 同一个道理:SSOT 是人的声明,工具给料,不代笔。这也顺带避开了两件麻烦事:
// 自动改写会毁掉 SSOT 里的注释,而"系统自己改 SSOT"会给它添第二个写入者,
// 而单一写入者正是 dry-run diff、漂移检测、回滚三个产物的地基。
//
// **换端口是修复,也是诊断。** "这条流被标记了"和"某处状态坏了"两个假设
// 对换端口的反应完全一样,判据是**能撑多久** —— 所以 -reason 是必填的,
// 而且打印出来的那一行带上日期,下次翻到它的人才知道这个实验在等什么答案。
func cmdRotateTunnel(args []string) error {
	fs := flag.NewFlagSet("rotate-tunnel", flag.ExitOnError)
	reason := fs.String("reason", "", "为什么换(必填)")
	rest, err := parseInterspersed(fs, args)
	if err != nil {
		return err
	}
	if len(rest) != 3 {
		return fmt.Errorf("用法:loom rotate-tunnel <ssot.yaml> <节点A> <节点B> -reason <理由>")
	}
	if strings.TrimSpace(*reason) == "" {
		return fmt.Errorf("要 -reason:换端口既是修复也是诊断,而判据是能撑多久 —— " +
			"下次翻到这一行的人需要知道这个实验在等什么答案")
	}
	path, a, b := rest[0], rest[1], rest[2]

	body, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	s, err := model.Load(body)
	if err != nil {
		return err
	}

	port, retired, err := s.RotateTunnelPort(a, b)
	if err != nil {
		return err
	}
	t := findTunnel(s, a, b)
	old := t.ListenPort

	fmt.Printf("隧道 %s\n", t.Pair())
	fmt.Printf("  %d → %d\n", old, port)
	if len(retired) > 1 {
		fmt.Printf("  已退役 %d 个端口:%s\n", len(retired), joinInts(retired))
	}
	fmt.Printf("\n把 SSOT 里这一行换成:\n\n")
	fmt.Printf("  # %s 换端口(%d → %d):%s\n", time.Now().Format("2006-01-02"), old, port, *reason)
	fmt.Printf("  %s\n", rotatedTunnelLine(t, port, retired))

	fmt.Printf("\n换完之后:\n")
	fmt.Printf("  1. loom validate %s          确认还过得了校验\n", path)
	fmt.Printf("  2. loom diff %s -o <目录>     应当**正好两行**:一端的 ListenPort、另一端的 Endpoint\n", path)
	fmt.Printf("  3. 存盘,发布器 30 秒内接管;两端各自 pull(一个周期,约 10 分钟)\n")
	fmt.Printf("     急的话 loom apply 直接推,几秒到两端\n")
	fmt.Printf("\n  两端错开更新的那个窗口里隧道是断的 —— 而它本来就断着的话,没有额外代价。\n")
	return nil
}

// rotatedTunnelLine 按 SSOT 里的行内写法拼出替换行。
//
// 刻意贴着现有格式(单行 flow 映射),这样粘回去的 diff 只有该变的那部分。
func rotatedTunnelLine(t *model.Tunnel, port int, retired []int) string {
	var b strings.Builder
	fmt.Fprintf(&b, "- {from: %s, to: %s, listen_port: %d", t.From, t.To, port)
	fmt.Fprintf(&b, ", retired_ports: [%s]", joinInts(retired))
	fmt.Fprintf(&b, ", from_addr: %s, to_addr: %s", t.FromAddr, t.ToAddr)
	if t.Obfuscation != "" {
		fmt.Fprintf(&b, ", obfuscation: %s", t.Obfuscation)
	}
	b.WriteString("}")
	return b.String()
}

func findTunnel(s *model.SSOT, a, b string) *model.Tunnel {
	for i := range s.Tunnels {
		t := &s.Tunnels[i]
		if (t.From == a && t.To == b) || (t.From == b && t.To == a) {
			return t
		}
	}
	return nil
}

func joinInts(xs []int) string {
	out := make([]string, 0, len(xs))
	sorted := append([]int(nil), xs...)
	sort.Ints(sorted)
	for _, x := range sorted {
		out = append(out, strconv.Itoa(x))
	}
	return strings.Join(out, ", ")
}

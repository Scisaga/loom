package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"loom/internal/netx"
	"loom/internal/publish"
)

// cmdSnapshots 列出中控发过哪些快照,以及**现在还能退回哪些**。
//
// 这是 `loom rollback` 的前置问题。回滚要一个快照 id,而 id 是一串十二位
// 十六进制 —— 没有这条命令就无处可查:分发点是 `autoindex off`,列不出来;
// 事件历史里的 `snapshot` 记的是"某台节点装的版本变了",一个发出去但没
// 节点取到的快照在那里一条记录都没有。
//
// **最右边那列才是重点。** 光有 id 列表回答不了"我现在能退到哪儿" ——
// 没有源头存档的快照退不了(D61),而那正是需要回滚时最不想现发现的事。
func cmdSnapshots(args []string) error {
	fs := flag.NewFlagSet("snapshots", flag.ExitOnError)
	history := fs.String("ssot-history", "deploy/ssot-history", "源头存档与发布历史所在目录")
	url := fs.String("url", "", "分发点地址(默认从 /etc/loom/control.json 读),用来标出当前在跑哪个")
	dns := fs.String("dns", "", "解析分发点用的 DNS(默认从 control.json 读)")
	limit := fs.Int("n", 20, "最多列几条(0 = 全部)")
	if _, err := parseInterspersed(fs, args); err != nil {
		return err
	}

	recs, err := publish.ReadPublished(*history)
	if err != nil {
		return err
	}
	if len(recs) == 0 {
		fmt.Printf("发布历史是空的(%s)\n\n", publish.HistoryPath(*history))
		fmt.Printf("要么还没用带发布历史的版本发过东西,要么这台不是中控。\n")
		fmt.Printf("在那之前 `loom rollback` 没有可退的目标 —— 只能用 `loom pin` 退二进制。\n")
		return nil
	}

	// 分发点当前指向哪个。问不到不是错误 —— 历史本身仍然有用,
	// 只是少一个"现在"的标记。
	served := ""
	if base, d := resolveDist(*url, *dns); base != "" {
		if body, err := getBytes(netx.Client(d, 15*time.Second), base+"/current.json"); err == nil {
			var cur struct {
				Snapshot string `json:"snapshot"`
			}
			if json.Unmarshal(body, &cur) == nil {
				served = cur.Snapshot
			}
		}
	}

	off := 0
	if *limit > 0 && len(recs) > *limit {
		off = len(recs) - *limit
	}
	shown := recs[off:]

	// 同一个快照可能出现多次(回滚回去就是一次新的发布事件),但"现在在跑
	// 的是哪一条"只有一条 —— **标最后那次**。两行都标 → 会看成有两个当前版本。
	current := -1
	for i := range recs {
		if recs[i].Snapshot == served {
			current = i
		}
	}

	fmt.Printf("发布历史(%d 条,新的在下)\n\n", len(recs))
	// 列头手写对齐:中文字符显示占两格,而 %-12s 是按字符数补的,
	// 用格式化动词会歪。
	fmt.Printf("  快照          发布时间          源头          能回滚吗\n")
	for i := range shown {
		r := &shown[i]
		mark := "  "
		if off+i == current {
			mark = "→ "
		}
		_, why := rollbackable(*history, r)
		fmt.Printf("%s%-12s  %-16s  %-12s  %s\n",
			mark, short(r.Snapshot), humanTime(r.At), shortHash(r.SSOTSum), why)
	}

	fmt.Printf("\n")
	if served == "" {
		fmt.Printf("(问不到分发点现在提供哪个,所以没标 →)\n")
	} else if !contains(recs, served) {
		// 分发点在提供一个历史里没有的快照 —— 要么是别的机器发的,
		// 要么历史被清过。两种都值得当场知道。
		fmt.Printf("⚠️ 分发点在提供 %s,而发布历史里没有这一条 —— "+
			"可能是别处发的,或历史被清理过\n", short(served))
	}
	// **两个数都对全量算,不对 -n 截出来的那几行算。** 口径不一致的话
	// `-n 1` 会显示"1 / 2 个版本",读起来像"有一个版本退不了" —— 而那
	// 纯粹是显示条数造成的。会说谎的面板比没有面板更糟(D55)。
	//
	// 按**不同的快照**数,不按日志行数:回滚回旧版会让同一个快照出现两次,
	// 而"能退到哪儿"问的是有几个不同的落点。
	rollable, distinct := map[string]bool{}, map[string]bool{}
	for i := range recs {
		distinct[recs[i].Snapshot] = true
		if can, _ := rollbackable(*history, &recs[i]); can {
			rollable[recs[i].Snapshot] = true
		}
	}
	fmt.Printf("能整份回滚的:%d / %d 个版本。回滚:loom rollback <快照 id> -reason <理由>\n",
		len(rollable), len(distinct))
	return nil
}

// rollbackable 判断这一条现在还能不能整份退回去。
//
// **判据必须是"源头存档真的在且内容对得上"**,不是"历史里有这一行" ——
// 存档被清理过、被改过,历史行照样在。而回滚失败最糟的时机就是需要它的
// 那一刻。
func rollbackable(dir string, r *publish.Published) (bool, string) {
	if r.SSOTSum == "" {
		return false, "❌ 没记源头哈希"
	}
	if _, err := publish.ReadArchivedSSOT(dir, r.SSOTSum); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return false, "❌ 源头存档没了"
		}
		return false, "❌ 存档对不上哈希"
	}
	return true, "✅"
}

func contains(recs []publish.Published, id string) bool {
	for i := range recs {
		if recs[i].Snapshot == id {
			return true
		}
	}
	return false
}

// resolveDist 取分发点地址,拿不到就返回空 —— 列历史不该因为问不到
// 分发点而整个失败。
func resolveDist(url, dns string) (string, string) {
	if url == "" {
		u, d, err := controlDefaults()
		if err != nil {
			return "", ""
		}
		url = u
		if dns == "" {
			dns = d
		}
	}
	return strings.TrimRight(url, "/"), dns
}

// humanTime 把 RFC3339 缩成给人看的样子。解析不了就原样输出 ——
// 显示层不该因为一条坏数据罢工。
func humanTime(ts string) string {
	t, err := time.Parse(time.RFC3339, ts)
	if err != nil {
		return ts
	}
	return t.Local().Format("01-02 15:04")
}

package main

import (
	"flag"
	"fmt"
	"os"
	"sort"
	"time"

	"loom/internal/agent"
	"loom/internal/measure"
	"loom/internal/model"
	"loom/internal/render"
)

// probe 主动探测每条候选,把结果追加进度量文件。
//
// §16.2 把"被动观测优先"定为硬约束 —— 真实流量零额外成本、零额外暴露,
// 且比合成探测更准确。**主动探测只覆盖没有真实流量的候选,必须限频、限额。**
// 现在还没有被动观测(那需要 Agent 在数据路径上统计),所以先用主动的。
//
// 探测走**渲染出的探测入口**(§7.3.1 的 probe-in):一个回环端口,用户名
// 区分候选,路由规则把每个用户名打到同名的候选出站上。
//
// **为什么不用 sing-box 自带的 delay 接口:它忽略传入的 url 参数。** 后果不是
// 数字不准,是排序被颠倒 —— 实测同一批候选,delay 接口把 direct 排第一
// (128ms),而用真实目标探测时 direct 根本不通(超时 10 秒)。
//
// 它测的仍是 L4 可得的量(建连 + 首字节),不是 TTFT:应用层指标要 L7
// 观测点(§16.2)。记录里如实标 observation_point=l4_tunnel。

func cmdProbe(args []string) error {
	fs := flag.NewFlagSet("probe", flag.ExitOnError)
	probeAddr := fs.String("probe", render.ProbeListen, "接入节点的探测入口")
	secretsFile := fs.String("secrets", "", "秘密文件,取 probe/<node> 这一项")
	node := fs.String("node", "", "接入节点 id(用于给记录打标,并从秘密文件取口令)")
	out := fs.String("o", "measurements.jsonl", "度量输出文件(追加)")
	rounds := fs.Int("rounds", 1, "每条候选探测几轮")
	budget := fs.Int("budget", 200, "本次最多发多少个探测请求 —— 探测预算是硬上限(§16.2)")
	timeoutMs := fs.Int("timeout", 8000, "单次探测超时(毫秒)")

	rest, err := parseInterspersed(fs, args)
	if err != nil {
		return err
	}
	if len(rest) != 1 {
		return fmt.Errorf("需要一个 SSOT 文件路径")
	}
	if *node == "" {
		return fmt.Errorf("需要 -node 指定接入节点 id")
	}

	s, err := loadAndValidate(rest[0])
	if err != nil {
		return err
	}
	var accessNode *model.Node
	for _, n := range s.AccessNodes() {
		if n.ID == *node {
			accessNode = n
		}
	}
	if accessNode == nil {
		return fmt.Errorf("SSOT 里没有叫 %q 的接入节点", *node)
	}

	if *secretsFile == "" {
		return fmt.Errorf("需要 -secrets 指向含 probe/%s 的秘密文件", *node)
	}
	secrets, err := readSecrets(*secretsFile)
	if err != nil {
		return err
	}
	sec := secrets["probe/"+*node]
	if sec == "" {
		return fmt.Errorf("秘密文件里没有 probe/%s", *node)
	}

	// 枚举这个接入节点上的全部候选。探测的单位与调度的单位必须一致 ——
	// 否则测的东西和选的东西对不上(§5.6)。
	decls := s.DeclarationByID()
	creds := s.CredentialByID()
	type item struct{ decl, cand, url string }
	var items []item
	seen := map[string]bool{}
	for _, cid := range accessNode.Access.Credentials {
		c := creds[cid]
		if c == nil || c.Revoked() {
			continue
		}
		d := decls[c.Declaration]
		if d == nil {
			continue
		}
		cands, _ := s.EnumerateCandidates(accessNode, d)
		for i := range cands {
			tag := cands[i].Tag()
			if !seen[tag] {
				seen[tag] = true
				// 每条声明用自己的探测目标 —— 目标的可达性profile不同,
				// 排序结果会完全不同。
				items = append(items, item{d.ID, tag, d.ProbeURL})
			}
		}
	}
	sort.Slice(items, func(i, j int) bool { return items[i].cand < items[j].cand })

	want := len(items) * *rounds
	if want > *budget {
		fmt.Fprintf(os.Stderr,
			"! 探测预算 %d 不够跑完 %d 条候选 × %d 轮(需要 %d)—— 本次只测前 %d 个\n",
			*budget, len(items), *rounds, want, *budget)
	}

	var got []measure.Measurement
	sent := 0

	for r := 0; r < *rounds; r++ {
		for _, it := range items {
			if sent >= *budget {
				break
			}
			sent++
			r, perr := agent.ProbeOnce(*probeAddr, sec, render.ProbeUser(it.cand), it.url,
				time.Duration(*timeoutMs)*time.Millisecond)
			m := measure.Measurement{
				// 时间由调用方注入,与渲染/打包保持同一个原则(D14)。
				TS:   time.Now().UTC().Format(time.RFC3339),
				Node: *node, CandidateID: it.cand, Declaration: it.decl,
				Point: measure.L4Tunnel, Kind: measure.Active,
			}
			if perr != nil {
				m.Error = perr.Error()
			} else {
				m.FirstByteMs = r.FirstByteMs
				m.KBps = r.KBps()
			}
			got = append(got, m)
		}
	}

	if err := measure.Append(*out, got); err != nil {
		return err
	}

	ok := 0
	for i := range got {
		if got[i].OK() {
			ok++
		}
	}
	fmt.Printf("探测 %d 次(%d 成功,%d 失败)→ %s\n", len(got), ok, len(got)-ok, *out)
	all, err := measure.Load(*out)
	if err != nil {
		return err
	}
	fmt.Print(measure.FormatSummary(measure.Summarize(all)))
	return nil
}

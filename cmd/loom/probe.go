package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"sort"
	"time"

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
// **它测的是路径质量,不是服务质量。**
//
// 目标是 sing-box 内置的一个中立端点,对所有候选都一样 —— 所以候选之间的
// **相对排序**有效,而这正是服务器轴需要的(§4)。
//
// 它说不了任何关于**地址轴**的事:比较等价类里几个服务地址的好坏,要看
// TTFT、tokens/s、响应结构,而那些只能从 L7 观测点拿(§16.2)。

func cmdProbe(args []string) error {
	fs := flag.NewFlagSet("probe", flag.ExitOnError)
	api := fs.String("api", "http://"+render.APIListen, "接入节点的 sing-box 控制端点")
	secret := fs.String("secret", "", "控制端点口令(或用 -secrets 从秘密文件取)")
	secretsFile := fs.String("secrets", "", "秘密文件,取 api/<node> 这一项")
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

	sec := *secret
	if sec == "" && *secretsFile != "" {
		m, err := readSecrets(*secretsFile)
		if err != nil {
			return err
		}
		sec = m["api/"+*node]
	}
	if sec == "" {
		return fmt.Errorf("需要控制端点口令:用 -secret,或 -secrets 指向含 api/%s 的秘密文件", *node)
	}

	// 枚举这个接入节点上的全部候选。探测的单位与调度的单位必须一致 ——
	// 否则测的东西和选的东西对不上(§5.6)。
	decls := s.DeclarationByID()
	creds := s.CredentialByID()
	type item struct{ decl, cand string }
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
				items = append(items, item{d.ID, tag})
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

	client := &http.Client{Timeout: time.Duration(*timeoutMs+2000) * time.Millisecond}
	var got []measure.Measurement
	sent := 0

	for r := 0; r < *rounds; r++ {
		for _, it := range items {
			if sent >= *budget {
				break
			}
			sent++
			ms, perr := probeOne(client, *api, sec, it.cand, *timeoutMs)
			m := measure.Measurement{
				// 时间由调用方注入,与渲染/打包保持同一个原则(D14)。
				TS:   time.Now().UTC().Format(time.RFC3339),
				Node: *node, CandidateID: it.cand, Declaration: it.decl,
				Point: measure.L4Tunnel, Kind: measure.Active,
			}
			if perr != nil {
				m.Error = perr.Error()
			} else {
				m.FirstByteMs = ms
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

// probeOne 问控制端点要一条候选的延迟。
//
// 这个接口**不改变 selector 的当前选择**,所以可以在真实流量跑着的时候
// 逐条测 —— 否则每测一条就要切一次,既慢又会打断连接。
func probeOne(c *http.Client, api, secret, cand string, timeoutMs int) (int, error) {
	// **不传 url 参数。** sing-box 1.11.4 的 delay 接口忽略它 —— 实测传
	// neverbefore.example.org,它照样去连自己的默认目标 www.gstatic.com。
	// 传一个不生效的参数,只会让人以为测的是自己指定的东西。
	u := fmt.Sprintf("%s/proxies/%s/delay?timeout=%d", api, url.PathEscape(cand), timeoutMs)
	req, err := http.NewRequest(http.MethodGet, u, nil)
	if err != nil {
		return 0, err
	}
	req.Header.Set("Authorization", "Bearer "+secret)

	resp, err := c.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()

	var body struct {
		Delay   int    `json:"delay"`
		Message string `json:"message"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return 0, fmt.Errorf("解析响应:%w", err)
	}
	if resp.StatusCode != http.StatusOK || body.Delay == 0 {
		if body.Message != "" {
			return 0, fmt.Errorf("%s", body.Message)
		}
		return 0, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return body.Delay, nil
}

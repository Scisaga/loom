package publish

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"runtime"
	"strings"
	"time"

	"loom/internal/version"
)

// Options 是发布器的运行期参数。
type Options struct {
	SSOTPath string
	Key      ed25519.PrivateKey
	Target   Target
	Author   string

	// VerifyURL 非空时,推完之后从**节点视角**确认真的取得到。
	// 推成功不等于取得到 —— nginx 的路径写错时,推送这一侧完全正常。
	VerifyURL string
	// DNS 是解析 VerifyURL 用的服务器。留空则用系统解析器。
	DNS string
	// PinDir 是钉住状态所在目录。非空且钉住了的话,发的是钉住的那个
	// 二进制,而不是 BinaryPath 指的那个。
	PinDir string

	// ArchiveDir 是源头存档目录(中控本地,不进分发树)。
	//
	// 每次成功发布都把当时那版 SSOT 存一份,`loom rollback` 靠它把快照 id
	// 换算回源头。**留空就等于这些版本将来回滚不了** —— SSOT 没有别的
	// 版本历史:不在 git,中控界面是覆盖式保存。
	ArchiveDir string

	// BinaryPath 是要一起发的 Agent 二进制。
	//
	// 存路径而不是内容:**每轮重新读**。重新编译之后不重启发布器就发不出去,
	// 那又是一个"改了没生效"的隐蔽故障。代价是每轮多读 12MB,可忽略。
	BinaryPath string

	// HealthPath 是发布器写自己状态的地方(见 health.go)。留空则不写。
	//
	// 没有它的话,"进程活着但发不出去"只能靠翻 journal 发现 —— 而没人
	// 会去翻一个 systemd 显示 active 的服务的日志。
	HealthPath string

	Interval time.Duration
	Once     bool
	Log      io.Writer
	// Now 由调用方注入。发布器是运行期组件,它**必须**读时钟,
	// 只是入口收在这一处(渲染与打包仍然不读,§12)。
	Now func() time.Time
}

func (o *Options) fill() {
	if o.Interval == 0 {
		o.Interval = 30 * time.Second
	}
	if o.Log == nil {
		o.Log = os.Stderr
	}
	if o.Now == nil {
		o.Now = func() time.Time { return time.Now().UTC() }
	}
}

// Run 盯着 SSOT,变了就发布。
//
// 它同时做两件事,而第二件容易被忘掉:
//
//  1. SSOT 变了 → 校验、渲染、签名、推送
//  2. **分发点指向的快照与本地算出来的不一致 → 重推**
//
// 第二件是收敛(D33 的同一个道理):分发点被清空、推到一半断线、有人手工
// 动过,都会让它和真相分叉。只在"文件变了"时才动作的发布器修不了这些。
func Run(ctx context.Context, opts Options) error {
	opts.fill()
	logf := func(f string, a ...any) {
		fmt.Fprintf(opts.Log, "%s "+f+"\n", append([]any{opts.Now().Format("15:04:05")}, a...)...)
	}

	health := &Health{
		Version:   version.Self(),
		PID:       os.Getpid(),
		StartedAt: opts.Now().Format(time.RFC3339),
	}
	// 写不出状态文件不该拦住发布 —— 发布是主职,自报是附加。
	// 但要说一次,否则"状态文件一直是旧的"会变成新的静默故障。
	saveHealth := func() {
		health.UpdatedAt = opts.Now().Format(time.RFC3339)
		if err := health.Write(opts.HealthPath); err != nil {
			logf("⚠️ 写发布器状态失败:%v —— loom status 看到的会是旧的", err)
		}
	}
	saveHealth()

	lastSSOT := ""
	lastBuilt := ""
	lastBin := ""
	lastPin := ""
	lastLive := ""

	for {
		body, err := os.ReadFile(opts.SSOTPath)
		if err != nil {
			logf("读 SSOT 失败:%v", err)
		} else {
			h := sha256.Sum256(body)
			cur := hex.EncodeToString(h[:8])

			// 二进制也算输入的一部分:它变了,快照就该变(§15.4 绑定回滚)。
			binPath := opts.BinaryPath
			pin, pinBin, perr := ReadPin(opts.PinDir)
			if perr != nil {
				logf("读钉住状态失败:%v", perr)
			} else if pin != nil {
				binPath = pinBin
				if pin.Snapshot != lastPin {
					logf("⚠️ 二进制钉在 %s(%s)—— 重新编译不会发出去", short(pin.Snapshot), pin.Reason)
					lastPin = pin.Snapshot
				}
			} else if lastPin != "" {
				logf("钉住已解除,恢复发本机二进制")
				lastPin = ""
			}

			bins, binSum, berr := readBinary(binPath)
			if berr != nil {
				logf("读二进制失败:%v", berr)
			}

			// 钉住期间本机二进制变了 —— **正是"我重新编译了但没发出去"
			// 那一刻**。只在这时说一次,不刷屏。
			if pin != nil && opts.BinaryPath != "" {
				if _, liveSum, err := readBinary(opts.BinaryPath); err == nil && liveSum != lastLive {
					if lastLive != "" {
						logf("⚠️ 本机二进制变了(%s),但钉住生效中,发出去的仍是 %s",
							short(liveSum), short(binSum))
					}
					lastLive = liveSum
				}
			}

			served, serr := opts.Target.Current()
			if serr != nil {
				logf("问不到分发点当前指向哪个快照:%v", serr)
			}

			first := lastSSOT == ""
			changed := cur != lastSSOT || (lastBin != "" && binSum != lastBin)
			// 分发点和本地算出来的不一致就重推,与 SSOT 有没有变无关。
			diverged := serr == nil && lastBuilt != "" && served != lastBuilt

			switch {
			case first:
				// 刚起来时不知道自己处在什么状态,先核对一遍。
				logf("启动,核对分发点(SSOT %s)", cur[:8])
			case changed && binSum != lastBin && lastBin != "":
				logf("二进制变了(%s → %s)", short(lastBin), short(binSum))
			case changed:
				logf("SSOT 变了(%s)", cur[:8])
			case diverged:
				logf("分发点指向 %s,本地算出来是 %s —— 重推", short(served), short(lastBuilt))
			}

			if changed || diverged {
				id, err := publishOnce(&opts, body, bins, logf)
				// **校验不过时不更新 lastSSOT**:下一轮还要再试一次,
				// 否则改坏了再改回来的中间态会被当成"已经处理过"。
				if err == nil {
					// 存档在发布**之后** —— 存的是"确实发出去过的那一版",
					// 而不是"试过但没发成的那一版"。回滚只该退到前者。
					sum, aerr := ArchiveSSOT(opts.ArchiveDir, body)
					if aerr != nil {
						logf("⚠️ 源头存档失败:%v —— 快照 %s 将来回滚不了", aerr, short(id))
					}
					// 记进发布历史。只在快照 id 变了时才写一行 ——
					// 收敛每 30 秒确认一次同一个快照,逐轮记就是一天 2880 行。
					if wrote, herr := AppendPublished(opts.ArchiveDir, Published{
						At: opts.Now().Format(time.RFC3339), Snapshot: id,
						SSOTSum: sum, Binary: binSum, Author: opts.Author,
					}); herr != nil {
						logf("⚠️ 记发布历史失败:%v —— `loom snapshots` 会少这一条", herr)
					} else if wrote {
						logf("  已记进发布历史(%s)", HistoryPath(opts.ArchiveDir))
					}
					// 钉住的是快照 X 的二进制,而源头已经算出别的快照 ——
					// 发出去的就是"X 的二进制 + 当前源头的配置",正是
					// §15.4 要防的组合。D60 记下了这个洞但没让工具拦,
					// 这里补上:每次发布都说,直到两者对上或钉住解除。
					if pin != nil && id != pin.Snapshot {
						logf("⚠️ 危险组合:二进制钉在 %s,而这次发的配置是 %s —— "+
							"旧二进制配新配置(§15.4)。要么 `loom rollback %s` 把源头也退回去,"+
							"要么 `loom pin -clear`", short(pin.Snapshot), short(id), short(pin.Snapshot))
					}
					lastSSOT, lastBuilt, lastBin = cur, id, binSum
					health.LastSuccess = opts.Now().Format(time.RFC3339)
					health.LastSnapshot, health.LastSSOT = id, cur
					// **LastError 刻意不清空。** 清了的话一次成功就把
					// "刚才卡了两小时"抹掉了,而那正是要留住的信息。
					saveHealth()
				} else {
					logf("未发布:%v", err)
					health.LastError = err.Error()
					health.LastErrorAt = opts.Now().Format(time.RFC3339)
					saveHealth()
					if changed {
						lastSSOT = cur // 同一份坏内容不重复刷屏,改动了会再试
					}
				}
			}
		}

		if opts.Once {
			return nil
		}
		// 每轮都刷一次 UpdatedAt:它是心跳。**和 LastSuccess 分开** ——
		// 昨天那次故障里心跳一直正常,停住的是 LastSuccess。
		saveHealth()
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(opts.Interval):
		}
	}
}

func publishOnce(opts *Options, body []byte, bins map[string][]byte, logf func(string, ...any)) (string, error) {
	t, err := Build(body, opts.Key, Meta{
		CreatedAt: opts.Now().Format(time.RFC3339), Author: opts.Author,
		Binaries: bins,
	})
	if err != nil {
		return "", err
	}
	// 分发点已经在提供这个快照就别推了 —— 内容哈希相同意味着字节相同(§12)。
	if served, err := opts.Target.Current(); err == nil && served == t.Snapshot {
		logf("快照 %s,分发点已是最新", short(t.Snapshot))
		return t.Snapshot, nil
	}
	if err := opts.Target.Push(t); err != nil {
		return "", fmt.Errorf("推送到 %s:%w", opts.Target, err)
	}
	logf("已发布 %s(%d 个节点:%s)→ %s",
		short(t.Snapshot), len(t.Owners()), strings.Join(t.Owners(), " "), opts.Target)

	if opts.VerifyURL != "" {
		if err := VerifyServed(opts.VerifyURL, t.Snapshot, opts.DNS, 20*time.Second); err != nil {
			// 推成功了但节点取不到,等于没发布。必须当成失败。
			return "", fmt.Errorf("推完了,但从节点视角取不到:%w", err)
		}
		logf("  ✅ 节点视角已确认(%s)", opts.VerifyURL)
	}
	return t.Snapshot, nil
}

// readBinary 读要一起发的二进制,并返回它的内容哈希。
//
// 每轮都读:重新编译之后不重启发布器就发不出去,那是"改了没生效"里最难
// 想到的一种。
func readBinary(path string) (map[string][]byte, string, error) {
	if path == "" {
		return nil, "", nil
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, "", err
	}
	sum := sha256.Sum256(b)
	return map[string][]byte{runtime.GOOS + "/" + runtime.GOARCH: b}, hex.EncodeToString(sum[:]), nil
}

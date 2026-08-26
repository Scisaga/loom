package publish

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"runtime"
	"strings"
	"time"

	"loom/internal/snapshot"
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
	// ReleaseDir 为空的兼容模式才会每轮直接读取它；正常显式 release 模式
	// 只把它用于提示“本机构建已变化但尚未放行”,真正发布的是内容寻址副本。
	BinaryPath string

	// ReleaseDir 是放行记录所在目录(见 release.go)。
	//
	// **非空时,只发被 `loom release` 显式批准过的二进制。** 留空则回到
	// 旧行为(发 BinaryPath 指的那份,一变就发)—— 那正是"一次 go build
	// 武装全网升级"的来源,只为不把既有部署一刀切断而保留。
	ReleaseDir string

	// AllowUntraceable 放行"追溯不回 git 的二进制"。
	//
	// 默认**不放行**:认不出 commit 或构建自脏工作区的二进制一旦发到全网,
	// 出了问题就没法用 git 复现,而 5 台机器同时中招。这与 backup 里
	// "要么加密要么显式 -plaintext"是同一个规矩 —— **风险选项要显式选,
	// 不能默认帮人做主**。
	//
	// 救火时确实可能要发一个没提交的修复,所以留了这个出口,而不是硬堵死。
	AllowUntraceable bool

	// HealthPath 是发布器写自己状态的地方(见 health.go)。留空则不写。
	//
	// 没有它的话,"进程活着但发不出去"只能靠翻 journal 发现 —— 而没人
	// 会去翻一个 systemd 显示 active 的服务的日志。
	HealthPath string
	// LockPath 串行化每一次 Build→Push→Verify→存档/历史事务。生产
	// 命令必须设置为 LockPath；留空只供纯内存/单元测试调用，
	// 避免碰宿主 /var/lib。
	LockPath string

	Interval time.Duration
	Once     bool
	Log      io.Writer
	// Now 由调用方注入。发布器是运行期组件,它**必须**读时钟,
	// 只是入口收在这一处(渲染与打包仍然不读,§12)。
	Now func() time.Time

	// beforeLock 只给包内回归测试精确构造“读旧输入→另一笔
	// 发布完成→本轮取锁”的窗口；生产入口无法设置。
	beforeLock func()
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
		Version:         version.Self(),
		PID:             os.Getpid(),
		StartedAt:       opts.Now().Format(time.RFC3339Nano),
		IntervalSeconds: max(1, int64(opts.Interval/time.Second)),
	}
	// 写不出状态文件不该拦住发布 —— 发布是主职,自报是附加。
	// 但要说一次,否则"状态文件一直是旧的"会变成新的静默故障。
	saveHealth := func() {
		health.UpdatedAt = opts.Now().Format(time.RFC3339Nano)
		if err := health.Write(opts.HealthPath); err != nil {
			logf("⚠️ 写发布器状态失败:%v —— loom status 看到的会是旧的", err)
		}
	}
	retryPending := false
	recordFailure := func(err error) {
		if err == nil {
			return
		}
		retryPending = true
		health.LastError = err.Error()
		health.LastErrorAt = opts.Now().Format(time.RFC3339Nano)
		saveHealth()
	}
	saveHealth()

	lastSSOT := ""
	lastBuilt := ""
	lastBin := ""
	lastPin := ""
	lastLive := ""
	lastRel := ""

	for {
		var iterationErr error
		body, err := os.ReadFile(opts.SSOTPath)
		if err != nil {
			iterationErr = fmt.Errorf("读 SSOT 失败:%w", err)
			logf("未发布:%v", iterationErr)
			recordFailure(iterationErr)
		} else {
			h := sha256.Sum256(body)
			ssotSum := hex.EncodeToString(h[:])
			// 变化坐标使用完整 SHA-256；截断只用于人读日志。
			// 若把 64-bit 前缀当成 inputsChanged/Health 的事实，
			// 精心构造同前缀的 SSOT 会被误判为 no-op。
			cur := ssotSum

			// 二进制也算输入的一部分:它变了,快照就该变(§15.4 绑定回滚)。
			//
			// 发哪一份,优先级是 **钉住 > 放行 > (什么都不发)**:
			//
			//	钉住  救火状态,粘性覆盖。救火期间不该被一次 release 悄悄解开
			//	放行  loom release 显式批准过的那一份(D77)
			//	都没有  只发配置。**不回落到本机二进制** —— 那正是要根治的
			//	        "一次 go build 武装全网升级"
			binPath := ""
			expectedBin := ""
			selectedCandidate := BinaryCandidate{}
			hasCandidate := false
			selectedSource := "config"
			selectedAuthorization := ""
			blocked := ""
			block := func(f string, a ...any) {
				if blocked == "" {
					blocked = fmt.Sprintf(f, a...)
				}
			}
			pin, pinBin, pinCandidate, perr := ReadPinCandidate(opts.PinDir)
			if perr != nil {
				block("读钉住状态失败:%v", perr)
			} else if pin != nil {
				binPath = pinBin
				expectedBin = pin.SHA256
				selectedCandidate, hasCandidate = pinCandidate, true
				selectedSource = "pin"
				selectedAuthorization = pin.Snapshot + ":" + pin.SHA256
				if pin.Snapshot != lastPin {
					logf("⚠️ 二进制钉在 %s(%s)—— 重新编译不会发出去", short(pin.Snapshot), pin.Reason)
					lastPin = pin.Snapshot
				}
			} else {
				if lastPin != "" {
					logf("钉住已解除,恢复发放行的二进制")
					lastPin = ""
				}
				if opts.ReleaseDir == "" {
					// 显式关掉 release 机制:回到"发 -binary 指的那份"。
					// 留这条路是为了不把既有部署和测试一刀切断。
					binPath = opts.BinaryPath
					if binPath != "" {
						selectedSource = "legacy-binary"
						selectedAuthorization = binPath
					}
				} else if rel, relBin, relCandidate, rerr := ReadReleaseCandidate(opts.ReleaseDir); rerr != nil {
					block("读放行状态失败:%v", rerr)
				} else if rel != nil {
					binPath = relBin
					expectedBin = rel.SHA256
					selectedCandidate, hasCandidate = relCandidate, true
					selectedSource = "release"
					selectedAuthorization = rel.SHA256
					if rel.SHA256 != lastRel {
						logf("放行的二进制:%s(commit %s)—— %s",
							short(rel.SHA256), version.Short(rel.Commit), rel.Reason)
						lastRel = rel.SHA256
					}
				} else if lastRel != "-" {
					// **说一次就够,但必须说。** 沉默的话,"节点为什么不升级"
					// 会变成一个查不出来的怪事。
					logf("还没放行过任何二进制:只发配置。要发二进制:loom release -reason <理由>")
					lastRel = "-"
				}
			}

			var bins map[string][]byte
			var binSum string
			var berr error
			if hasCandidate {
				bins = map[string][]byte{runtime.GOOS + "/" + runtime.GOARCH: selectedCandidate.Body}
				binSum = selectedCandidate.SHA256
			} else {
				bins, binSum, berr = readBinary(binPath)
			}
			if berr != nil {
				block("读二进制失败:%v", berr)
			}
			if berr == nil && expectedBin != "" && binSum != expectedBin {
				block("二进制在状态检查之后发生变化(记录 %s,实际 %s),拒绝发布",
					short(expectedBin), short(binSum))
			}
			inputStamp := publishInputStamp{
				SSOT: ssotSum, Source: selectedSource,
				Authorization: selectedAuthorization, Binary: binSum,
			}
			// 发出去之前先问:这份二进制追溯得回 git 吗。
			// 问的是**文件**不是本进程 —— 钉住时发的是历史二进制,
			// 而它的 commit 只有文件自己知道。
			if berr == nil && binPath != "" {
				body := bins[runtime.GOOS+"/"+runtime.GOARCH]
				vc, verr := InspectBinary(newBinaryCandidate(body))
				if verr != nil {
					block("读不出待发布二进制的构建信息:%v", verr)
				} else if !vc.Traceable() && !opts.AllowUntraceable {
					why := "认不出 commit"
					if vc.Dirty {
						why = "构建自脏工作区(" + version.Short(vc.Commit) + "+dirty)"
					}
					block("%s", "二进制"+why+",追溯不回 git —— 拒绝发到全网。"+
						"提交后重新编译,或者明知故犯时加 -allow-dirty")
				}
			}

			// 本机二进制变了但没 release —— **正是"我重新编译了但没发出去"
			// 那一刻**。钉住和放行两种情形都要说,只说一次,不刷屏。
			if pin == nil && opts.ReleaseDir != "" && opts.BinaryPath != "" {
				if _, liveSum, err := readBinary(opts.BinaryPath); err == nil && liveSum != lastLive {
					if lastLive != "" && liveSum != binSum {
						logf("ⓘ 本机二进制变了(%s),但没放行 —— 不会发出去。要发:loom release -reason <理由>",
							short(liveSum))
					}
					lastLive = liveSum
				}
			}
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
				// current.json 损坏/截断正是 D33 要自修复的对象。它不是本地
				// 安全门,不能因为读不到就拒绝 Push；把状态视为 unknown/diverged,
				// 重新铺树并由 Push + 节点视角 Verify 决定最终成败。
				logf("问不到分发点当前指向哪个快照:%v —— 按分叉处理并重推", serr)
			}

			first := lastSSOT == ""
			// 二进制变了也算变 —— 包括**从"没有"变成"有"**。
			//
			// 原先写的是 `lastBin != "" && binSum != lastBin`,那个守卫在
			// D77 之前无害:binPath 总是有值,binSum 永远非空。D77 让
			// "没放行 = 不发二进制"成为合法状态之后,`"" → sha` 这个转换
			// 就被守卫吞掉了 —— 发布器认了放行,却不重推。实测踩到。
			//
			// 用 !first 代替:首轮本来就走 cur != lastSSOT 那一支,
			// 第二个条件在首轮不需要出力。
			changed := inputsChanged(first, cur, lastSSOT, binSum, lastBin)
			// 分发点和本地算出来的不一致就重推,与 SSOT 有没有变无关。
			diverged := serr != nil || (lastBuilt != "" && served != lastBuilt)

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

			if blocked != "" {
				// **拦下来也要记进 Health。** 只打日志的话,这又变成一个
				// "systemd 说 active 但发不出去"的静默故障 —— 正是 D72
				// 要根治的形状。
				logf("未发布:%s", blocked)
				iterationErr = fmt.Errorf("%s", blocked)
				recordFailure(iterationErr)
			} else if changed || diverged || retryPending {
				id, err := func() (string, error) {
					if opts.beforeLock != nil {
						opts.beforeLock()
					}
					unlock := func() {}
					if opts.LockPath != "" {
						var err error
						unlock, err = AcquireLock(opts.LockPath)
						if err != nil {
							return "", err
						}
					}
					defer unlock()

					// 锁只能防止两笔提交交错，不能自动让锁外早先读到
					// 的输入变新。拿锁后再读一次授权坐标：若 daemon A
					// 读了旧 SSOT，手工 B 先发布新 SSOT，A 不能随后把
					// current 完整地退回旧版。
					fresh, err := readPublishInputStamp(&opts)
					if err != nil {
						return "", fmt.Errorf("取得发布锁后重读输入:%w", err)
					}
					if fresh != inputStamp {
						return "", fmt.Errorf("发布输入在读取后、取锁前发生变化(%s → %s)；本轮已放弃，下一轮重新读取",
							inputStamp.summary(), fresh.summary())
					}

					if pin != nil {
						candidateID, err := SnapshotID(body, bins)
						if err != nil {
							return "", fmt.Errorf("核对钉住快照:%w", err)
						}
						if candidateID != pin.Snapshot {
							return "", fmt.Errorf("钉住安全门:当前源头+钉住二进制重算为 %s，不是钉住的 %s；"+
								"已拒绝发布旧二进制+新配置组合。请 `loom rollback %s` 同时恢复源头，或 `loom pin -clear`",
								short(candidateID), short(pin.Snapshot), pin.Snapshot)
						}
					}

					// 源头存档是回滚的必要半边，不是可有可无的日志。
					// 必须在 Push 前持久化；否则可以绿色发布一个永远回不去的快照。
					sum, err := ArchiveSSOT(opts.ArchiveDir, body)
					if err != nil {
						return "", fmt.Errorf("源头存档失败，拒绝发布:%w", err)
					}
					id, err := publishOnce(&opts, body, bins, logf)
					if err != nil {
						return "", err
					}
					// 存档与历史是这笔发布事务的一部分。放到锁外时，
					// daemon 与手工 publish 可能按相反顺序追加历史，甚至
					// 同时写同一个存档临时文件。锁仍只持有一轮，不是
					// daemon 生命周期锁。
					// 只在快照 id 变了时才写一行；同一把锁保证
					// ReadPublished → append 不会被另一笔发布插入。
					if wrote, herr := AppendPublished(opts.ArchiveDir, Published{
						At: opts.Now().Format(time.RFC3339), Snapshot: id,
						SSOTSum: sum, Binary: binSum, Author: opts.Author,
					}); herr != nil {
						return "", fmt.Errorf("快照 %s 已推送，但发布历史持久化失败（不标记成功，下一轮重试）:%w", short(id), herr)
					} else if wrote {
						logf("  已记进发布历史(%s)", HistoryPath(opts.ArchiveDir))
					}
					return id, nil
				}()
				// **校验不过时不更新 lastSSOT**:下一轮还要再试一次,
				// 否则改坏了再改回来的中间态会被当成"已经处理过"。
				if err == nil {
					lastSSOT, lastBuilt, lastBin = cur, id, binSum
					retryPending = false
					health.LastSuccess = opts.Now().Format(time.RFC3339Nano)
					health.LastSnapshot, health.LastSSOT = id, cur
					// **LastError 刻意不清空。** 清了的话一次成功就把
					// "刚才卡了两小时"抹掉了,而那正是要留住的信息。
					saveHealth()
				} else {
					logf("未发布:%v", err)
					iterationErr = err
					recordFailure(err)
				}
			}
		}

		if opts.Once {
			return iterationErr
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
	// 分发点已经指向这个快照时可以不重传,但**不能跳过节点视角校验**。
	// 上一轮可能是 Push 成功、VerifyServed 失败；如果这里直接报成功,健康
	// 状态会在节点仍取不到时假绿。
	pub := opts.Key.Public().(ed25519.PublicKey)
	resultSnapshot := t.Snapshot
	needsPush := true
	served, currentErr := opts.Target.Current()
	if currentErr == nil && served == t.Snapshot {
		logf("快照 %s,分发点已是最新", short(t.Snapshot))
		complete, why, err := releaseSurfaceComplete(opts.Target, t, pub)
		if err != nil {
			return "", fmt.Errorf("核对已发布快照 %s:%w", short(t.Snapshot), err)
		}
		if complete {
			needsPush = false
		} else {
			logf("  已发布快照不完整(%s),从本地可信产物重铺", why)
		}
	} else if currentErr == nil && served != "" {
		// snapshot ID 仍含 raw SSOT hash。仅改注释/排版时，新 ID 会变化，
		// 但运行配置、组件、秘密代次、下线集合和二进制可能逐项相同。
		// 当前 manifest 是可信签名且整棵旧树完整时，保留它；不要为了源头
		// 的非运行差异让全网 rollout 一次。
		equivalent, why, err := equivalentCurrentRelease(opts.Target, t, served, pub, opts.ArchiveDir)
		if err != nil {
			return "", fmt.Errorf("核对当前快照 %s:%w", short(served), err)
		}
		if equivalent {
			needsPush = false
			resultSnapshot = served
			logf("运行产物未变,保留 current 快照 %s", short(served))
		} else if why != "" {
			logf("当前快照不能复用(%s),发布新快照 %s", why, short(t.Snapshot))
		}
	}
	if needsPush {
		if err := opts.Target.Push(t); err != nil {
			return "", fmt.Errorf("推送到 %s:%w", opts.Target, err)
		}
		// Push 返回 nil 仍不等于树完整。尤其是 same-current 自愈时，旧
		// current.json 一直可见，必须确认正文、manifest、签名和 blob 都
		// 已经重新铺好，才能把 Health 标成成功。
		complete, why, err := releaseSurfaceComplete(opts.Target, t, pub)
		if err != nil {
			return "", fmt.Errorf("推送后核对快照 %s:%w", short(t.Snapshot), err)
		}
		if !complete {
			return "", fmt.Errorf("推送后快照 %s 仍不完整:%s", short(t.Snapshot), why)
		}
		logf("已发布 %s(%d 个节点:%s)→ %s",
			short(t.Snapshot), len(t.Owners()), strings.Join(t.Owners(), " "), opts.Target)
	}

	if opts.VerifyURL != "" {
		if err := VerifyServed(opts.VerifyURL, resultSnapshot, opts.DNS, 20*time.Second, t, pub); err != nil {
			// 推成功了但节点取不到,等于没发布。必须当成失败。
			return "", fmt.Errorf("推完了,但从节点视角取不到:%w", err)
		}
		logf("  ✅ 节点视角已确认(%s)", opts.VerifyURL)
	}
	return resultSnapshot, nil
}

// equivalentCurrentRelease 判断 current 指向的**已有签名快照**是否与新树
// 运行等价并且仍完整可用。仅 manifest 看起来相同不够：正文或 blob 已丢时
// 必须发布新树自愈，不能把旧 current 永久保留下来。
func equivalentCurrentRelease(target Target, t *Tree, current string, pub ed25519.PublicKey, archiveDir string) (bool, string, error) {
	wantManifestPath := t.Snapshot + "/snapshot.json"
	var want snapshot.Manifest
	if err := json.Unmarshal(t.Files[wantManifestPath], &want); err != nil {
		return false, "", fmt.Errorf("解析本地产物 %s:%w", wantManifestPath, err)
	}

	manifestPath := current + "/snapshot.json"
	manifestBytes, found, err := target.ReadFile(manifestPath)
	if err != nil {
		return false, "", fmt.Errorf("读取 %s:%w", manifestPath, err)
	}
	if !found {
		return false, manifestPath + " 缺失", nil
	}
	var got snapshot.Manifest
	if err := json.Unmarshal(manifestBytes, &got); err != nil {
		return false, manifestPath + " 损坏", nil
	}
	if got.ID != current {
		return false, manifestPath + " 的 id 与 current 不符", nil
	}

	signaturePath := current + "/snapshot.sig"
	sig, found, err := target.ReadFile(signaturePath)
	if err != nil {
		return false, "", fmt.Errorf("读取 %s:%w", signaturePath, err)
	}
	if !found {
		return false, signaturePath + " 缺失", nil
	}
	if err := snapshot.VerifySignature(manifestBytes, sig, pub); err != nil {
		return false, signaturePath + " 损坏或与 manifest 不配对", nil
	}
	if !sameRuntimeContent(&got, &want) {
		return false, "运行内容确有变化", nil
	}
	// 保留旧 current 也等于保留它的回滚承诺。本轮只拿到
	// 新 SSOT 字节，无法从运行等价产物逆推出旧 manifest.SSOTHash
	// 对应的源头；若旧存档已丢，必须发布本轮新快照，而不是
	// 让 Health 绿在一个无法 rollback 的旧 id 上。空 archiveDir 只供
	// 包内纯内存测试；生产 CLI 已拒绝关闭存档。
	if archiveDir != "" {
		sum := got.SSOTSum()
		if sum == "" {
			return false, "旧快照 manifest 缺少 ssot_hash，无法保证回滚", nil
		}
		if _, err := ReadArchivedSSOT(archiveDir, sum); err != nil {
			return false, fmt.Sprintf("旧快照源头存档不可用(%v)", err), nil
		}
	}

	for _, p := range t.Paths() {
		if p == "current.json" || p == wantManifestPath || p == t.Snapshot+"/snapshot.sig" {
			continue
		}
		oldPath := p
		if suffix, ok := strings.CutPrefix(p, t.Snapshot+"/"); ok {
			oldPath = current + "/" + suffix
		}
		body, found, err := target.ReadFile(oldPath)
		if err != nil {
			return false, "", fmt.Errorf("读取 %s:%w", oldPath, err)
		}
		if !found {
			return false, oldPath + " 缺失", nil
		}
		if !bytes.Equal(body, t.Files[p]) {
			return false, oldPath + " 内容损坏", nil
		}
	}
	for p := range t.Blobs {
		ok, err := target.HasBlob(p)
		if err != nil {
			return false, "", fmt.Errorf("核对 blob %s:%w", p, err)
		}
		if !ok {
			return false, p + " 缺失或内容损坏", nil
		}
	}
	return true, "", nil
}

func sameRuntimeContent(a, b *snapshot.Manifest) bool {
	aa, bb := *a, *b
	aa.ID, aa.SSOTHash, aa.CreatedAt, aa.Author = "", "", "", ""
	bb.ID, bb.SSOTHash, bb.CreatedAt, bb.Author = "", "", "", ""
	ab, errA := json.Marshal(&aa)
	bbBody, errB := json.Marshal(&bb)
	return errA == nil && errB == nil && bytes.Equal(ab, bbBody)
}

// releaseSurfaceComplete 核对 current.json 背后的整棵可服务快照。
//
// snapshot id 刻意不含 CreatedAt/Author，因此同一个内容快照可能留有一份
// 由同一私钥签过、但发布时间不同的合法 manifest。这里比较不可变内容并
// 验目标上的 manifest/signature 配对，而不是逐字节强迫它等于本轮新签的
// metadata；节点正文则应当完全一致。
func releaseSurfaceComplete(target Target, t *Tree, pub ed25519.PublicKey) (bool, string, error) {
	manifestPath := t.Snapshot + "/snapshot.json"
	signaturePath := t.Snapshot + "/snapshot.sig"

	wantManifestBytes, ok := t.Files[manifestPath]
	if !ok {
		return false, "本地产物缺 snapshot.json", fmt.Errorf("Tree %s 没有 %s", short(t.Snapshot), manifestPath)
	}
	var wantManifest snapshot.Manifest
	if err := json.Unmarshal(wantManifestBytes, &wantManifest); err != nil {
		return false, "本地 manifest 无效", fmt.Errorf("解析本地产物 %s:%w", manifestPath, err)
	}

	gotManifestBytes, found, err := target.ReadFile(manifestPath)
	if err != nil {
		return false, "", fmt.Errorf("读取 %s:%w", manifestPath, err)
	}
	if !found {
		return false, manifestPath + " 缺失", nil
	}
	var gotManifest snapshot.Manifest
	if err := json.Unmarshal(gotManifestBytes, &gotManifest); err != nil {
		return false, manifestPath + " 损坏", nil
	}
	if !sameSnapshotContent(&gotManifest, &wantManifest) {
		return false, manifestPath + " 内容与本地产物不符", nil
	}

	sig, found, err := target.ReadFile(signaturePath)
	if err != nil {
		return false, "", fmt.Errorf("读取 %s:%w", signaturePath, err)
	}
	if !found {
		return false, signaturePath + " 缺失", nil
	}
	if err := snapshot.VerifySignature(gotManifestBytes, sig, pub); err != nil {
		return false, signaturePath + " 损坏或与 manifest 不配对", nil
	}

	for _, p := range t.Paths() {
		if p == "current.json" || p == manifestPath || p == signaturePath {
			continue
		}
		got, found, err := target.ReadFile(p)
		if err != nil {
			return false, "", fmt.Errorf("读取 %s:%w", p, err)
		}
		if !found {
			return false, p + " 缺失", nil
		}
		if !bytes.Equal(got, t.Files[p]) {
			return false, p + " 内容损坏", nil
		}
	}

	for p := range t.Blobs {
		ok, err := target.HasBlob(p)
		if err != nil {
			return false, "", fmt.Errorf("核对 blob %s:%w", p, err)
		}
		if !ok {
			return false, p + " 缺失或内容损坏", nil
		}
	}
	return true, "", nil
}

func sameSnapshotContent(a, b *snapshot.Manifest) bool {
	aa, bb := *a, *b
	aa.CreatedAt, aa.Author = "", ""
	bb.CreatedAt, bb.Author = "", ""
	ab, errA := json.Marshal(&aa)
	bbBody, errB := json.Marshal(&bb)
	return errA == nil && errB == nil && bytes.Equal(ab, bbBody)
}

type publishInputStamp struct {
	SSOT          string
	Source        string
	Authorization string
	Binary        string
}

func (s publishInputStamp) summary() string {
	auth := s.Authorization
	if strings.Contains(auth, ":") {
		parts := strings.Split(auth, ":")
		for i := range parts {
			parts[i] = short(parts[i])
		}
		auth = strings.Join(parts, ":")
	} else {
		auth = short(auth)
	}
	return fmt.Sprintf("ssot=%s source=%s auth=%s binary=%s",
		short(s.SSOT), s.Source, auth, short(s.Binary))
}

// readPublishInputStamp 在持有 publish.lock 后重新选一次输入。
// 它不返回要发的字节：只用来证明锁外读到内存的那组字节
// 仍是当前被授权的组合。坐标变了就丢掉整轮，不在原地混搭。
func readPublishInputStamp(opts *Options) (publishInputStamp, error) {
	body, err := os.ReadFile(opts.SSOTPath)
	if err != nil {
		return publishInputStamp{}, fmt.Errorf("读 SSOT:%w", err)
	}
	stamp := publishInputStamp{SSOT: sha256Bytes(body), Source: "config"}

	pin, _, pinCandidate, err := ReadPinCandidate(opts.PinDir)
	if err != nil {
		return publishInputStamp{}, fmt.Errorf("读钉住状态:%w", err)
	}
	if pin != nil {
		stamp.Source = "pin"
		stamp.Authorization = pin.Snapshot + ":" + pin.SHA256
		stamp.Binary = pinCandidate.SHA256
		return stamp, nil
	}

	if opts.ReleaseDir == "" {
		if opts.BinaryPath == "" {
			return stamp, nil
		}
		_, sum, err := readBinary(opts.BinaryPath)
		if err != nil {
			return publishInputStamp{}, fmt.Errorf("读兼容模式二进制:%w", err)
		}
		stamp.Source = "legacy-binary"
		stamp.Authorization = opts.BinaryPath
		stamp.Binary = sum
		return stamp, nil
	}

	rel, _, candidate, err := ReadReleaseCandidate(opts.ReleaseDir)
	if err != nil {
		return publishInputStamp{}, fmt.Errorf("读放行状态:%w", err)
	}
	if rel != nil {
		stamp.Source = "release"
		stamp.Authorization = rel.SHA256
		stamp.Binary = candidate.SHA256
	}
	return stamp, nil
}

// readBinary 读要一起发的二进制,并返回它的内容哈希。
//
// 每轮都读选定的不可变副本:pin/release 状态可能在运行中切换,发布器不应
// 需要重启。启用 ReleaseDir 时它不会读取刚编译的本机文件 —— 只有显式
// `loom release` 原子更新 current.json 后才会选中新候选。
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

// inputsChanged 说这一轮的输入(SSOT 或二进制)和上一轮比变了没有。
//
// 拆出来是为了能测 `"" → sha` 那个转换 —— 它只在跨轮之间发生,
// 而 -once 跑不出跨轮。实测踩到过一次:发布器认了放行却不重推。
func inputsChanged(first bool, cur, lastSSOT, binSum, lastBin string) bool {
	// 首轮本来就走 cur != lastSSOT 那一支(lastSSOT 是空串),
	// 第二个条件在首轮不需要出力,也不该出力。
	return cur != lastSSOT || (!first && binSum != lastBin)
}

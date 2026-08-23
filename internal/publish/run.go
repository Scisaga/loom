package publish

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"strings"
	"time"
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

	lastSSOT := ""
	lastBuilt := ""

	for {
		body, err := os.ReadFile(opts.SSOTPath)
		if err != nil {
			logf("读 SSOT 失败:%v", err)
		} else {
			h := sha256.Sum256(body)
			cur := hex.EncodeToString(h[:8])

			served, serr := opts.Target.Current()
			if serr != nil {
				logf("问不到分发点当前指向哪个快照:%v", serr)
			}

			first := lastSSOT == ""
			changed := cur != lastSSOT
			// 分发点和本地算出来的不一致就重推,与 SSOT 有没有变无关。
			diverged := serr == nil && lastBuilt != "" && served != lastBuilt

			switch {
			case first:
				// 刚起来时不知道自己处在什么状态,先核对一遍。
				logf("启动,核对分发点(SSOT %s)", cur[:8])
			case changed:
				logf("SSOT 变了(%s)", cur[:8])
			case diverged:
				logf("分发点指向 %s,本地算出来是 %s —— 重推", short(served), short(lastBuilt))
			}

			if changed || diverged {
				id, err := publishOnce(&opts, body, logf)
				// **校验不过时不更新 lastSSOT**:下一轮还要再试一次,
				// 否则改坏了再改回来的中间态会被当成"已经处理过"。
				if err == nil {
					lastSSOT, lastBuilt = cur, id
				} else {
					logf("未发布:%v", err)
					if changed {
						lastSSOT = cur // 同一份坏内容不重复刷屏,改动了会再试
					}
				}
			}
		}

		if opts.Once {
			return nil
		}
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(opts.Interval):
		}
	}
}

func publishOnce(opts *Options, body []byte, logf func(string, ...any)) (string, error) {
	t, err := Build(body, opts.Key, Meta{
		CreatedAt: opts.Now().Format(time.RFC3339), Author: opts.Author,
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

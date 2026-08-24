package publish

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// 发布历史:中控记下自己发过哪些快照。
//
// **为什么必须在中控本地记。** 分发点上快照层确实都在,但它是
// `autoindex off` 的 —— 列不出来。而事件历史里的 `snapshot` 记的是
// **每台节点装的版本变了**,不是"中控发过什么":一个快照发出去但没有
// 任何节点取到,事件里就一条都没有。
//
// **只记变化,不记状态**(同 events 包)。发布器每 30 秒收敛一轮,同一个
// 快照会被反复确认;逐轮记一行的话,一天就是 2880 行"还是那个快照"。
// 所以只有 id 与上一条不同才追加。
//
// 它回答的是 `loom rollback` 的前置问题:**我现在能退到哪儿。**
// 光有快照 id 列表还不够 —— 还要知道哪些**有源头存档**,因为没有存档的
// 那些退不了(D61)。所以 Published 与存档目录放在一起,由 `loom snapshots`
// 交叉核对。

const historyFile = "published.jsonl"

// Published 是一次"发出去的快照变了"。
type Published struct {
	// At 是 RFC3339 时间,由调用方注入(§12:包内不读时钟)。
	At string `json:"at"`

	Snapshot string `json:"snapshot"`
	// SSOTSum 是这个快照的源头哈希 —— 拿它去存档里找那一版。
	SSOTSum string `json:"ssot_sum"`
	// Binary 是配套二进制的哈希。回滚要两半一起退,所以两边都记。
	Binary string `json:"binary,omitempty"`
	Author string `json:"author,omitempty"`
}

// AppendPublished 追加一条,但**只在快照 id 与上一条不同时**。
//
// 返回是否真的写了,让调用方能把"发布了新版本"和"确认还是那一版"分开说。
func AppendPublished(dir string, rec Published) (bool, error) {
	if dir == "" || rec.Snapshot == "" {
		return false, nil
	}
	prev, err := ReadPublished(dir)
	if err != nil {
		return false, err
	}
	if n := len(prev); n > 0 && prev[n-1].Snapshot == rec.Snapshot {
		return false, nil
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return false, err
	}
	body, err := json.Marshal(&rec)
	if err != nil {
		return false, err
	}
	f, err := os.OpenFile(filepath.Join(dir, historyFile),
		os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return false, err
	}
	defer f.Close()
	if _, err := f.Write(append(body, '\n')); err != nil {
		return false, err
	}
	return true, nil
}

// ReadPublished 按时间顺序读回全部记录。文件不存在不是错误 ——
// 还没发过任何东西是一个合法状态。
//
// 坏行跳过而不是整份读失败:这是一份追加式日志,写到一半断电会留下半行,
// 而为了一行坏数据丢掉整段历史,恰恰是在最需要它的时候把它弄没。
func ReadPublished(dir string) ([]Published, error) {
	if dir == "" {
		return nil, nil
	}
	f, err := os.Open(filepath.Join(dir, historyFile))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var out []Published
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var p Published
		if json.Unmarshal([]byte(line), &p) != nil || p.Snapshot == "" {
			continue
		}
		out = append(out, p)
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("读发布历史:%w", err)
	}
	return out, nil
}

// HistoryPath 是发布历史的位置。给错误消息用。
func HistoryPath(dir string) string { return filepath.Join(dir, historyFile) }

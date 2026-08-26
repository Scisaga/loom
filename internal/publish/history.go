package publish

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
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
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return false, err
	}
	path := filepath.Join(dir, historyFile)
	// 断电可能留下一行没有 LF 的半截 JSON。直接 O_APPEND
	// 会把新记录粘在它后面：Write+Sync 都成功，但读时整行
	// 仍是坏的，发布器却会假绿。先截回最后一个完整 LF。
	if err := truncatePartialHistoryTail(path); err != nil {
		return false, err
	}
	prev, err := ReadPublished(dir)
	if err != nil {
		return false, err
	}
	if n := len(prev); n > 0 && prev[n-1].Snapshot == rec.Snapshot {
		return false, nil
	}
	body, err := json.Marshal(&rec)
	if err != nil {
		return false, err
	}
	f, err := os.OpenFile(path,
		os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return false, err
	}
	if _, err := f.Write(append(body, '\n')); err != nil {
		_ = f.Close()
		return false, err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return false, err
	}
	if err := f.Close(); err != nil {
		return false, err
	}
	// 不只相信 Write/Sync 返回值：按真实读取路径回读，确认
	// 刚追加的记录真的是一条可见 JSON，而不是粘在半行后。
	confirmed, err := ReadPublished(dir)
	if err != nil {
		return false, fmt.Errorf("回读发布历史:%w", err)
	}
	if len(confirmed) == 0 || confirmed[len(confirmed)-1] != rec {
		return false, fmt.Errorf("发布历史已写入但回读不到目标记录")
	}
	return true, nil
}

func truncatePartialHistoryTail(path string) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o644)
	if err != nil {
		return err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return err
	}
	if info.Size() == 0 {
		return nil
	}
	var last [1]byte
	if _, err := f.ReadAt(last[:], info.Size()-1); err != nil {
		return err
	}
	if last[0] == '\n' {
		return nil
	}

	const chunkSize = int64(64 << 10)
	end := info.Size()
	for end > 0 {
		start := end - chunkSize
		if start < 0 {
			start = 0
		}
		buf := make([]byte, end-start)
		n, err := f.ReadAt(buf, start)
		if err != nil && err != io.EOF {
			return err
		}
		if i := bytes.LastIndexByte(buf[:n], '\n'); i >= 0 {
			if err := f.Truncate(start + int64(i) + 1); err != nil {
				return err
			}
			return f.Sync()
		}
		end = start
	}
	if err := f.Truncate(0); err != nil {
		return err
	}
	return f.Sync()
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

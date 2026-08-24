package publish

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
)

// 源头存档:中控保存每一版发布过的 SSOT,供回滚取用。
//
// **为什么在本地而不在分发点。** 分发点在设计上是当作已被攻陷来对待的
// (D32),签名保证它伪造不了配置。但源头里有 `ssh_port` 这类字段 ——
// SSOT 自己的注释写着"记在这里是为了 bootstrap 与排障,不是为了被连" ——
// 它们不出现在任何渲染产物里。把管理平面的信息主动送到那台机器上,
// 属于签名拦不住的那一类风险。
//
// 而这份存档本来也只有中控用得着:**只有它做渲染,节点从来不读 SSOT。**
// 它不是分发树的一部分,是中控自己的备份,所以归 `loom backup` 管。
//
// 内容寻址,和二进制同一个道理:源头不常变,同一版跨多个快照只存一份。
// 实测一份约 10 KB。

const archiveExt = ".yaml"

// ArchiveSSOT 把这一版源头存进存档,返回它的内容哈希。
//
// 已经存在就不重写 —— 路径即内容哈希,在即是对(同 Target.HasBlob)。
func ArchiveSSOT(dir string, ssotBytes []byte) (string, error) {
	if dir == "" {
		return "", nil
	}
	sum := sha256.Sum256(ssotBytes)
	name := hex.EncodeToString(sum[:])
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	dst := filepath.Join(dir, name+archiveExt)
	if _, err := os.Stat(dst); err == nil {
		return name, nil
	}
	// 先写临时文件再改名:回滚可能正好在读,而半截 YAML 会让它报一个
	// 跟真实原因无关的解析错误。
	tmp := dst + ".tmp"
	if err := os.WriteFile(tmp, ssotBytes, 0o644); err != nil {
		return "", err
	}
	if err := os.Rename(tmp, dst); err != nil {
		return "", err
	}
	return name, nil
}

// ReadArchivedSSOT 按内容哈希取回一版源头,并核对它确实是那一版。
//
// **核对不是多余的。** 存档在本机,但"本机文件没被动过"从来不是一个可以
// 假设的前提 —— 漂移检测这一整套东西存在的理由就是它。而这里核对的代价
// 是一次哈希,收益是不会拿一份错的源头去覆盖事实来源。
func ReadArchivedSSOT(dir, sum string) ([]byte, error) {
	if dir == "" {
		return nil, fmt.Errorf("没有指定源头存档目录")
	}
	if sum == "" {
		return nil, fmt.Errorf("快照没有记录源头哈希")
	}
	path := filepath.Join(dir, sum+archiveExt)
	body, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	got := sha256.Sum256(body)
	if hex.EncodeToString(got[:]) != sum {
		return nil, fmt.Errorf("存档 %s 的内容与文件名对不上 —— 这份存档被改过", path)
	}
	return body, nil
}

// ArchivePath 是某一版源头在存档里的位置。给错误消息和 `loom backup` 用。
func ArchivePath(dir, sum string) string {
	return filepath.Join(dir, sum+archiveExt)
}

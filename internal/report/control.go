package report

import (
	"encoding/json"
	"fmt"
	"os"

	"loom/internal/secret"
)

// ControlPath 是中控角色的本机配置。
//
// **它不是渲染产物**,和发布器的 unit、信任根、本机秘密层一样属于 bootstrap。
// 它引用的路径(git 工作副本、秘密层)是这台机器上的事实,不是平台约定 ——
// 写进 SSOT 会变成自我引用(SSOT 里记着 SSOT 在哪)。
const ControlPath = "/etc/loom/control.json"

// Control 让这台机器成为中控:多出改 SSOT 的能力(§14.2.3、D36)。
//
// 只有一台机器该有它。写操作收敛到一处,是因为任何节点都能到任何节点的
// 隧道地址 —— 五个写入口意味着一台被拿下就能去动其他四台。
type Control struct {
	// SSOTPath 是发布器盯着的那个文件。界面改的就是它,改完存盘,
	// 发布器 30 秒内接管 —— 所以界面上**没有"发布"按钮**。
	SSOTPath string `json:"ssot_path"`

	// Secrets / OperatorRef 指出运维口令从哪来。复用已有的秘密层,
	// 不新增一套凭据机制。
	Secrets     string `json:"secrets"`
	OperatorRef string `json:"operator_ref"`
	// BootstrapSSHKey 是中控范围唯一的 SSH bootstrap 私钥路径。它不在
	// SSOT，也不下发给节点；UI 只能导出相邻的 .pub。
	BootstrapSSHKey string `json:"bootstrap_ssh_key,omitempty"`
	// KnownHostsPath 是节点接入专用的 host-key 信任库。它不复用
	// 运行用户的 ~/.ssh/known_hosts，避免网页接入流程暗中继承
	// 中控主机上无关的 TOFU 记录。
	KnownHostsPath string `json:"known_hosts_path,omitempty"`
	// GeoIPDisabled disables the optional ipwho.is lookup used only to prefill
	// operator-editable Country / City during node declaration review. Lookup
	// failure is non-fatal even when this remains enabled.
	GeoIPDisabled bool `json:"geoip_disabled,omitempty"`

	// DistributionURL / DNS 用来回答"发布器跟上我这次改动了吗"。
	//
	// 看的是**分发点在提供哪个快照**,不是本机装了哪个 —— 后者会晚一整个
	// pull 周期,而改完之后最想知道的恰恰是"发出去了没有"。
	DistributionURL string `json:"distribution_url,omitempty"`
	DNS             string `json:"dns,omitempty"`
}

// LoadControl 读中控配置。文件不存在返回 (nil, nil) —— 绝大多数节点不是中控,
// 那不是错误。
func LoadControl(path string) (*Control, string, error) {
	b, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil, "", nil
	}
	if err != nil {
		return nil, "", err
	}
	var c Control
	if err := json.Unmarshal(b, &c); err != nil {
		return nil, "", fmt.Errorf("解析 %s:%w", path, err)
	}
	if c.SSOTPath == "" {
		return nil, "", fmt.Errorf("%s 缺 ssot_path", path)
	}
	if c.BootstrapSSHKey == "" {
		c.BootstrapSSHKey = "/etc/loom/control-bootstrap"
	}
	if c.KnownHostsPath == "" {
		c.KnownHostsPath = "/etc/loom/control-known_hosts"
	}
	if _, err := readSSOTSnapshot(c.SSOTPath); err != nil {
		return nil, "", fmt.Errorf("ssot_path 指向 %s,但读不到:%w", c.SSOTPath, err)
	}

	// 口令拿不到就**不给写权限**,而不是退化成"不需要认证"。
	// 后者是那种没有任何症状、直到出事才发现的配置错误。
	if c.Secrets == "" || c.OperatorRef == "" {
		return &c, "", fmt.Errorf("中控配置缺 secrets / operator_ref —— 写操作将全部关闭")
	}
	all, err := secret.Load(c.Secrets)
	if err != nil {
		return &c, "", fmt.Errorf("读秘密层:%w", err)
	}
	pw := all[c.OperatorRef]
	if pw == "" {
		return &c, "", fmt.Errorf("秘密层里没有 %s —— 写操作将全部关闭", c.OperatorRef)
	}
	return &c, pw, nil
}

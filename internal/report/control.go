package report

import (
	"encoding/json"
	"fmt"
	"os"
)

// ControlPath 是中控角色的本机配置。
//
// **它不是渲染产物**,和发布器的 unit、信任根、本机秘密层一样属于 bootstrap。
// 它引用的路径(git 工作副本、秘密层)是这台机器上的事实,不是平台约定 ——
// 写进 SSOT 会变成自我引用(SSOT 里记着 SSOT 在哪)。
const ControlPath = "/etc/loom/control.json"

// Control 让这台机器成为中控:多出改 SSOT 的能力。
//
// 只有一台机器该有它。写操作收敛到一处,是因为任何节点都能到任何节点的
// 隧道地址 —— 五个写入口意味着一台被拿下就能去动其他四台。
type Control struct {
	// Node 由 report 配置注入，不在 bootstrap JSON 里再维护一份。
	Node string `json:"-"`

	// SSOTPath 是发布器盯着的那个文件。界面改的就是它,改完存盘,
	// 发布器 30 秒内接管 —— 所以界面上**没有"发布"按钮**。
	SSOTPath string `json:"ssot_path"`

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
	// ClientRegistryPath points at the retained v1 identity history used only by
	// the read-only Device inventory projection. v2 mutations never write it.
	ClientRegistryPath string `json:"client_registry_path,omitempty"`
	// ClientLinuxPackagePath is the locally published, signed Linux bootstrap
	// archive exposed by the authenticated Clients page.
	ClientLinuxPackagePath string `json:"client_linux_package_path,omitempty"`
	// ClientPublicBaseURL is the deployment-owned HTTPS directory that exposes
	// only generic bootstrap artifacts and install.sh. It is never inferred from
	// an HTTP Host header and contains no invitation or Device configuration.
	ClientPublicBaseURL string `json:"client_public_base_url,omitempty"`

	// DistributionURL / DNS 用来回答"发布器跟上我这次改动了吗"。
	//
	// 看的是**分发点在提供哪个快照**,不是本机装了哪个 —— 后者会晚一整个
	// pull 周期,而改完之后最想知道的恰恰是"发出去了没有"。
	DistributionURL string `json:"distribution_url,omitempty"`
	DNS             string `json:"dns,omitempty"`
}

// LoadControl 读中控配置。文件不存在返回 (nil, nil) —— 绝大多数节点不是中控,
// 那不是错误。
func LoadControl(path string) (*Control, error) {
	b, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var c Control
	if err := json.Unmarshal(b, &c); err != nil {
		return nil, fmt.Errorf("解析 %s:%w", path, err)
	}
	if c.SSOTPath == "" {
		return nil, fmt.Errorf("%s 缺 ssot_path", path)
	}
	if c.BootstrapSSHKey == "" {
		c.BootstrapSSHKey = "/etc/loom/control-bootstrap"
	}
	if c.KnownHostsPath == "" {
		c.KnownHostsPath = "/etc/loom/control-known_hosts"
	}
	if c.ClientRegistryPath == "" {
		c.ClientRegistryPath = "/var/lib/loom/client-enrollment/registry.json"
	}
	if c.ClientLinuxPackagePath == "" {
		c.ClientLinuxPackagePath = "/var/lib/loom/client-dist/loom-client-linux-amd64.tar.gz"
	}
	if _, err := readSSOTSnapshot(c.SSOTPath); err != nil {
		return nil, fmt.Errorf("ssot_path 指向 %s,但读不到:%w", c.SSOTPath, err)
	}
	if c.ClientPublicBaseURL != "" {
		if _, err := validClientPublicBaseURL(c.ClientPublicBaseURL); err != nil {
			return &c, fmt.Errorf("%s client_public_base_url 无效:%w", path, err)
		}
	}

	return &c, nil
}

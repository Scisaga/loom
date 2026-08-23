package report

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"loom/internal/model"
	"loom/internal/netx"
	"loom/internal/validate"
	"loom/internal/webui"
)

// controlDeps 把中控配置接到界面上。
//
// 界面唯一能做的写操作是**改 SSOT**。发布是自动的 —— 发布器盯着同一个文件,
// 存盘之后 30 秒内接管(§14.2.3)。
func controlDeps(c *Control) *webui.ControlDeps {
	return &webui.ControlDeps{
		SSOTPath: c.SSOTPath,
		Read: func() (string, error) {
			b, err := os.ReadFile(c.SSOTPath)
			return string(b), err
		},
		Validate: func(content string) (string, error) {
			s, err := model.Load([]byte(content))
			if err != nil {
				return "", fmt.Errorf("解析失败:%w", err)
			}
			if fs := validate.Validate(s); len(fs) > 0 {
				return validate.Format(fs), nil
			}
			return "", nil
		},
		Save: func(content string) error {
			// **保存前自己再校验一次。** 界面上的校验按钮只是给人看的:
			// 表单可以被直接 POST,而一份坏 SSOT 存进去之后,发布器会拒绝
			// 发布,线上停在旧快照 —— 症状是"改了没生效",很难查。
			s, err := model.Load([]byte(content))
			if err != nil {
				return fmt.Errorf("解析失败,未保存:%w", err)
			}
			if fs := validate.Validate(s); len(fs) > 0 {
				return fmt.Errorf("校验不通过,未保存")
			}
			// 先写同目录的临时文件再改名:发布器可能正好在读,
			// 而半截 YAML 会让它报一个跟真实原因无关的解析错误。
			tmp := filepath.Join(filepath.Dir(c.SSOTPath), ".ssot.tmp")
			if err := os.WriteFile(tmp, []byte(content), 0o644); err != nil {
				return err
			}
			return os.Rename(tmp, c.SSOTPath)
		},
		Distributed: func() (string, error) {
			if c.DistributionURL == "" {
				return "", fmt.Errorf("中控配置里没有 distribution_url")
			}
			resp, err := netx.Client(c.DNS, 10*time.Second).
				Get(strings.TrimRight(c.DistributionURL, "/") + "/current.json")
			if err != nil {
				return "", err
			}
			defer resp.Body.Close()
			if resp.StatusCode != 200 {
				return "", fmt.Errorf("HTTP %d", resp.StatusCode)
			}
			var cur struct {
				Snapshot string `json:"snapshot"`
			}
			if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<16)).Decode(&cur); err != nil {
				return "", err
			}
			return cur.Snapshot, nil
		},
	}
}

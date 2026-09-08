package clientruntime

// WindowsHealthPlan 只描述已激活的本机运行面（§16.1），不生成业务探测目标。
type WindowsHealthPlan struct{ profile WindowsRuntimeProfile }

func BuildWindowsHealthPlan(body []byte, profile WindowsRuntimeProfile, caPath string) (*WindowsHealthPlan, error) {
	if err := ValidateWindowsRuntimeConfig(body, profile, caPath); err != nil {
		return nil, err
	}
	return &WindowsHealthPlan{profile: profile}, nil
}

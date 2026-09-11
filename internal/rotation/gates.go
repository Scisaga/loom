package rotation

// GateStatus 是机器可读的两道门禁。Windows 在另一开发机完成前，调用方只能
// 上报 false，因此 Gate A/Gate B 不会被本仓库代码自行越过（Issue #10）。
type GateStatus struct {
	Schema                 int  `json:"schema"`
	ServerOverlapGuard     bool `json:"server_overlap_guard"`
	LinuxV2Reader          bool `json:"linux_v2_reader"`
	WindowsV2Reader        bool `json:"windows_v2_reader"`
	AndroidV2Reader        bool `json:"android_v2_reader"`
	LinuxAcceptance        bool `json:"linux_acceptance"`
	WindowsAcceptance      bool `json:"windows_acceptance"`
	AndroidAcceptance      bool `json:"android_acceptance"`
	NoV1CallersEvidence    bool `json:"no_v1_callers_evidence"`
	RecoverableBackupProof bool `json:"recoverable_backup_proof"`
}

// ServerLinuxAndroidReady 是本仓库当前交付顺序的非破坏性里程碑：它允许服务端、
// Linux、Android 完成开发和各自验收，但绝不授权开始全端正式轮换或删除 v1。
// Windows 留在另一开发机，不会反向阻塞这三部分（Issue #10）。
func (g GateStatus) ServerLinuxAndroidReady() bool {
	return g.Schema == 1 && g.ServerOverlapGuard && g.LinuxV2Reader && g.AndroidV2Reader &&
		g.LinuxAcceptance && g.AndroidAcceptance
}

func (g GateStatus) GateA() bool {
	return g.Schema == 1 && g.ServerOverlapGuard && g.LinuxV2Reader && g.WindowsV2Reader && g.AndroidV2Reader
}

func (g GateStatus) GateB() bool {
	return g.GateA() && g.LinuxAcceptance && g.WindowsAcceptance && g.AndroidAcceptance && g.NoV1CallersEvidence && g.RecoverableBackupProof
}

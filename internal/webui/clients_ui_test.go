package webui

import (
	"testing"
	"time"
)

func clientUIDeps() Deps {
	d := misakaDeps()
	d.Control.Clients = &ClientControlDeps{
		EnrollmentOptions: func() (DeviceEnrollmentOptions, error) {
			return DeviceEnrollmentOptions{DestinationGrants: []DeviceDestinationOption{
				{ID: "best-egress", Name: "Best egress"}, {ID: "sg-fixed", Name: "Singapore"},
			}}, nil
		},
		List: func() (ClientInventory, error) {
			return ClientInventory{
				Clients: []ClientView{
					{ID: "client-linux01", Name: "Build server", Platform: "linux", Status: "provisioning", CreatedAt: "2026-08-31T09:00:00Z", EnrolledAt: "2026-08-31T09:02:00Z"},
					{ID: "client-phone01", Name: "Phone", Status: "pending", CreatedAt: "2026-08-31T10:00:00Z"},
				},
				ActiveInvites: 1,
			}, nil
		},
		CreateInvite: func(ClientInviteInput) (ClientInviteView, error) { return ClientInviteView{}, nil },
		LinuxPackage: func() (LinuxClientPackageView, error) {
			return LinuxClientPackageView{
				Filename:     "loom-client-linux-amd64.tar.gz",
				URL:          "/devices/download/linux-amd64",
				InstallerURL: "https://packages.example/install.sh",
				SHA256:       "0123456789abcdef",
				Version:      "v1.0.0",
				Arch:         "linux/amd64",
			}, nil
		},
	}
	return d
}

func TestWindowsAndroidAndLinuxRequireSignedPresence(t *testing.T) {
	now := time.Date(2026, 9, 14, 0, 0, 0, 0, time.UTC)
	inventory := ClientInventory{Clients: []ClientView{
		{ID: "demo-android", Platform: "android", Status: "ready"},
		{ID: "demo-linux", Platform: "linux-server", Status: "ready"},
		{ID: "demo-windows", Platform: "windows-desktop", Status: "ready"},
	}}
	view := View{Nodes: []NodeView{
		{ID: "demo-android", Declared: true, Health: "healthy", Source: "签名健康转述", ObservedAt: now.Add(-16 * time.Second).Format(time.RFC3339), PresenceAt: now.Add(-16 * time.Second).Format(time.RFC3339), AgeSec: 16},
		{ID: "demo-linux", Declared: true, Health: "healthy", Source: "签名健康转述", ObservedAt: now.Add(-16 * time.Second).Format(time.RFC3339), AgeSec: 16},
		{ID: "demo-windows", Declared: true, Health: "healthy", Source: "签名健康转述", ObservedAt: now.Add(-16 * time.Second).Format(time.RFC3339), AgeSec: 16},
	}}
	merged := mergeClientRuntime(inventory, view, now)
	if got := merged.Clients[0]; got.Status != "stale" || got.DataPlaneStatus != "stale" {
		t.Fatalf("Android 15-second presence lease did not expire: %+v", got)
	}
	if got := merged.Clients[1]; got.Status != "stale" || got.DataPlaneStatus != "stale" || got.PresenceStatus != "not yet reported" {
		t.Fatalf("Linux 在从未提交心跳时错误兼容了完整 Observation: %+v", got)
	}
	if got := merged.Clients[2]; got.Status != "stale" || got.DataPlaneStatus != "stale" || got.PresenceStatus != "not yet reported" {
		t.Fatalf("Windows 在从未提交心跳时错误沿用了完整 Observation lease: %+v", got)
	}
}

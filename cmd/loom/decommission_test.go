package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type fakeDecommissionSystemd struct {
	units map[string]*fakeDecommissionUnit
	fail  map[string]bool
	calls []string
}

type fakeDecommissionUnit struct {
	load, active, enabled string
}

func (f *fakeDecommissionSystemd) run(args ...string) (string, error) {
	op := args[0]
	unit := args[len(args)-1]
	f.calls = append(f.calls, strings.Join(args, "|"))
	u := f.units[unit]
	if u == nil {
		u = &fakeDecommissionUnit{load: "not-found", active: "inactive", enabled: "not-found"}
		f.units[unit] = u
	}
	if f.fail[op+"|"+unit] {
		return "injected", errors.New("injected")
	}
	switch op {
	case "show":
		return u.load, nil
	case "stop":
		u.active = "inactive"
		return "", nil
	case "is-active":
		return u.active, nil
	case "disable":
		u.enabled = "disabled"
		return "", nil
	case "is-enabled":
		return u.enabled, nil
	case "enable":
		u.enabled, u.active = "enabled", "active"
		return "", nil
	default:
		return "", errors.New("unexpected operation")
	}
}

func TestDecommissionDisablesRuntimeEnablementExplicitly(t *testing.T) {
	dir := t.TempDir()
	state := filepath.Join(dir, "applied")
	units := []string{"loom-agent", "loom-pull.timer"}
	fake := newFakeDecommissionSystemd(units)
	fake.units["loom-agent"].enabled = "enabled-runtime"
	if err := decommissionWith(state, units, fake.run); err != nil {
		t.Fatal(err)
	}
	foundRuntimeDisable := false
	for _, call := range fake.calls {
		if call == "disable|--runtime|loom-agent" {
			foundRuntimeDisable = true
		}
	}
	if !foundRuntimeDisable || fake.units["loom-agent"].enabled != "disabled" {
		t.Fatalf("enabled-runtime 没有显式收敛:found=%v state=%+v calls=%v",
			foundRuntimeDisable, fake.units["loom-agent"], fake.calls)
	}
}

func newFakeDecommissionSystemd(units []string) *fakeDecommissionSystemd {
	f := &fakeDecommissionSystemd{units: map[string]*fakeDecommissionUnit{}, fail: map[string]bool{}}
	for _, unit := range units {
		f.units[unit] = &fakeDecommissionUnit{load: "loaded", active: "active", enabled: "enabled"}
	}
	return f
}

func TestDecommissionKeepsPullTimerWhenEarlierUnitFails(t *testing.T) {
	dir := t.TempDir()
	state := filepath.Join(dir, "applied")
	if err := os.WriteFile(state, []byte("snapshot-old\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	units := []string{"loom-agent", "loom-report", "loom-pull.timer"}
	fake := newFakeDecommissionSystemd(units)
	fake.fail["stop|loom-report"] = true
	err := decommissionWith(state, units, fake.run)
	if err == nil {
		t.Fatal("任一 unit 停用失败不能宣称下线成功")
	}
	for _, call := range fake.calls {
		if strings.HasSuffix(call, "|loom-pull.timer") {
			t.Fatalf("前置 unit 失败后仍关闭了自修复 timer:%v", fake.calls)
		}
	}
	if _, err := os.Stat(filepath.Join(dir, "DECOMMISSIONED")); !os.IsNotExist(err) {
		t.Fatalf("失败时不应写下线标记:%v", err)
	}
	if got, err := os.ReadFile(state); err != nil || string(got) != "snapshot-old\n" {
		t.Fatalf("失败时 applied 不应失效:%q err=%v", got, err)
	}
}

func TestDecommissionConvergesAndVerifiesTimerLast(t *testing.T) {
	dir := t.TempDir()
	state := filepath.Join(dir, "applied")
	if err := os.WriteFile(state, []byte("snapshot-old\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	units := []string{"loom-agent", "missing.service", "loom-report", "loom-pull.timer"}
	fake := newFakeDecommissionSystemd([]string{"loom-agent", "loom-report", "loom-pull.timer"})
	if err := decommissionWith(state, units, fake.run); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(state); !os.IsNotExist(err) {
		t.Fatalf("成功下线后 applied 仍在:%v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "DECOMMISSIONED")); err != nil {
		t.Fatalf("成功下线没有落标记:%v", err)
	}
	firstTimer := -1
	for i, call := range fake.calls {
		if strings.HasSuffix(call, "|loom-pull.timer") {
			firstTimer = i
			break
		}
	}
	if firstTimer < 0 {
		t.Fatal("没有停 pull timer")
	}
	for i := firstTimer; i < len(fake.calls); i++ {
		if !strings.HasSuffix(fake.calls[i], "|loom-pull.timer") {
			t.Fatalf("pull timer 不是最后处理的 unit:%v", fake.calls)
		}
	}
	for _, unit := range []string{"loom-agent", "loom-report", "loom-pull.timer"} {
		u := fake.units[unit]
		if u.active != "inactive" || u.enabled != "disabled" {
			t.Errorf("%s 未收敛为 inactive/disabled:%+v", unit, u)
		}
	}
}

func TestDecommissionTimerFailureRestoresRetryCoordinates(t *testing.T) {
	dir := t.TempDir()
	state := filepath.Join(dir, "applied")
	if err := os.WriteFile(state, []byte("snapshot-old\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	units := []string{"loom-agent", "loom-pull.timer"}
	fake := newFakeDecommissionSystemd(units)
	fake.fail["stop|loom-pull.timer"] = true
	err := decommissionWith(state, units, fake.run)
	if err == nil {
		t.Fatal("timer 停用失败不能成功")
	}
	if _, err := os.Stat(filepath.Join(dir, "DECOMMISSIONED")); !os.IsNotExist(err) {
		t.Fatalf("timer 失败后 marker 未撤销:%v", err)
	}
	if got, err := os.ReadFile(state); err != nil || string(got) != "snapshot-old\n" {
		t.Fatalf("timer 失败后 applied 未恢复:%q err=%v", got, err)
	}
	u := fake.units["loom-pull.timer"]
	if u.active != "active" || u.enabled != "enabled" {
		t.Fatalf("timer 失败后没有恢复自修复入口:%+v calls=%v", u, fake.calls)
	}
}

func TestDecommissionUnitDiscoveryIsStableAndTimerLast(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"wg-z.conf", "wg-a.conf", "node.key", "readme"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	units, err := decommissionUnits(dir, nil, func(...string) (string, error) { return "", nil })
	if err != nil {
		t.Fatal(err)
	}
	got := strings.Join(units, " ")
	if !strings.Contains(got, "wg-quick@wg-a wg-quick@wg-z loom-pull.timer") {
		t.Fatalf("隧道未排序或 timer 不在最后:%s", got)
	}
}

func TestDecommissionDiscoveryUnionsInventoryAndSystemdOrphans(t *testing.T) {
	dir := t.TempDir() // 故意没有任何 .conf
	installed := []string{"/etc/wireguard/wg-inventory.conf"}
	ctl := func(args ...string) (string, error) {
		switch args[0] {
		case "list-units":
			return "wg-quick@wg-loaded.service loaded active running test", nil
		case "list-unit-files":
			return "wg-quick@wg-enabled.service enabled enabled", nil
		default:
			return "", errors.New("unexpected discovery call")
		}
	}
	units, err := decommissionUnits(dir, installed, ctl)
	if err != nil {
		t.Fatal(err)
	}
	got := " " + strings.Join(units, " ") + " "
	for _, want := range []string{
		" wg-quick@wg-enabled ", " wg-quick@wg-inventory ", " wg-quick@wg-loaded ",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("发现集合缺 %s: %s", want, got)
		}
	}
	if units[len(units)-1] != "loom-pull.timer" {
		t.Fatalf("pull.timer 不在最后:%v", units)
	}
}

func TestDecommissionDiscoveryFailureCannotCommitOrDisableTimer(t *testing.T) {
	dir := t.TempDir()
	state := filepath.Join(dir, "applied")
	if err := os.WriteFile(state, []byte("snapshot-old\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var calls []string
	ctl := func(args ...string) (string, error) {
		calls = append(calls, strings.Join(args, "|"))
		if args[0] == "list-units" {
			return "permission denied", errors.New("injected discovery failure")
		}
		return "", nil
	}
	if _, err := decommissionWithDiscovery(state, dir, nil, ctl); err == nil {
		t.Fatal("systemd 枚举失败不能继续下线")
	}
	if got, err := os.ReadFile(state); err != nil || string(got) != "snapshot-old\n" {
		t.Fatalf("发现失败后 applied 被动过:got=%q err=%v", got, err)
	}
	if _, err := os.Stat(filepath.Join(dir, "DECOMMISSIONED")); !os.IsNotExist(err) {
		t.Fatalf("发现失败后写了 Decommissioned marker:%v", err)
	}
	for _, call := range calls {
		if strings.HasSuffix(call, "|loom-pull.timer") {
			t.Fatalf("发现失败后仍触碰 pull.timer:%v", calls)
		}
	}
}

func TestDecommissionStopsSystemdOrphanWithoutConfigFile(t *testing.T) {
	dir := t.TempDir()
	state := filepath.Join(dir, "applied")
	if err := os.WriteFile(state, []byte("snapshot-old\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	orphan := "wg-quick@wg-orphan"
	fake := newFakeDecommissionSystemd([]string{orphan, "loom-pull.timer"})
	ctl := func(args ...string) (string, error) {
		switch args[0] {
		case "list-units":
			return orphan + ".service loaded active running test", nil
		case "list-unit-files":
			return orphan + ".service enabled enabled", nil
		default:
			return fake.run(args...)
		}
	}
	units, err := decommissionWithDiscovery(state, dir, nil, ctl)
	if err != nil {
		t.Fatal(err)
	}
	if fake.units[orphan].active != "inactive" || fake.units[orphan].enabled != "disabled" {
		t.Fatalf("无配置文件的 systemd orphan 未收敛:%+v calls=%v units=%v",
			fake.units[orphan], fake.calls, units)
	}
	if _, err := os.Stat(filepath.Join(dir, "DECOMMISSIONED")); err != nil {
		t.Fatalf("完整停掉 orphan 后没有提交下线:%v", err)
	}
}

func TestConvergeUnitOffDoesNotTrustNotFoundLoadState(t *testing.T) {
	unit := "wg-quick@wg-orphan"
	fake := newFakeDecommissionSystemd([]string{unit})
	fake.units[unit].load = "not-found"
	fake.units[unit].active = "active"
	fake.units[unit].enabled = "enabled"

	if err := convergeUnitOff(unit, fake.run); err != nil {
		t.Fatal(err)
	}
	if fake.units[unit].active != "inactive" || fake.units[unit].enabled != "disabled" {
		t.Fatalf("LoadState=not-found 的 active/enabled 残留未收敛:%+v calls=%v",
			fake.units[unit], fake.calls)
	}
	for _, want := range []string{"stop|" + unit, "disable|" + unit} {
		found := false
		for _, call := range fake.calls {
			if call == want {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("缺少 %s，调用=%v", want, fake.calls)
		}
	}
}

func TestConvergeUnitOffFailsClosedWhenResidualStateIsUnknown(t *testing.T) {
	for _, tc := range []struct {
		name    string
		active  string
		enabled string
	}{
		{name: "active", active: "unknown", enabled: "disabled"},
		{name: "enabled", active: "inactive", enabled: "mystery"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			unit := "wg-quick@wg-unknown"
			fake := newFakeDecommissionSystemd([]string{unit})
			fake.units[unit].load = "not-found"
			fake.units[unit].active = tc.active
			fake.units[unit].enabled = tc.enabled
			if err := convergeUnitOff(unit, fake.run); err == nil {
				t.Fatalf("未知 %s 状态不能当作已经下线:calls=%v", tc.name, fake.calls)
			}
		})
	}
}

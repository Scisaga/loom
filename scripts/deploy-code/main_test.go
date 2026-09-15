//go:build !windows

package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"loom/internal/publish"
	"loom/internal/snapshot"
	"loom/internal/version"
)

func TestDotenvDoesNotExecuteOrExportOtherCredentials(t *testing.T) {
	values, err := parseEnv(strings.NewReader("# demo\nexport LOOM_DEPLOY_HOSTS='demo-control demo-server'\nGANDI_PAT_TOKEN=$(touch demo-never-executed)\nLOOM_PUBLISH_OUTPUTS='[\"deploy/distribution\"]'\n"))
	if err != nil {
		t.Fatal(err)
	}
	if values["LOOM_DEPLOY_HOSTS"] != "demo-control demo-server" || len(values) != 2 {
		t.Fatalf("解析未限制到发布参数：%v", values)
	}
	for _, input := range []string{
		"LOOM_DEPLOY_HOSTS=demo-control\nLOOM_DEPLOY_HOSTS=demo-server",
		"LOOM_DEPLOY_HOSTS=$(touch demo-file)",
		"LOOM_DEPLOY_HOSTS=`touch demo-file`",
		"LOOM_DEPLOY_HOSTS=$DEPLOY_NODES",
		"LOOM_DEPLOY_HOSTS='demo-control",
		"LOOM_DEPLOY_HOTS=demo-control",
		"source demo-file",
	} {
		if _, err := parseEnv(strings.NewReader(input)); err == nil {
			t.Errorf("未拒绝不安全或含糊赋值：%s", input)
		}
	}
}

func fixtureConfig(t *testing.T) config {
	t.Helper()
	root := t.TempDir()
	write := func(name, body string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(root, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write(".env", "LOOM_DEPLOY_HOSTS='demo-control demo-server'\nLOOM_LOCAL_NODE=demo-control\nLOOM_DEPLOY_SOURCE=ssot.yaml\nLOOM_PUBLISH_OUTPUTS='[\"distribution\"]'\n")
	write(".ssh_config", "Host demo-server\n    HostName example.invalid\nHost *\n    BatchMode yes\n")
	write("ssot.yaml", "nodes:\n  - id: demo-control\n    server: {}\n  - id: demo-server\n    server: {}\n  - id: demo-retired\n    server: {}\n    decommission: true\n  - id: demo-phone\n    access:\n      platform: android\n")
	c, err := loadConfig(filepath.Join(root, ".env"))
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestInventoryMustCoverEveryCurrentLinuxNode(t *testing.T) {
	c := fixtureConfig(t)
	if err := validateInventory(c); err != nil {
		t.Fatal(err)
	}
	// §14.2：本机就地安装无需 SSH Host；取消本机声明后，同一清单必须拒绝。
	remoteOnly := c
	remoteOnly.local = ""
	if err := validateInventory(remoteOnly); err == nil {
		t.Fatal("未声明为本机且缺少 SSH Host 的节点仍被接受")
	}
	for _, hosts := range [][]string{
		{"demo-control"}, {"demo-control", "demo-control"}, {"demo-control", "demo-retired"},
		{"demo-control", "demo-unknown"}, {"demo-control", "-oProxyCommand=demo-command"},
	} {
		broken := c
		broken.hosts = hosts
		if err := validateInventory(broken); err == nil {
			t.Errorf("未拒绝节点清单：%v", hosts)
		}
	}
	c.local = "demo-unknown"
	if err := validateInventory(c); err == nil {
		t.Fatal("未拒绝未知本机别名")
	}
	c.local = ""
	if err := os.WriteFile(c.sshConfig, []byte("Host *\n  HostName example.invalid\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := validateInventory(c); err == nil {
		t.Fatal("通配 SSH Host 不能替代明确节点别名")
	}
}

func TestDistributionConfigurationRejectsEmptyDuplicateAndRemoteOnly(t *testing.T) {
	for _, value := range []string{`[]`, `[""]`, `["distribution","./distribution"]`, `["ssh://demo-server/var/lib/demo-distribution"]`} {
		root := t.TempDir()
		path := filepath.Join(root, ".env")
		if err := os.WriteFile(path, []byte("LOOM_PUBLISH_OUTPUTS='"+value+"'\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := loadConfig(path); err == nil {
			t.Errorf("未拒绝分发目录：%s", value)
		}
	}
}

func TestCoordinateRequiresExactCleanCommit(t *testing.T) {
	commit := strings.Repeat("a", 40)
	good := version.Coordinate{Commit: commit, Platform: "linux/" + runtime.GOARCH}
	if err := validateCoordinate(good, commit); err != nil {
		t.Fatal(err)
	}
	for _, coordinate := range []version.Coordinate{
		{Commit: commit, Dirty: true, Platform: good.Platform},
		{Commit: strings.Repeat("b", 40), Platform: good.Platform},
		{Commit: commit, Platform: "windows/amd64"},
	} {
		if err := validateCoordinate(coordinate, commit); err == nil {
			t.Errorf("未拒绝制品：%+v", coordinate)
		}
	}
}

func TestAuthorizationStopsOnFailureAndPublishesOnlyOnce(t *testing.T) {
	c := fixtureConfig(t)
	for _, fail := range []string{"release", "publish", ""} {
		var calls []string
		command := func(_ context.Context, _ string, args []string, _ string) (string, error) {
			calls = append(calls, args[0])
			if args[0] == fail {
				return "", errors.New("demo-failure")
			}
			return "", nil
		}
		err := authorize(c, "/demo-artifact", "demo-reason", command)
		if (err != nil) != (fail != "") {
			t.Fatalf("授权失败未传播：%v", err)
		}
		want := []string{"release", "publish"}
		if fail == "release" {
			want = want[:1]
		}
		if !reflect.DeepEqual(calls, want) {
			t.Fatalf("错误发布顺序：%v", calls)
		}
	}
}

func candidateFromBytes(body []byte) publish.BinaryCandidate {
	sum := sha256.Sum256(body)
	return publish.BinaryCandidate{Body: body, SHA256: hex.EncodeToString(sum[:]), Size: len(body)}
}

func signedDistribution(t *testing.T) (string, publish.BinaryCandidate, ed25519.PublicKey) {
	t.Helper()
	root := t.TempDir()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	candidate := candidateFromBytes([]byte("demo-artifact"))
	current := &publish.DeploymentCurrent{Schema: 1, Generation: 1, Snapshot: "aaaaaaaaaaaa", PublishedAt: "2026-01-01T00:00:00Z"}
	if err := current.Sign(priv); err != nil {
		t.Fatal(err)
	}
	manifest := &snapshot.Manifest{ID: current.Snapshot,
		Bundles:  []snapshot.BundleRef{{Owner: "demo-control"}, {Owner: "demo-server"}},
		Binaries: []snapshot.BinaryRef{{OS: "linux", Arch: runtime.GOARCH, SHA256: candidate.SHA256, Size: candidate.Size}},
	}
	body, err := manifest.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	sig, err := snapshot.Sign(manifest, priv)
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := json.Marshal(current)
	if err != nil {
		t.Fatal(err)
	}
	for path, body := range map[string][]byte{
		"current.json": envelope, current.Snapshot + "/snapshot.json": body,
		current.Snapshot + "/snapshot.sig": sig, "bin/" + candidate.SHA256: candidate.Body,
	} {
		path = filepath.Join(root, path)
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, body, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return root, candidate, pub
}

func TestSignedDistributionBindsCandidateAndEveryNode(t *testing.T) {
	root, candidate, pub := signedDistribution(t)
	hosts := []string{"demo-control", "demo-server"}
	if err := verifyDistribution(root, hosts, candidate, pub); err != nil {
		t.Fatal(err)
	}
	if err := verifyDistribution(root, hosts, candidateFromBytes([]byte("demo-new-artifact")), pub); err == nil {
		t.Fatal("已签名旧制品不能授权新制品直发")
	}
	if err := verifyDistribution(root, []string{"demo-unknown"}, candidate, pub); err == nil {
		t.Fatal("缺少节点配置不能直发")
	}
	for _, path := range []string{"current.json", "aaaaaaaaaaaa/snapshot.json", "aaaaaaaaaaaa/snapshot.sig", "bin/" + candidate.SHA256} {
		t.Run(path, func(t *testing.T) {
			root, candidate, pub := signedDistribution(t)
			if err := os.WriteFile(filepath.Join(root, path), []byte("demo-corruption"), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := verifyDistribution(root, hosts, candidate, pub); err == nil {
				t.Fatal("损坏发布记录仍被接受")
			}
		})
	}
}

func TestActivationCopiesSameArtifactConcurrentlyWithoutProbes(t *testing.T) {
	c := fixtureConfig(t)
	var mu sync.Mutex
	var copies, activations int
	barrier := make(chan struct{})
	command := func(ctx context.Context, name string, args []string, input string) (string, error) {
		mu.Lock()
		if name == "scp" || name == "install" {
			copies++
			if copies == len(c.hosts) {
				close(barrier)
			}
			if !strings.Contains(strings.Join(args, " "), "/demo-stable-artifact") || !strings.Contains(args[len(args)-1], "/usr/local/bin/.loom-") {
				t.Error("复制未使用相同稳定制品与同目录临时文件")
			}
			mu.Unlock()
			select {
			case <-barrier:
			case <-ctx.Done():
				return "", ctx.Err()
			case <-time.After(time.Second):
				return "", errors.New("复制没有并发")
			}
			return "", nil
		}
		defer mu.Unlock()
		if name != "ssh" && name != "bash" {
			t.Errorf("额外命令：%s", name)
		}
		activations++
		if input == "" || !strings.Contains(input, "sha256sum -c -") || strings.Contains(input, "systemctl start") || strings.Contains(input, "sleep") {
			t.Error("激活漏校验或包含额外启动/等待")
		}
		return "demo-activated\n", nil
	}
	var output bytes.Buffer
	if err := activateAll(c, "/demo-stable-artifact", strings.Repeat("a", 64), command, &output); err != nil {
		t.Fatal(err)
	}
	if copies != len(c.hosts) || activations != len(c.hosts) {
		t.Fatalf("额外连接或遗漏节点：copies=%d activations=%d", copies, activations)
	}
}

func TestActivationFailureNamesNodeAndDoesNotActivateFailedCopy(t *testing.T) {
	c := fixtureConfig(t)
	command := func(_ context.Context, name string, _ []string, input string) (string, error) {
		if name == "scp" {
			return "", errors.New("demo-copy-failure")
		}
		if name == "ssh" {
			t.Error("复制失败后仍连接激活")
		}
		return "", nil
	}
	var output bytes.Buffer
	err := activateAll(c, "/demo-stable-artifact", strings.Repeat("a", 64), command, &output)
	if err == nil || !strings.Contains(err.Error(), "demo-server") || !strings.Contains(output.String(), "demo-server: 失败") {
		t.Fatalf("失败未立即归属到节点：%v\n%s", err, output.String())
	}
}

func TestActivationShellChecksHashAndOnlyRestartsRunningDaemons(t *testing.T) {
	for _, mode := range []string{"success", "bad-hash", "list-failure"} {
		t.Run(mode, func(t *testing.T) {
			root := t.TempDir()
			candidatePath, trace := filepath.Join(root, "candidate"), filepath.Join(root, "trace")
			candidate := candidateFromBytes([]byte("demo-artifact"))
			if err := os.WriteFile(candidatePath, candidate.Body, 0o600); err != nil {
				t.Fatal(err)
			}
			// §14.2：仅 systemctl 与安装目标移动由替身接收；SHA-256 校验运行真实工具。
			for name, body := range map[string]string{
				"systemctl": `#!/bin/sh
case "$1" in
  list-units)
    [ "$DEMO_MODE" != list-failure ] || exit 1
    printf '%s\n' 'loom-report.service loaded active running' 'loom-pull.service loaded active running' 'loom-demo-once.service loaded active running'
    ;;
  show)
    case "$4" in loom-demo-once.service) echo oneshot ;; *) echo simple ;; esac
    ;;
  restart) printf '%s\n' "$*" >> "$DEMO_TRACE" ;;
  *) exit 2 ;;
esac
`,
				"mv": "#!/bin/sh\nprintf '%s\\n' moved >> \"$DEMO_TRACE\"\n",
			} {
				if err := os.WriteFile(filepath.Join(root, name), []byte(body), 0o700); err != nil {
					t.Fatal(err)
				}
			}
			hash := candidate.SHA256
			if mode == "bad-hash" {
				hash = strings.Repeat("a", 64)
			}
			cmd := exec.Command("bash", "-s")
			cmd.Env = []string{"PATH=" + root + ":/usr/bin:/bin", "DEMO_TRACE=" + trace, "DEMO_MODE=" + mode}
			cmd.Stdin = strings.NewReader(activationScript(candidatePath, hash))
			output, err := cmd.CombinedOutput()
			if (err != nil) != (mode != "success") {
				t.Fatalf("激活结果错误：%v\n%s", err, output)
			}
			body, readErr := os.ReadFile(trace)
			if mode == "success" {
				if readErr != nil || string(body) != "moved\nrestart loom-report.service\n" {
					t.Fatalf("激活触及不应重启的服务：%v %s", readErr, body)
				}
			} else if !os.IsNotExist(readErr) {
				t.Fatalf("校验或服务列表失败后仍执行替换：%v %s", readErr, body)
			}
		})
	}
}

func TestPlanOnlyReadsLocalMetadata(t *testing.T) {
	c := fixtureConfig(t)
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(c.signingKey), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(c.signingKey, []byte(base64.StdEncoding.EncodeToString(priv)), 0o600); err != nil {
		t.Fatal(err)
	}
	binary := filepath.Join(c.root, "demo-artifact")
	if err := os.WriteFile(binary, []byte("demo-candidate"), 0o700); err != nil {
		t.Fatal(err)
	}
	envPath := filepath.Join(c.root, ".env")
	f, err := os.OpenFile(envPath, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString("LOOM_DEPLOY_COMMAND=" + binary + "\n"); err != nil {
		t.Fatal(err)
	}
	f.Close()
	commit := strings.Repeat("a", 40)
	calls := 0
	makeRunner := func(root string) runner {
		if root != c.root {
			t.Fatal("元数据查询不在指定源码目录")
		}
		return func(_ context.Context, name string, args []string, input string) (string, error) {
			calls++
			if name != "git" || !reflect.DeepEqual(args, []string{"cat-file", "-e", commit + "^{commit}"}) || input != "" {
				t.Fatalf("plan 执行了非本地元数据命令：%s %v", name, args)
			}
			return "", nil
		}
	}
	inspect := func(candidate publish.BinaryCandidate) (version.Coordinate, error) {
		if string(candidate.Body) != "demo-candidate" {
			t.Fatal("plan 未读取指定候选字节")
		}
		return version.Coordinate{Commit: commit, Platform: "linux/" + runtime.GOARCH}, nil
	}
	var output bytes.Buffer
	err = runWith([]string{"--env", envPath, "--binary", binary, "--commit", commit, "--reason", "demo-reason", "--plan"}, &output, makeRunner, inspect)
	if err != nil {
		t.Fatal(err)
	}
	if calls != 1 || !strings.Contains(output.String(), `"mode":"plan"`) {
		t.Fatalf("plan 结果错误：calls=%d %s", calls, output.String())
	}
	for _, path := range []string{c.releaseDir, c.pinDir, c.history, c.outputs[0]} {
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Fatalf("plan 创建了发布状态：%s %v", path, err)
		}
	}
}

func TestCommandRunnerDisablesLazyFetchAndOmitsCredentials(t *testing.T) {
	root := t.TempDir()
	git := filepath.Join(root, "git")
	body := "#!/bin/sh\n[ \"$GIT_NO_LAZY_FETCH\" = 1 ] || exit 1\n[ \"${GANDI_PAT_TOKEN+x}\" != x ] || exit 2\n[ \"${LOOM_DEPLOY_SECRET+x}\" != x ] || exit 3\n"
	if err := os.WriteFile(git, []byte(body), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GANDI_PAT_TOKEN", "demo-token")
	t.Setenv("LOOM_DEPLOY_SECRET", "demo-secret")
	if _, err := commandRunner(root)(context.Background(), git, []string{"cat-file", "-e", "demo-commit"}, ""); err != nil {
		t.Fatal(err)
	}
}

func TestActivationKeepsExistingPublishLockUntilAllCommandsReturn(t *testing.T) {
	c := fixtureConfig(t)
	lockPath := filepath.Join(t.TempDir(), "publisher.lock")
	command := func(_ context.Context, _ string, _ []string, _ string) (string, error) {
		if unlock, err := publish.AcquireLock(lockPath); err == nil {
			unlock()
			t.Error("激活命令执行期间其他发布事务可以取得锁")
		}
		return "", nil
	}
	var output bytes.Buffer
	if err := withActivationLock(lockPath, func() error {
		return activateAll(c, "/demo-stable-artifact", strings.Repeat("a", 64), command, &output)
	}); err != nil {
		t.Fatal(err)
	}
	unlock, err := publish.AcquireLock(lockPath)
	if err != nil {
		t.Fatalf("激活后未释放事务锁：%v", err)
	}
	defer unlock()
	called := false
	if err := withActivationLock(lockPath, func() error { called = true; return nil }); err == nil || called {
		t.Fatal("已有发布事务持锁时仍开始激活")
	}
}

func TestAuthorizationChangedBeforeActivationIsRejectedUnderLock(t *testing.T) {
	for _, changed := range []string{"distribution", "pin"} {
		t.Run(changed, func(t *testing.T) {
			root, candidate, pub := signedDistribution(t)
			pinDir, lockPath := filepath.Join(root, "pinned"), filepath.Join(root, "publisher.lock")
			if err := verifyDistribution(root, []string{"demo-control"}, candidate, pub); err != nil {
				t.Fatal(err)
			}
			// §15.4：模拟 publish 返回后、激活重新获取锁前完成的另一笔事务。
			if changed == "distribution" {
				if err := os.WriteFile(filepath.Join(root, "current.json"), []byte("demo-changed-current"), 0o600); err != nil {
					t.Fatal(err)
				}
			} else if err := publish.WritePin(pinDir, &publish.Pin{Snapshot: "bbbbbbbbbbbb", Reason: "demo-pin"}, []byte("demo-pinned-artifact")); err != nil {
				t.Fatal(err)
			}
			activated := false
			err := withActivationLock(lockPath, func() error {
				if err := verifyPin(pinDir, candidate.SHA256); err != nil {
					return err
				}
				if err := verifyDistribution(root, []string{"demo-control"}, candidate, pub); err != nil {
					return err
				}
				activated = true
				return nil
			})
			if err == nil || activated {
				t.Fatal("授权在间隙改变后仍激活旧候选")
			}
			unlock, err := publish.AcquireLock(lockPath)
			if err != nil {
				t.Fatal("验证失败后未释放事务锁")
			}
			unlock()
		})
	}
}

package clientdist

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestBuildIsReproducibleAndVerifiable(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux client artifact fixture runs on the Linux development gate")
	}
	for _, architecture := range []string{"amd64", "arm64"} {
		t.Run(architecture, func(t *testing.T) {
			loom, singBox := buildClientFixturesForArch(t, architecture)
			seed := bytes.Repeat([]byte{0x42}, ed25519.SeedSize)
			privateKey := ed25519.NewKeyFromSeed(seed)
			in := fixtureBuildInput(loom, singBox, privateKey)
			one, err := Build(in)
			if err != nil {
				t.Fatal(err)
			}
			two, err := Build(in)
			if err != nil {
				t.Fatal(err)
			}
			if one.Name != "loom-client-linux-"+architecture+".tar.gz" || !bytes.Equal(one.Archive, two.Archive) ||
				!bytes.Equal(one.Checksum, two.Checksum) || !bytes.Equal(one.Signature, two.Signature) {
				t.Fatal("same inputs did not produce identical client artifacts")
			}
			manifest, err := Verify(one.Archive, one.Checksum, one.Signature, privateKey.Public().(ed25519.PublicKey))
			if err != nil {
				t.Fatal(err)
			}
			if manifest.Arch != architecture || manifest.Lifecycle != "signed-node-bundle" || manifest.SingBox.Version != "v1.11.4" {
				t.Fatalf("unexpected manifest: %+v", manifest)
			}
			for _, name := range []string{"licenses/LOOM-LICENSE", "licenses/LOOM-NOTICE",
				"licenses/SING-BOX-LICENSE", "licenses/THIRD-PARTY-NOTICES.md", "uninstall.sh"} {
				found := false
				for _, file := range manifest.Files {
					found = found || file.Path == name
				}
				if !found {
					t.Fatalf("manifest 缺许可证/生命周期文件 %s", name)
				}
			}
			dir := t.TempDir()
			archivePath := filepath.Join(dir, one.Name)
			writeTestBytes(t, archivePath, one.Archive)
			writeTestBytes(t, archivePath+".sha256", one.Checksum)
			writeTestBytes(t, archivePath+".sig", one.Signature)
			pubPath := filepath.Join(dir, "trusted.pub")
			writeTestBytes(t, pubPath, append([]byte(base64.StdEncoding.EncodeToString(privateKey.Public().(ed25519.PublicKey))), '\n'))
			published, err := VerifyFiles(archivePath, pubPath)
			if err != nil || published.SHA256 == "" || published.Size != int64(len(one.Archive)) || !bytes.Equal(published.Archive, one.Archive) {
				t.Fatalf("VerifyFiles err=%v sha=%q size=%d bytes_match=%v", err, published.SHA256, published.Size, bytes.Equal(published.Archive, one.Archive))
			}
		})
	}
}

func TestLinuxInstallerUsesOnlyPrivateEnrollment(t *testing.T) {
	for _, expected := range []string{
		"--invite-v2-file", "client enroll -invite-file", "--resume-v2-file", "client resume-v2",
		"--secret-envelope-dir", "--invite-file", "client enroll",
	} {
		if !strings.Contains(installScript, expected) {
			t.Fatalf("install script 缺少 %q", expected)
		}
	}
	if strings.Contains(installScript, "eval ") {
		t.Fatal("install script 不得用 eval 重建含私有路径的参数")
	}
	for _, expected := range []string{
		"rollback_install", "install_owned", "loom selfcheck", "sing-box\" version", "sync -f",
	} {
		if !strings.Contains(installScript, expected) {
			t.Fatalf("install script 缺原子升级/回滚步骤 %q", expected)
		}
	}
	for name, script := range map[string]string{"install.sh": installScript, "uninstall.sh": uninstallScript} {
		command := exec.Command("/bin/sh", "-n")
		command.Stdin = strings.NewReader(script)
		if output, err := command.CombinedOutput(); err != nil {
			t.Fatalf("%s shell syntax: %v: %s", name, err, output)
		}
	}
	for _, expected := range []string{
		"client uninstall-v2-runtime", "-apply", "cmp -s", "Device identity/LKG/floors",
	} {
		if !strings.Contains(uninstallScript, expected) {
			t.Fatalf("uninstall script 缺少 %q", expected)
		}
	}
	for _, forbidden := range []string{
		"/var/lib/loom/client-v2/state.json", "/var/lib/loom/client-v2/identity.json",
		"rm -rf /var/lib/loom/client-v2", "rm -f /usr/local/bin/loom", "rm -f /usr/local/bin/sing-box",
	} {
		if strings.Contains(uninstallScript, forbidden) {
			t.Fatalf("Gate B 前 uninstall script 不得删除 identity/LKG/shared runtime: %q", forbidden)
		}
	}
}

func TestLinuxInstallerRollsBackPartialBinaryTransaction(t *testing.T) {
	if os.Getenv("LOOM_INSTALLER_NAMESPACE_TEST") != "1" {
		t.Skip("由 Linux v2 development gate 在隔离 mount namespace 中执行")
	}
	if runtime.GOOS != "linux" || runtime.GOARCH != "amd64" {
		t.Skip("当前 namespace fixture 只在 linux/amd64 builder 执行")
	}
	if _, err := exec.LookPath("bwrap"); err != nil {
		t.Fatal("Linux installer transaction test requires bwrap")
	}
	loom, singBox := buildClientFixtures(t)
	root := t.TempDir()
	packageDirectory := filepath.Join(root, "package")
	usrBin := filepath.Join(root, "usr-local-bin")
	etcLoom := filepath.Join(root, "etc-loom")
	varLoom := filepath.Join(root, "var-lib-loom")
	for _, directory := range []string{packageDirectory, usrBin, etcLoom, varLoom} {
		if err := os.MkdirAll(directory, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	files := map[string][]byte{
		"install.sh": []byte(installScript), "loom": loom, "sing-box": singBox,
		"platform.pub": []byte("namespace-test-platform-key\n"),
	}
	var checksums strings.Builder
	for _, name := range []string{"install.sh", "loom", "platform.pub", "sing-box"} {
		body := files[name]
		writeTestBytes(t, filepath.Join(packageDirectory, name), body)
		if name == "install.sh" || name == "loom" || name == "sing-box" {
			if err := os.Chmod(filepath.Join(packageDirectory, name), 0o755); err != nil {
				t.Fatal(err)
			}
		}
		checksums.WriteString(sha256Hex(body) + "  " + name + "\n")
	}
	writeTestFile(t, filepath.Join(packageDirectory, "checksums.txt"), checksums.String())

	previousLoom := []byte("previous-v1-compatible-loom\n")
	writeTestBytes(t, filepath.Join(usrBin, "loom"), []byte("interrupted-partial-install\n"))
	if err := os.Chmod(filepath.Join(usrBin, "loom"), 0o755); err != nil {
		t.Fatal(err)
	}
	interrupted := filepath.Join(varLoom, ".loom-client-install.interrupted")
	if err := os.Mkdir(interrupted, 0o700); err != nil {
		t.Fatal(err)
	}
	writeTestBytes(t, filepath.Join(interrupted, "loom"), previousLoom)
	writeTestFile(t, filepath.Join(interrupted, "manifest"), "/usr/local/bin/loom|loom|0755\n")
	// 第二个 package target 故意是目录：loom 已换入后才失败，必须触发
	// 上一轮中断恢复及本轮 transaction rollback，而不是只证明预检提前失败。
	if err := os.Mkdir(filepath.Join(usrBin, "sing-box"), 0o755); err != nil {
		t.Fatal(err)
	}
	command := exec.Command("bwrap", "--die-with-parent", "--unshare-all", "--uid", "0", "--gid", "0",
		"--ro-bind", "/", "/", "--proc", "/proc", "--dev", "/dev",
		"--bind", usrBin, "/usr/local/bin", "--bind", etcLoom, "/etc/loom",
		"--bind", varLoom, "/var/lib/loom", "--ro-bind", packageDirectory, "/mnt",
		"/bin/sh", "/mnt/install.sh", "--no-enroll")
	if output, err := command.CombinedOutput(); err == nil {
		t.Fatalf("unsafe target 未让 installer 失败:\n%s", output)
	} else {
		t.Logf("installer 按预期失败: %v: %s", err, output)
		if !bytes.Contains(output, []byte("unsafe installed package target: /usr/local/bin/sing-box")) {
			t.Fatalf("installer 未运行到预期 transaction fault: %v: %s", err, output)
		}
	}
	restored, err := os.ReadFile(filepath.Join(usrBin, "loom"))
	if err != nil || !bytes.Equal(restored, previousLoom) {
		t.Fatalf("partial install 未恢复旧 Loom: err=%v body=%q", err, restored)
	}
	entries, err := os.ReadDir(varLoom)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".loom-client-install.") {
			t.Fatalf("失败回滚遗留 transaction directory: %s", entry.Name())
		}
	}
}

func TestLinuxInstallerCommitsVerifiedPackageInMountNamespace(t *testing.T) {
	if os.Getenv("LOOM_INSTALLER_NAMESPACE_TEST") != "1" {
		t.Skip("由 Linux v2 development gate 在隔离 mount namespace 中执行")
	}
	if runtime.GOOS != "linux" || runtime.GOARCH != "amd64" {
		t.Skip("当前 namespace fixture 只在 linux/amd64 builder 执行")
	}
	loom, singBox := buildClientFixtures(t)
	root := t.TempDir()
	packageDirectory := filepath.Join(root, "package")
	usrBin := filepath.Join(root, "usr-local-bin")
	etcLoom := filepath.Join(root, "etc-loom")
	varLoom := filepath.Join(root, "var-lib-loom")
	for _, directory := range []string{packageDirectory, usrBin, etcLoom, varLoom} {
		if err := os.MkdirAll(directory, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	files := map[string][]byte{
		"install.sh": []byte(installScript), "loom": loom, "sing-box": singBox,
		"platform.pub": []byte("namespace-test-platform-key\n"),
	}
	var checksums strings.Builder
	for _, name := range []string{"install.sh", "loom", "platform.pub", "sing-box"} {
		body := files[name]
		writeTestBytes(t, filepath.Join(packageDirectory, name), body)
		if name == "install.sh" || name == "loom" || name == "sing-box" {
			if err := os.Chmod(filepath.Join(packageDirectory, name), 0o755); err != nil {
				t.Fatal(err)
			}
		}
		checksums.WriteString(sha256Hex(body) + "  " + name + "\n")
	}
	writeTestFile(t, filepath.Join(packageDirectory, "checksums.txt"), checksums.String())

	command := exec.Command("bwrap", "--die-with-parent", "--unshare-all", "--uid", "0", "--gid", "0",
		"--ro-bind", "/", "/", "--proc", "/proc", "--dev", "/dev",
		"--bind", usrBin, "/usr/local/bin", "--bind", etcLoom, "/etc/loom",
		"--bind", varLoom, "/var/lib/loom", "--ro-bind", packageDirectory, "/mnt",
		"/bin/sh", "/mnt/install.sh", "--no-enroll")
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("transactional package install failed: %v: %s", err, output)
	}
	for relative, want := range map[string][]byte{
		filepath.Join(usrBin, "loom"):                   loom,
		filepath.Join(usrBin, "sing-box"):               singBox,
		filepath.Join(etcLoom, "trust", "platform.pub"): files["platform.pub"],
	} {
		got, err := os.ReadFile(relative)
		if err != nil || !bytes.Equal(got, want) {
			t.Fatalf("installed package file mismatch %s: err=%v", relative, err)
		}
	}
	if _, err := os.Stat(filepath.Join(etcLoom, "client")); !os.IsNotExist(err) {
		t.Fatalf("v2/no-enroll install 不应创建 v1 identity directory: %v", err)
	}
	stateInfo, err := os.Stat(filepath.Join(varLoom, "client-v2"))
	if err != nil || stateInfo.Mode().Perm() != 0o700 {
		t.Fatalf("v2 state directory mode 无效: info=%v err=%v", stateInfo, err)
	}
	entries, err := os.ReadDir(varLoom)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".loom-client-install.") {
			t.Fatalf("成功安装遗留 transaction directory: %s", entry.Name())
		}
	}
}

func TestReadRegularBoundedRejectsLinks(t *testing.T) {
	dir := t.TempDir()
	original := filepath.Join(dir, "original")
	writeTestBytes(t, original, []byte("signed bytes"))

	symlink := filepath.Join(dir, "symlink")
	if err := os.Symlink(original, symlink); err != nil {
		t.Fatal(err)
	}
	if _, err := readRegularBounded(symlink, 1024); err == nil {
		t.Fatal("符号链接被当成已发布制品读取")
	}

	hardlink := filepath.Join(dir, "hardlink")
	if err := os.Link(original, hardlink); err != nil {
		t.Fatal(err)
	}
	if _, err := readRegularBounded(hardlink, 1024); err == nil {
		t.Fatal("硬链接被当成已发布制品读取")
	}
}

func TestVerifyRejectsTamperAndWrongTrustRoot(t *testing.T) {
	if runtime.GOOS != "linux" || runtime.GOARCH != "amd64" {
		t.Skip("fixture builder currently exercises the production linux/amd64 package")
	}
	loom, singBox := buildClientFixtures(t)
	privateKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x11}, ed25519.SeedSize))
	artifact, err := Build(fixtureBuildInput(loom, singBox, privateKey))
	if err != nil {
		t.Fatal(err)
	}
	tampered := append([]byte(nil), artifact.Archive...)
	tampered[len(tampered)/2] ^= 1
	if _, err := Verify(tampered, artifact.Checksum, artifact.Signature, privateKey.Public().(ed25519.PublicKey)); err == nil {
		t.Fatal("tampered archive was accepted")
	}
	wrong := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x22}, ed25519.SeedSize))
	if _, err := Verify(artifact.Archive, artifact.Checksum, artifact.Signature, wrong.Public().(ed25519.PublicKey)); err == nil {
		t.Fatal("wrong trust root was accepted")
	}
}

func TestBuildRejectsMissingLicenseMaterial(t *testing.T) {
	if runtime.GOOS != "linux" || runtime.GOARCH != "amd64" {
		t.Skip("fixture builder currently exercises the production linux/amd64 package")
	}
	loom, singBox := buildClientFixtures(t)
	privateKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x31}, ed25519.SeedSize))
	input := fixtureBuildInput(loom, singBox, privateKey)
	input.SingBoxLicense = nil
	if _, err := Build(input); err == nil || !strings.Contains(err.Error(), "sing-box LICENSE") {
		t.Fatalf("缺少第三方许可证仍可构建: %v", err)
	}
}

func fixtureBuildInput(loom, singBox []byte, privateKey ed25519.PrivateKey) BuildInput {
	return BuildInput{
		Loom: loom, SingBox: singBox, LoomLicense: []byte("Apache-2.0 test license\n"),
		LoomNotice: []byte("Loom test notice\n"), SingBoxLicense: []byte("GPL-3.0 test license\n"),
		PrivateKey: privateKey, AllowDirty: true,
	}
}

func TestBuildRejectsFakeSingBox(t *testing.T) {
	if _, err := inspectSingBox([]byte("#!/bin/sh\nexit 0\n"), "amd64"); err == nil || !strings.Contains(err.Error(), "Linux ELF") {
		t.Fatalf("fake sing-box error=%v", err)
	}
}

func buildClientFixtures(t *testing.T) ([]byte, []byte) {
	return buildClientFixturesForArch(t, "amd64")
}

func buildClientFixturesForArch(t *testing.T, architecture string) ([]byte, []byte) {
	t.Helper()
	dir := t.TempDir()
	repo, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	loomPath := filepath.Join(dir, "loom")
	cmd := exec.Command("go", "build", "-buildvcs=false", "-o", loomPath, "./cmd/loom")
	cmd.Dir = repo
	cmd.Env = append(os.Environ(), "GOWORK=off", "CGO_ENABLED=0", "GOOS=linux", "GOARCH="+architecture)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build Loom fixture: %v\n%s", err, output)
	}

	root := filepath.Join(dir, "fixture")
	module := filepath.Join(dir, "sing-box")
	if err := os.MkdirAll(filepath.Join(module, "cmd", "sing-box"), 0o755); err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, filepath.Join(root, "go.mod"), "module fixture\n\ngo 1.27.0\n\nrequire github.com/sagernet/sing-box v1.11.4\nreplace github.com/sagernet/sing-box => ../sing-box\n")
	writeTestFile(t, filepath.Join(module, "go.mod"), "module github.com/sagernet/sing-box\n\ngo 1.27.0\n")
	writeTestFile(t, filepath.Join(module, "cmd", "sing-box", "main.go"), "package main\nfunc main() {}\n")
	singBoxPath := filepath.Join(dir, "sing-box.bin")
	cmd = exec.Command("go", "build", "-buildvcs=false", "-o", singBoxPath, "github.com/sagernet/sing-box/cmd/sing-box")
	cmd.Dir = root
	cmd.Env = append(os.Environ(), "GOWORK=off", "CGO_ENABLED=0", "GOOS=linux", "GOARCH="+architecture)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build sing-box fixture: %v\n%s", err, output)
	}
	loom, err := os.ReadFile(loomPath)
	if err != nil {
		t.Fatal(err)
	}
	singBox, err := os.ReadFile(singBoxPath)
	if err != nil {
		t.Fatal(err)
	}
	return loom, singBox
}

func writeTestFile(t *testing.T, path, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

func writeTestBytes(t *testing.T, path string, body []byte) {
	t.Helper()
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}
}

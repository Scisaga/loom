package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"loom/internal/wire"
)

func TestControlCreateInviteNormalEntryAndRetainedRetry(t *testing.T) {
	runtime, adminDir := controlInviteRuntime(t)
	endpoint, client, _ := progressTestServer(t, runtime, adminDir)
	ctx := context.Background()
	var options controlInviteContextV1
	if err := fetchControlInviteJSON(ctx, endpoint, client, privateControlInviteContextPath, &options); err != nil {
		t.Fatal(err)
	}
	if len(options.Grants) == 0 {
		t.Fatal("正常入口没有从当前配置读取目标授权")
	}
	grant := options.Grants[0].Grant
	input := controlCreateInviteInputV1{Name: "demo-normal-device", Platform: "linux-server",
		Responsibilities: controlResponsibilityValues("use_loom"), Grants: []string{grant.Kind + ":" + grant.TargetID}, TTLSeconds: 900}
	output := filepath.Join(t.TempDir(), "delivery")
	if err := os.Mkdir(output, 0o700); err != nil {
		t.Fatal(err)
	}
	unlock, err := lockControlState(output)
	if err != nil {
		t.Fatal(err)
	}
	if err := createControlInvite(ctx, adminDir, endpoint, client, input, output, runtime.now); err == nil {
		t.Fatal("并发创建没有保护同一个交付目录")
	}
	unlock()
	if len(runtime.journal.Records) != 1 {
		t.Fatal("未持有交付锁的请求发生了创建")
	}
	if err := createControlInvite(ctx, adminDir, endpoint, client, input, output, runtime.now); err != nil {
		t.Fatal(err)
	}
	var retained controlInviteRequestFileV1
	var descriptor wire.InviteBootstrapDescriptorV2
	var proof wire.InviteProofBundleV2
	for name, target := range map[string]any{"request.json": &retained, "invite.loom-invite": &descriptor, "proof.json": &proof} {
		if err := readCanonicalFile(filepath.Join(output, name), 8<<20, target); err != nil {
			t.Fatal(err)
		}
		info, err := os.Stat(filepath.Join(output, name))
		if err != nil || info.Mode().Perm() != 0o600 {
			t.Fatalf("邀请文件 %s 没有受保护: %v", name, err)
		}
	}
	verified, err := wire.VerifyInviteProofBundle(&proof, &descriptor, runtime.now(), wire.InviteProofTrustV2{})
	if err != nil || verified.Head().HeadHash != runtime.store.Snapshot().CertifiedHead.HeadHash {
		t.Fatalf("正常入口交付的证明不可被客户端验证: %v", err)
	}
	first, err := os.ReadFile(filepath.Join(output, "invite.loom-invite"))
	if err != nil {
		t.Fatal(err)
	}
	if err := createControlInvite(ctx, adminDir, endpoint, client, input, output, runtime.now); err != nil {
		t.Fatal(err)
	}
	second, err := os.ReadFile(filepath.Join(output, "invite.loom-invite"))
	if err != nil || !bytes.Equal(first, second) || len(runtime.journal.Records) != 2 {
		t.Fatal("重试生成了另一个邀请或改变了原交付")
	}
	input.Name = "demo-other-device"
	if err := createControlInvite(ctx, adminDir, endpoint, client, input, output, runtime.now); err == nil || len(runtime.journal.Records) != 2 {
		t.Fatal("不同输入覆盖了已签请求")
	}
	// 已提交请求即使超过原操作 deadline 仍可读取原结果；不允许改正文后使用旧 Head。
	later := runtime.now().Add(10 * time.Minute)
	runtime.now = func() time.Time { return later }
	endpoint, client, _ = progressTestServer(t, runtime, adminDir)
	if _, err := submitControlOperation(ctx, adminDir, endpoint, client, retained.Base, retained.Request); err != nil {
		t.Fatalf("已提交请求过期后不能读取原结果: %v", err)
	}
	retained.Request.Operation.Body.Reason = "demo-altered-retry"
	if _, err := submitControlOperation(ctx, adminDir, endpoint, client, retained.Base, retained.Request); err == nil {
		t.Fatal("改过正文的过期请求复用了原结果")
	}
}

func TestControlCreateInviteValidatesRolesAndNameBeforeSavingRequest(t *testing.T) {
	runtime, adminDir := controlInviteRuntime(t)
	endpoint, client, _ := progressTestServer(t, runtime, adminDir)
	var options controlInviteContextV1
	if err := fetchControlInviteJSON(context.Background(), endpoint, client, privateControlInviteContextPath, &options); err != nil {
		t.Fatal(err)
	}
	roles := controlResponsibilityValues("internet_egress, use_loom,forward")
	if err := wire.ValidateEnrollmentResponsibilities(&wire.EnrollmentResponsibilitiesV1{Schema: 1, Values: roles}); err != nil {
		t.Fatalf("CLI 职责排序不符合 wire 契约: %v", err)
	}
	for _, role := range []string{"use_loom,use_loom", "unknown", "internet_egress"} {
		input := controlCreateInviteInputV1{Name: "demo-invalid", Platform: "linux-server",
			Responsibilities: controlResponsibilityValues(role), TTLSeconds: 900}
		output := filepath.Join(t.TempDir(), "delivery")
		if err := createControlInvite(context.Background(), adminDir, endpoint, client, input, output, runtime.now); err == nil {
			t.Fatal("非法职责被接受")
		}
		if _, err := os.Stat(filepath.Join(output, "request.json")); !os.IsNotExist(err) {
			t.Fatal("非法输入留下了无法重试的已签请求")
		}
	}
	input := controlCreateInviteInputV1{Name: string([]byte{0xff}), Platform: "linux-server", Responsibilities: []string{"use_loom"}, TTLSeconds: 900}
	if _, err := buildControlInviteRequest(adminDir, endpoint, options, input, runtime.now()); err == nil {
		t.Fatal("非法 UTF-8 名称被接受")
	}
}

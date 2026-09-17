package main

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"loom/internal/publish"
	"loom/internal/wire"
)

// controlDistributionTarget 只配置外部副作用执行位置，不把 SSH 路径写进
// certified application。没有配置时 daemon 仍可提供既有 LKG，但任何需要
// 发布首份配置的新 Enrollment 都会在 completion 返回前失败关闭。
func controlDistributionTarget(specs []string, sshConfig string) (publish.Target, error) {
	if len(specs) == 0 {
		return nil, nil
	}
	if len(specs) < 2 || len(specs) > 3 {
		return nil, errors.New("control serve 的生产静态分发必须逐一配置 2–3 个镜像")
	}
	usesSSH := false
	for _, spec := range specs {
		usesSSH = usesSSH || strings.HasPrefix(spec, "ssh://")
	}
	if usesSSH {
		clean := filepath.Clean(sshConfig)
		info, err := os.Lstat(clean)
		if sshConfig == "" || !filepath.IsAbs(sshConfig) || clean != sshConfig || err != nil ||
			!info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
			return nil, errors.New("control serve 的 SSH 分发必须指定绝对、实体 -ssh-config")
		}
	}
	targets := make([]publish.Target, 0, len(specs))
	for _, spec := range specs {
		target, err := publish.ParseTarget(spec, sshConfig)
		if err != nil {
			return nil, err
		}
		targets = append(targets, target)
	}
	return publish.NewMirrorSet(targets...)
}

func enrollmentDistributionObjects(plan controlEnrollmentRuntimePlanV1) (map[string][]byte, []string, error) {
	configs := append([]controlPublishedConfigV1(nil), plan.ClientConfigs...)
	for _, server := range plan.Servers {
		configs = append(configs, server.Configs...)
	}
	if len(configs) == 0 {
		return nil, nil, errors.New("[首次配置] completion 没有可发布的配置制品")
	}
	objects := make(map[string][]byte, len(configs))
	evidence := make([]string, 0, len(configs))
	seenHashes := make(map[string]bool, len(configs))
	for _, config := range configs {
		if err := wire.ValidateDeviceConfigArtifactRef(&config.Ref); err != nil {
			return nil, nil, err
		}
		canonical, err := wire.CanonicalizeStrict(config.Content)
		digest, hashErr := wire.DeviceConfigArtifactContentHash(config.Content)
		parsed, parseErr := wire.ParseHash(config.Ref.ContentHash)
		if err != nil || hashErr != nil || parseErr != nil || !bytes.Equal(canonical, config.Content) ||
			digest != config.Ref.ContentHash || int64(len(config.Content)) != config.Ref.SizeBytes {
			return nil, nil, errors.New("[首次配置] 静态发布制品与认证引用不一致")
		}
		path := filepath.ToSlash(filepath.Join("distribution", "sha256", hex.EncodeToString(parsed)))
		if previous, exists := objects[path]; exists && !bytes.Equal(previous, config.Content) {
			return nil, nil, errors.New("[首次配置] 同一内容地址绑定了不同配置")
		}
		objects[path] = append([]byte(nil), config.Content...)
		if !seenHashes[config.Ref.ContentHash] {
			evidence = append(evidence, config.Ref.ContentHash)
			seenHashes[config.Ref.ContentHash] = true
		}
	}
	sort.Strings(evidence)
	return objects, evidence, nil
}

func (runtime *controlRuntime) reconcileEnrollmentDistributionRecordLocked(record *controlOperationRecordV1) ([]string, error) {
	if record == nil || record.Enrollment == nil || record.Enrollment.Mutation.Preimage == nil ||
		record.Enrollment.Mutation.Preimage.Completion == nil {
		return nil, nil
	}
	if record.Result == nil {
		return nil, errors.New("[首次配置] 未 certified 的 completion 不得发布配置")
	}
	if runtime.distribution == nil {
		return nil, errors.New("[首次配置] control daemon 未配置 2–3 个静态分发目标")
	}
	completion := record.Enrollment.Mutation.Preimage.Completion
	if completion.Record.ProvisionalOperation == nil {
		return nil, errors.New("[首次配置] completion 缺已认证 provisional operation")
	}
	var raw []byte
	planCount := 0
	for index := range runtime.journal.Records {
		candidate := runtime.journal.Records[index].Enrollment
		if candidate == nil || candidate.Mutation.Preimage == nil || candidate.Mutation.Preimage.Provisional == nil {
			continue
		}
		provisional := candidate.Mutation.Preimage.Provisional
		if provisional.Record.InviteID != completion.Record.InviteID ||
			!wire.EqualCanonical(provisional.Prepared.Operation, *completion.Record.ProvisionalOperation) {
			continue
		}
		planCount++
		if planCount > 1 {
			return nil, errors.New("[首次配置] completion 对应多个 provisional 运行计划")
		}
		raw = append([]byte(nil), provisional.Prepared.RuntimePlan...)
	}
	if planCount == 0 {
		return nil, errors.New("[首次配置] completion 缺原 provisional 运行计划")
	}
	// 仅旧测试/组件注入的 issuer 不携 daemon runtime plan；正式
	// productionEnrollmentWorkflow 始终生成非空计划并走镜像门禁。
	if len(raw) == 0 {
		return nil, nil
	}
	plan, err := decodeEnrollmentRuntimePlan(raw)
	if err != nil {
		return nil, err
	}
	objects, evidence, err := enrollmentDistributionObjects(plan)
	if err != nil {
		return nil, err
	}
	if err := publish.PushImmutable(runtime.distribution, objects); err != nil {
		return nil, fmt.Errorf("[首次配置] 静态镜像发布失败: %w", err)
	}
	paths := make([]string, 0, len(objects))
	for path := range objects {
		paths = append(paths, path)
	}
	sort.Strings(paths)
	for _, path := range paths {
		body, found, err := runtime.distribution.ReadFile(path)
		if err != nil || !found || !bytes.Equal(body, objects[path]) {
			if err != nil {
				return nil, fmt.Errorf("[首次配置] 静态镜像回读失败: %w", err)
			}
			return nil, errors.New("[首次配置] 静态镜像未返回 exact 配置制品")
		}
	}
	return evidence, nil
}

// 启动时重验历史 completion 的公开不可变对象，修复镜像被清空或旧版本只写
// control 本地 staging 的情况。它不重新签发身份，也不改变任何 Head。
func (runtime *controlRuntime) reconcileEnrollmentDistributionPrefix() error {
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	for index := range runtime.journal.Records {
		if _, err := runtime.reconcileEnrollmentDistributionRecordLocked(&runtime.journal.Records[index]); err != nil {
			return err
		}
	}
	return nil
}

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"os"
	"path/filepath"
	"time"

	"loom/internal/androidrelease"
	"loom/internal/control"
)

func cmdReleasePackageAndroid(args []string) error {
	fs := flag.NewFlagSet("release package-android", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	env := fs.String("env", ".env", "通过唯一 YAML 读取签发能力引用")
	pub := fs.String("pubkey", "", "带外固定的发布公钥")
	apkPath := fs.String("apk", "", "正式签名 APK")
	aarPath := fs.String("aar", "", "构建该 APK 的原始已审核 AAR")
	sdk := fs.String("sdk", "", "本机 Android SDK 绝对路径")
	generationText := fs.String("generation", "", "Android 应用清单发布代")
	output := fs.String("o", "", "本次应用清单输出目录")
	if err := fs.Parse(args); err != nil {
		return err
	}
	generation, err := control.ParseU64(*generationText)
	if err != nil || generation == 0 || fs.NArg() != 0 || *apkPath == "" || *aarPath == "" || *sdk == "" || *output == "" || *pub == "" {
		return errors.New("package-android 需要 apk、aar、sdk、generation、pubkey 和 o")
	}
	key, public, err := releaseSigningKey(*env, *pub)
	if err != nil {
		return err
	}
	apk, err := readBoundedRegular(*apkPath, 256<<20, false)
	if err != nil {
		return err
	}
	aar, err := readBoundedRegular(*aarPath, 256<<20, false)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	if err := androidrelease.AuditAPK(ctx, *sdk, apk); err != nil {
		return err
	}
	manifest, body, signature, err := androidrelease.Build(apk, aar, generation, key)
	if err != nil {
		return err
	}
	if _, err = androidrelease.Verify(body, signature, apk, public); err != nil {
		return err
	}
	if err := os.MkdirAll(*output, 0755); err != nil {
		return err
	}
	for _, file := range []struct {
		name string
		body []byte
	}{{androidrelease.Name, apk}, {androidrelease.Name + ".manifest.json", body}, {androidrelease.Name + ".sig", signature}} {
		path := filepath.Join(*output, file.name)
		prior, err := readBoundedRegular(path, 256<<20, false)
		if err == nil {
			if !bytes.Equal(prior, file.body) {
				return errors.New("Android output already contains different bytes; choose a new output directory")
			}
			continue
		}
		if !errors.Is(err, os.ErrNotExist) {
			return err
		}
		if err := writeAndroidOutput(path, file.body); err != nil {
			return err
		}
	}
	return json.NewEncoder(os.Stdout).Encode(map[string]any{"component_id": androidrelease.Kind, "platform": "android-any", "manifest_digest": control.ReleaseDigest(body), "artifact": manifest.Artifact, "source_commit": manifest.SourceCommit, "version": manifest.VersionName, "components": manifest.Components()})
}

// Publish complete bytes without replacing a concurrent writer's output.
// These are disposable packaging files, not another release store.
func writeAndroidOutput(path string, body []byte) error {
	file, err := os.CreateTemp(filepath.Dir(path), ".loom-android-*")
	if err != nil {
		return err
	}
	defer os.Remove(file.Name())
	defer file.Close()
	if _, err := file.Write(body); err != nil {
		return err
	}
	if err := file.Chmod(0644); err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	if err := os.Link(file.Name(), path); err != nil {
		if !errors.Is(err, os.ErrExist) {
			return err
		}
		prior, readErr := readBoundedRegular(path, 256<<20, false)
		if readErr != nil || !bytes.Equal(prior, body) {
			return errors.New("Android output concurrently changed; choose a new output directory")
		}
	}
	return nil
}

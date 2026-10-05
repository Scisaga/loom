package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"os"
	"path/filepath"
	"time"

	"loom/internal/control"
	"loom/internal/windowsrelease"
)

func cmdReleasePackageWindows(args []string) error {
	fs := flag.NewFlagSet("release package-windows", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	env := fs.String("env", ".env", "通过唯一 YAML 读取签发能力引用")
	pub := fs.String("pubkey", "", "带外固定的发布公钥")
	artifactPath := fs.String("artifact", "", "原始 MSI 或便携 ZIP")
	bundlePath := fs.String("bundle", "", "仅 Installed：构建 MSI 的原始 Installed ZIP")
	edition := fs.String("edition", "", "installed、portable-tun 或 portable-mixed")
	arch := fs.String("arch", "", "amd64 或 arm64")
	generationText := fs.String("generation", "", "Windows 应用清单发布代")
	output := fs.String("o", "", "本次应用清单输出目录")
	if err := fs.Parse(args); err != nil {
		return err
	}
	generation, err := control.ParseU64(*generationText)
	if err != nil || generation == 0 || fs.NArg() != 0 || *artifactPath == "" || *output == "" || *pub == "" || (*edition == "installed") != (*bundlePath != "") || !windowsrelease.IsArtifact(windowsrelease.Name(*edition, *arch)) {
		return errors.New("package-windows 需要 artifact、edition、arch、generation、pubkey 和 o；仅 Installed 还须原始 bundle")
	}
	key, public, err := releaseSigningKey(*env, *pub)
	if err != nil {
		return err
	}
	artifact, err := readBoundedRegular(*artifactPath, 256<<20, false)
	if err != nil {
		return err
	}
	bundle, version := artifact, ""
	if *edition == "installed" {
		bundle, err = readBoundedRegular(*bundlePath, 256<<20, false)
		if err != nil {
			return err
		}
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		version, err = windowsrelease.AuditMSI(ctx, artifact, bundle, *arch)
		if err != nil {
			return err
		}
	}
	manifest, body, signature, err := windowsrelease.Build(artifact, bundle, *edition, *arch, version, generation, key)
	if err != nil {
		return err
	}
	if _, err = windowsrelease.Verify(body, signature, artifact, public); err != nil {
		return err
	}
	if err = os.MkdirAll(*output, 0755); err != nil {
		return err
	}
	for _, file := range []struct {
		name string
		body []byte
	}{{manifest.Artifact.Name, artifact}, {manifest.Artifact.Name + ".manifest.json", body}, {manifest.Artifact.Name + ".sig", signature}} {
		if err := writeReleaseOutput(filepath.Join(*output, file.name), file.body); err != nil {
			return err
		}
	}
	return json.NewEncoder(os.Stdout).Encode(map[string]any{"component_id": "windows-client-" + manifest.Edition, "platform": "windows-" + manifest.Arch, "manifest_digest": control.ReleaseDigest(body), "artifact": manifest.Artifact, "source_commit": manifest.SourceCommit, "version": manifest.Version(), "components": manifest.Components})
}

package main

import (
	"crypto/ed25519"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"loom/internal/bootstrapaccess"
	"loom/internal/certmanager"
	"loom/internal/distribution"
	"loom/internal/wire"
)

func cmdBootstrapRenderPublic(args []string) error {
	flags := flag.NewFlagSet("bootstrap render-public", flag.ContinueOnError)
	bundlePath := flags.String("bundle", "", "管理员导出的认证安装交付")
	device := flags.String("device", "", "原 Device ID")
	platform := flags.String("platform-pubkey", "/etc/loom/trust/platform.pub", "原平台公钥")
	certificates := flags.String("certificate-dir", "/var/lib/loom-public-v2/certificates", "原节点已有证书材料目录")
	staticRoot := flags.String("static-root", "", "fake website 与不可变对象的静态根目录")
	out := flags.String("out", "", "生成的 Nginx server 配置")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 || *bundlePath == "" || *device == "" || *staticRoot == "" ||
		!filepath.IsAbs(*out) || filepath.Clean(*out) != *out {
		return errors.New("bootstrap render-public 需要 bundle、device、static-root 与 out 绝对路径")
	}
	for _, input := range []string{*bundlePath, *platform} {
		same, err := bootstrapPathsSame(*out, input)
		if err != nil {
			return err
		}
		if same {
			return errors.New("Nginx 输出不能覆盖安装交付或平台公钥")
		}
	}
	var bundle bootstrapInstallationBundleV1
	if err := readCanonicalFile(*bundlePath, 32<<20, &bundle); err != nil {
		return err
	}
	key, err := readKey(*platform, ed25519.PublicKeySize)
	if err != nil {
		return err
	}
	if err := renderBootstrapPublicNginx(bundle, key, *device, *certificates,
		*staticRoot, *out, nil, time.Now().UTC()); err != nil {
		return err
	}
	fmt.Println("✓ 已从认证安装交付生成纯静态公网 Nginx 配置；尚未 reload Nginx")
	return nil
}

func renderBootstrapPublicNginx(bundle bootstrapInstallationBundleV1, public ed25519.PublicKey,
	deviceID, certificateDirectory, staticRoot, out string, roots *x509.CertPool, now time.Time) error {
	installation, err := verifyBootstrapInstallationBundle(bundle, public, deviceID)
	if err != nil {
		return err
	}
	if now.IsZero() {
		return errors.New("[public surface] 缺可信时间")
	}
	from, err := wire.ParseTimeZ(installation.Input.ValidFrom)
	if err != nil {
		return err
	}
	until, err := wire.ParseTimeZ(installation.Input.ValidUntil)
	if err != nil {
		return err
	}
	if now.Before(from) || !now.Before(until) {
		return errors.New("[public surface] 认证安装交付尚未生效或已经过期")
	}
	if err := validateBootstrapStaticRoot(staticRoot); err != nil {
		return err
	}
	parent, err := os.Lstat(filepath.Dir(out))
	if err != nil || !parent.IsDir() || parent.Mode()&os.ModeSymlink != 0 {
		return errors.New("[public surface] Nginx 输出父目录必须是已有实体目录")
	}
	input, err := bootstrapPublicNginxInput(installation, deviceID, certificateDirectory,
		staticRoot, roots, now)
	if err != nil {
		return err
	}
	config, err := distribution.RenderNginx(input)
	if err != nil {
		return err
	}
	return writeBytesAtomic(out, config, 0o600)
}

func bootstrapPublicNginxInput(installation bootstrapaccess.InitialBootstrapInstallationV1,
	deviceID, certificateDirectory, staticRoot string, roots *x509.CertPool,
	now time.Time) (distribution.NginxInput, error) {
	var empty distribution.NginxInput
	if err := bootstrapaccess.ValidateInitialBootstrapInstallation(&installation); err != nil {
		return empty, err
	}
	var selected *bootstrapaccess.InitialBootstrapListenerInputV1
	for index := range installation.Input.Listeners {
		listener := &installation.Input.Listeners[index]
		if listener.Profile.ServerID != deviceID {
			continue
		}
		if selected == nil {
			copy := *listener
			selected = &copy
			continue
		}
		if !wire.EqualCanonical(selected.Profile, listener.Profile) ||
			!wire.EqualCanonical(selected.Resources, listener.Resources) {
			return empty, errors.New("[public surface] 同一节点存在冲突的认证公网 profile/resources")
		}
	}
	if selected == nil {
		return empty, errors.New("[public surface] 认证安装交付不含本节点公网 profile")
	}
	chainPath, keyPath, err := certmanager.ExistingRuntimeCertificatePaths(certificateDirectory,
		selected.Certificate, selected.Certificate.Identity, roots, now)
	if err != nil {
		return empty, err
	}
	return distribution.NginxInput{FQDN: selected.Profile.FQDN,
		ListenPort: int(selected.Resources.NginxLocalTCPPort), Certificate: chainPath,
		CertificateKey: keyPath, StaticRoot: staticRoot}, nil
}

func validateBootstrapStaticRoot(root string) error {
	if !filepath.IsAbs(root) || filepath.Clean(root) != root {
		return errors.New("[public surface] static root 必须是规范绝对路径")
	}
	info, err := os.Lstat(root)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("[public surface] static root 必须是已有实体目录")
	}
	index, err := os.Lstat(filepath.Join(root, "index.html"))
	if err != nil || !index.Mode().IsRegular() || index.Mode()&os.ModeSymlink != 0 || index.Size() < 1 || index.Size() > 1<<20 {
		return errors.New("[public surface] fake website index.html 必须是 1..1MiB 实体文件")
	}
	distributionDirectory := filepath.Join(root, "distribution", "sha256")
	if info, err := os.Lstat(distributionDirectory); err == nil {
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return errors.New("[public surface] immutable distribution 路径不是实体目录")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

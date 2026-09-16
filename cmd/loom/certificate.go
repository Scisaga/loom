package main

import (
	"bytes"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"loom/internal/certmanager"
	"loom/internal/wire"
)

func cmdCertificate(args []string) error {
	if len(args) == 0 || args[0] != "prepare-existing" {
		return errors.New("用法: loom certificate prepare-existing -input <请求文件> -artifact-dir <节点本地目录> -out <公开绑定文件>")
	}
	return prepareExistingCertificateCommand(args[1:], nil, time.Now().UTC())
}

func prepareExistingCertificateCommand(args []string, roots *x509.CertPool, now time.Time) error {
	flags := flag.NewFlagSet("certificate prepare-existing", flag.ContinueOnError)
	input := flags.String("input", "", "受保护的导入请求文件，不含私钥内容")
	directory := flags.String("artifact-dir", "", "原证书所属节点的持久材料目录")
	out := flags.String("out", "", "公开身份与完整链绑定文件")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 || *input == "" || *directory == "" || !filepath.IsAbs(*out) {
		return errors.New("必须指定 input、artifact-dir 与 out 绝对路径")
	}
	parent, err := os.Lstat(filepath.Dir(*out))
	if err != nil || !parent.IsDir() || parent.Mode().Perm() != 0700 || parent.Mode()&os.ModeSymlink != 0 {
		return errors.New("公开绑定输出须位于已有的 0700 实体目录")
	}
	body, err := readOwnerOnlyFile(*input, 1<<20)
	if err != nil {
		return err
	}
	var request certmanager.ExistingCertificateRequestV1
	if _, err := wire.DecodeStrict(body, 1<<20, &request); err != nil {
		return err
	}
	binding, err := certmanager.PrepareExistingCertificate(*directory, request, roots, now)
	if err != nil {
		return err
	}
	encoded, err := wire.MarshalCanonical(binding)
	if err != nil {
		return err
	}
	// 输出只含公有材料，但仍保护部署标识；不覆盖先前不同请求的结果。
	if saved, err := readOwnerOnlyFile(*out, 2<<20); err == nil {
		if !bytes.Equal(saved, encoded) {
			return errors.New("输出已存在不同证书绑定")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	} else {
		file, err := os.CreateTemp(filepath.Dir(*out), ".certificate-binding-*")
		if err != nil {
			return err
		}
		defer os.Remove(file.Name())
		if _, err = file.Write(encoded); err == nil {
			err = file.Sync()
		}
		closeErr := file.Close()
		if err == nil {
			err = closeErr
		}
		if err != nil {
			return err
		}
		if err := os.Link(file.Name(), *out); err != nil {
			saved, readErr := readOwnerOnlyFile(*out, 2<<20)
			if !errors.Is(err, os.ErrExist) || readErr != nil || !bytes.Equal(saved, encoded) {
				return errors.New("输出已存在或不能原子保存")
			}
		}
		parent, err := os.Open(filepath.Dir(*out))
		if err != nil {
			return err
		}
		err = parent.Sync()
		_ = parent.Close()
		if err != nil {
			return err
		}
	}
	fmt.Println("✓ 现有证书已在原节点准备；未调用 DNS/ACME，尚未认证或启用入口")
	return nil
}

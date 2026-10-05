package main

import (
	"crypto/rand"
	"errors"
	"flag"
	"fmt"
	"os"
	"time"

	"loom/internal/admincredential"
)

func cmdControlAdmin(args []string) error {
	if len(args) == 0 || args[0] != "issue" {
		return errors.New("用法: loom control admin issue -issuer-cert <root.crt> -issuer-key <root.key> -name <name> -out-dir <new-directory>")
	}
	fs := flag.NewFlagSet("control admin issue", flag.ContinueOnError)
	options := admincredential.Options{Now: time.Now().UTC(), Random: rand.Reader}
	fs.StringVar(&options.IssuerCertificate, "issuer-cert", "", "受保护的既有管理员 P-256 根证书")
	fs.StringVar(&options.IssuerKey, "issuer-key", "", "与根匹配的本机签发私钥引用")
	fs.StringVar(&options.Directory, "out-dir", "", "新的 owner-only 交付目录")
	fs.StringVar(&options.Name, "name", "", "管理员证书显示名称")
	fs.IntVar(&options.ValidDays, "valid-days", 365, "有效天数，1 至 365，不能超过签发根")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	if fs.NArg() != 0 || os.Geteuid() != 0 {
		return errors.New("administrator issuance requires the control's local root CLI and no positional arguments")
	}
	value, err := admincredential.Issue(options)
	if err != nil {
		return err
	}
	fmt.Printf("Administrator delivery verified: %s\nImport public admin.json through Settings to grant access; retrieve admin.p12 and its separate password privately.\n", value.ID)
	return nil
}

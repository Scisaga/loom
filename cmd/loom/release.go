package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"loom/internal/clientrelease"
	"loom/internal/control"
	"loom/internal/localconfig"
)

func cmdRelease(args []string) error {
	if len(args) == 0 {
		return errors.New("用法: loom release <stage|import|verify>")
	}
	switch args[0] {
	case "stage":
		return cmdReleaseStage(args[1:])
	case "verify":
		return cmdReleaseVerify(args[1:])
	case "import":
		return cmdReleaseImport(args[1:])
	default:
		return errors.New("未知 release 子命令")
	}
}

func cmdReleaseImport(args []string) error {
	fs := flag.NewFlagSet("release import", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	source := fs.String("source", "", "本次临时上传的签名目录")
	root := fs.String("root", "", "本节点目标发布目录")
	pub := fs.String("pubkey", "", "通过独立管理通道固定的发布公钥")
	catalog := fs.String("catalog", "", "显式选择的 catalog digest，不读取 latest")
	expected := fs.String("expected-current", "", "计划读取的目标旧 digest；新空目录省略")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 || *source == "" || *root == "" || *pub == "" || control.ValidateDigest(*catalog) != nil {
		return errors.New("release import 需要 source、root、pubkey 及精确 catalog")
	}
	key, err := control.ReadReleasePublicKey(*pub)
	if err != nil {
		return err
	}
	from, err := filepath.Abs(*source)
	if err != nil {
		return err
	}
	to, err := filepath.Abs(*root)
	if err != nil {
		return err
	}
	set, err := clientrelease.Import(from, to, *catalog, key, *expected)
	if err != nil {
		return err
	}
	return printReleaseReadback(set)
}

func cmdReleaseStage(args []string) error {
	fs := flag.NewFlagSet("release stage", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	env := fs.String("env", ".env", "通过唯一 YAML 读取签发能力引用")
	pub := fs.String("pubkey", "", "带外固定的发布公钥")
	output := fs.String("o", "", "本次本地交付审查目录")
	generationText := fs.String("generation", "", "显式 catalog 发布代")
	expected := fs.String("expected-current", "", "本地目录计划读取的旧 catalog digest；新空目录省略")
	paths, err := parseInterspersed(fs, args)
	if err != nil {
		return err
	}
	generation, err := control.ParseU64(*generationText)
	if err != nil || generation == 0 || *pub == "" || *output == "" || len(paths) == 0 {
		return errors.New("release stage 需要 generation、pubkey、o 及已签包路径")
	}
	config, err := localconfig.Load(*env)
	if err != nil {
		return err
	}
	public, err := control.ReadReleasePublicKey(*pub)
	if err != nil {
		return err
	}
	if strings.HasPrefix(config.SigningKey, "secret:") || strings.HasPrefix(config.SigningKey, "pkcs11:") {
		return errors.New("该不透明发布签发能力没有已配置的 adapter")
	}
	encoded, err := readBoundedRegular(config.SigningKey, 4096, true)
	if err != nil {
		return err
	}
	private, err := decodeB64(string(encoded))
	if err != nil || len(private) != ed25519.PrivateKeySize {
		return errors.New("部署 YAML 引用的发布签发密钥无效")
	}
	key := ed25519.PrivateKey(private)
	if !bytes.Equal(key.Public().(ed25519.PublicKey), public) {
		return errors.New("部署签发能力与带外验签公钥不一致")
	}
	packages := map[string]clientrelease.Input{}
	catalog := control.ReleaseCatalog{Schema: 3, Generation: generation, Entries: []control.ReleaseEntry{}}
	for _, path := range paths {
		body, err := readBoundedRegular(path, 256<<20, false)
		if err != nil {
			return err
		}
		value, err := clientrelease.Inspect(filepath.Base(path), body, public)
		if err != nil {
			return err
		}
		catalog.Entries = append(catalog.Entries, value.Entry)
		packages[value.Entry.Artifact.Digest] = clientrelease.Input{Body: body, Manifest: value.ManifestBody, Signature: value.Signature}
	}
	sort.Slice(catalog.Entries, func(i, j int) bool {
		a, b := catalog.Entries[i], catalog.Entries[j]
		if a.ComponentID != b.ComponentID {
			return a.ComponentID < b.ComponentID
		}
		return a.Platform < b.Platform
	})
	linux := []control.ReleaseEntry{}
	for _, entry := range catalog.Entries {
		if entry.ComponentID == "linux-client-bootstrap" {
			linux = append(linux, entry)
		}
	}
	if len(linux) > 0 {
		input, pkg, err := clientrelease.BuildBootstrap(generation, linux, key)
		if err != nil {
			return err
		}
		packages[pkg.Entry.Artifact.Digest] = input
		catalog.Entries = append([]control.ReleaseEntry{pkg.Entry}, catalog.Entries...)
	}
	body, signature, err := control.SignReleaseCatalog(catalog, key)
	if err != nil {
		return err
	}
	root, err := filepath.Abs(*output)
	if err != nil {
		return err
	}
	set, err := clientrelease.Publish(root, body, signature, public, packages, *expected)
	if err != nil {
		return err
	}
	return printReleaseReadback(set)
}

func cmdReleaseVerify(args []string) error {
	fs := flag.NewFlagSet("release verify", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	root := fs.String("root", "", "本地签名 release store")
	pub := fs.String("pubkey", "", "带外固定的发布公钥")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 || *root == "" || *pub == "" {
		return errors.New("release verify 需要 root 和 pubkey")
	}
	key, err := control.ReadReleasePublicKey(*pub)
	if err != nil {
		return err
	}
	directory, err := filepath.Abs(*root)
	if err != nil {
		return err
	}
	store, err := clientrelease.New(directory, key)
	if err != nil {
		return err
	}
	set, err := store.Read()
	if err != nil {
		return err
	}
	return printReleaseReadback(set)
}

func printReleaseReadback(set control.ReleaseSet) error {
	// This is local artifact verification, never a production deployment result.
	return json.NewEncoder(os.Stdout).Encode(struct {
		Catalog    string                 `json:"catalog_digest"`
		Generation control.U64            `json:"generation"`
		Entries    []control.ReleaseEntry `json:"entries"`
	}{set.ID, set.Catalog.Generation, set.Catalog.Entries})
}

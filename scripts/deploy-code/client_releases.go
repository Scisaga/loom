//go:build !windows

package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"loom/internal/clientrelease"
	"loom/internal/publish"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

func validateClientReleases(c config, pub ed25519.PublicKey, commit string) error {
	store := clientrelease.Store{Root: c.clientReleases, Key: pub}
	catalog, err := store.Load()
	if err != nil {
		return err
	}
	for _, artifact := range catalog.Artifacts {
		if artifact.Platform == "linux-server" && artifact.SourceCommit != commit {
			return fmt.Errorf("Linux 安装包必须与本次服务端发布来自相同提交")
		}
	}
	return nil
}
func publishClientReleases(c config, pub ed25519.PublicKey, output io.Writer) error {
	catalog, catalogPath, err := clientrelease.Read(c.clientReleases, pub)
	if err != nil {
		return err
	}
	tree := &publish.Tree{Files: map[string][]byte{}, Blobs: map[string][]byte{}}
	for _, f := range clientrelease.Files(catalog) {
		file, err := clientrelease.OpenVerified(c.clientReleases, f)
		if err != nil {
			return err
		}
		body, err := io.ReadAll(file)
		file.Close()
		if err != nil {
			return err
		}
		tree.Blobs[f.Path] = body
	}
	for _, path := range []string{catalogPath, strings.TrimSuffix(catalogPath, ".json") + ".sig"} {
		body, err := os.ReadFile(filepath.Join(c.clientReleases, path))
		if err != nil {
			return err
		}
		tree.Files[path] = body
	}
	// 公网只增加不可变 catalog 与内容寻址文件；不发布 current 指针。
	var wg sync.WaitGroup
	var mu sync.Mutex
	failures := []string{}
	for _, destination := range c.outputs {
		wg.Add(1)
		go func(destination string) {
			defer wg.Done()
			target, err := publish.ParseTarget(strings.TrimRight(destination, "/")+"/client-releases", c.sshConfig)
			if err == nil {
				err = target.Push(tree)
			}
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				fmt.Fprintf(output, "客户端制品分发失败: %s: %v\n", destination, err)
				failures = append(failures, fmt.Sprintf("%s: %v", destination, err))
			} else {
				fmt.Fprintf(output, "客户端制品分发完成: %s (%d 个包)\n", destination, len(catalog.Artifacts))
			}
		}(destination)
	}
	wg.Wait()
	if len(failures) > 0 {
		return fmt.Errorf("客户端制品分发失败: %s", strings.Join(failures, "; "))
	}
	// 全部分发落盘校验通过后才更新控制节点的可下载目录。
	// 指针绑定本次已验证的目录；复制期间源头发布新一代也不能混用。
	pointer, err := json.Marshal(map[string]string{"catalog": catalogPath})
	if err != nil {
		return err
	}
	receipt, _ := json.Marshal(map[string]any{"catalog": catalogPath, "mirrors": len(c.outputs), "verified_at": time.Now().UTC().Format(time.RFC3339)})
	localTree := &publish.Tree{Files: map[string][]byte{"current.json": pointer, "publication.json": receipt}, Blobs: tree.Blobs}
	for p, b := range tree.Files {
		localTree.Files[p] = b
	}
	local, err := publish.ParseTarget(c.clientStore, "")
	if err != nil {
		return err
	}
	if err = local.Push(localTree); err != nil {
		return err
	}
	// 当前 Linux shell bootstrap 仍消费固定包入口；与通用目录发布同一份字节。
	legacy := &publish.Tree{Files: map[string][]byte{}}
	for _, a := range catalog.Artifacts {
		if a.Platform == "linux-server" && a.Arch == "amd64" {
			legacy.Files[a.Filename] = tree.Blobs[a.Path]
			legacy.Files[a.Filename+".sha256"] = tree.Blobs[a.Checksum.Path]
			legacy.Files[a.Filename+".sig"] = tree.Blobs[a.Signature.Path]
			legacy.Files[a.Filename+".pub"] = []byte(base64.StdEncoding.EncodeToString(pub) + "\n")
		}
	}
	if len(legacy.Files) > 0 {
		target, err := publish.ParseTarget(filepath.Dir(c.clientStore), "")
		if err != nil {
			return err
		}
		if err = target.Push(legacy); err != nil {
			return err
		}
	}
	fmt.Fprintf(output, "客户端制品目录已激活: %d 个包\n", len(catalog.Artifacts))
	return nil
}

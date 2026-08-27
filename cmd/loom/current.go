package main

import (
	"crypto/ed25519"
	"flag"
	"fmt"
	"os"

	"loom/internal/publish"
)

// cmdCurrentInspect turns the signed release envelope into coordinates that
// operators can compare with node release floors during bootstrap/recovery.
// It is read-only and verifies with the same pinned platform key as pull.
func cmdCurrentInspect(args []string) error {
	fs := flag.NewFlagSet("current", flag.ExitOnError)
	file := fs.String("file", "", "要验签并查看的 signed current 文件(必需)")
	pubPath := fs.String("pubkey", "/etc/loom/trust/platform.pub", "平台 Ed25519 公钥")
	node := fs.String("node", "", "同时显示这个节点实际选择的 snapshot")
	if _, err := parseInterspersed(fs, args); err != nil {
		return err
	}
	if *file == "" {
		return fmt.Errorf("需要 -file 指定 signed current 文件")
	}
	body, err := os.ReadFile(*file)
	if err != nil {
		return err
	}
	pub, err := readKey(*pubPath, ed25519.PublicKeySize)
	if err != nil {
		return fmt.Errorf("读取平台公钥:%w", err)
	}
	current, err := publish.DecodeDeploymentCurrent(body)
	if err != nil {
		return err
	}
	if err := current.Verify(ed25519.PublicKey(pub)); err != nil {
		return fmt.Errorf("signed current 验签失败:%w", err)
	}
	digest, err := current.PayloadSHA256()
	if err != nil {
		return err
	}
	fmt.Printf("generation=%d\npayload_sha256=%s\nsnapshot=%s\npublished_at=%s\nassignments=%d\n",
		current.Generation, digest, current.Snapshot, current.PublishedAt, len(current.Assignments))
	if *node != "" {
		selected, err := current.Select(*node)
		if err != nil {
			return err
		}
		fmt.Printf("node=%s\nselected_snapshot=%s\n", *node, selected)
	}
	return nil
}

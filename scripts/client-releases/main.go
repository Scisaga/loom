// 构建目录只读取显式制品输入，复用既有平台签名权威。
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"loom/internal/clientrelease"
	"os"
)

func main() {
	input := flag.String("input", "", "制品输入 JSON")
	output := flag.String("output", "", "目录输出")
	keyPath := flag.String("key", "", "既有平台签名私钥路径")
	flag.Parse()
	if *input == "" || *output == "" || *keyPath == "" {
		fmt.Fprintln(os.Stderr, "需要 --input --output --key")
		os.Exit(1)
	}
	if err := run(*input, *output, *keyPath); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
func run(input, output, keyPath string) error {
	body, err := os.ReadFile(input)
	if err != nil {
		return err
	}
	var inputs []clientrelease.Input
	if err = json.Unmarshal(body, &inputs); err != nil {
		return err
	}
	key, err := clientrelease.PrivateKey(keyPath)
	if err != nil {
		return err
	}
	catalog, err := clientrelease.Build(output, inputs, key)
	if err != nil {
		return err
	}
	fmt.Printf("已签名 %d 个客户端制品\n", len(catalog.Artifacts))
	return nil
}

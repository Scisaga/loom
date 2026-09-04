//go:build !windows

package main

import "fmt"

func main() {
	fmt.Println("Loom Windows client: build this target with GOOS=windows")
}

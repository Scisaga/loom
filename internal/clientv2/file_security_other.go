//go:build !linux

package clientv2

import "os"

// 非 Linux 构建只保留共享 verifier；#11 的 root-owned 持久化约束不在这些平台启用。
func ownedByCurrentUser(_ os.FileInfo) bool { return true }

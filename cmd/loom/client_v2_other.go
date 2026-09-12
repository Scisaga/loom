//go:build !linux

package main

import "errors"

func cmdClientEnrollV2([]string) error {
	return errors.New("Linux v2 Enrollment 命令只能在 Linux 客户端运行")
}

func cmdClientResumeV2([]string) error {
	return errors.New("Linux v2 Enrollment 恢复命令只能在 Linux 客户端运行")
}

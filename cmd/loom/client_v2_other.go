//go:build !linux

package main

import "errors"

func cmdClientServeV2([]string) error {
	return errors.New("Linux v2 常驻客户端只能在 Linux 运行")
}

func cmdClientImportMigration([]string) error {
	return errors.New("Linux 迁移导入命令只能在 Linux 客户端运行")
}

func cmdClientExportMigrationRequest([]string) error {
	return errors.New("Linux 迁移请求命令只能在 Linux 客户端运行")
}

func cmdClientEnrollV2([]string) error {
	return errors.New("Linux v2 Enrollment 命令只能在 Linux 客户端运行")
}

func cmdClientResumeV2([]string) error {
	return errors.New("Linux v2 Enrollment 恢复命令只能在 Linux 客户端运行")
}

func cmdClientSyncV2([]string) error {
	return errors.New("Linux v2 private device_config 命令只能在 Linux 客户端运行")
}

func cmdClientReportV2([]string) error {
	return errors.New("Linux v2 private device_report 命令只能在 Linux 客户端运行")
}

func cmdClientAcceptV2Runtime([]string) error {
	return errors.New("Linux v2 runtime 命令只能在 Linux 客户端运行")
}

func cmdClientUninstallV2Runtime([]string) error {
	return errors.New("Linux v2 runtime 卸载命令只能在 Linux 客户端运行")
}

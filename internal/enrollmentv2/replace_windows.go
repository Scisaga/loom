//go:build windows

package enrollmentv2

import "golang.org/x/sys/windows"

func replaceDurableFile(source, target string) error {
	from, err := windows.UTF16PtrFromString(source)
	if err != nil {
		return err
	}
	to, err := windows.UTF16PtrFromString(target)
	if err != nil {
		return err
	}
	return windows.MoveFileEx(from, to,
		windows.MOVEFILE_REPLACE_EXISTING|windows.MOVEFILE_WRITE_THROUGH)
}

// Windows 不能像 Unix 一样用普通文件句柄 fsync 目录；WRITE_THROUGH 已覆盖替换提交。
func syncDurableDirectory(string) error { return nil }

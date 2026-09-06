//go:build windows

package main

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"unsafe"

	"golang.org/x/sys/windows"
)

func installedStateRoot() (string, error) {
	base, err := windows.KnownFolderPath(windows.FOLDERID_ProgramData, 0)
	if err != nil {
		return "", err
	}
	return filepath.Join(base, "Loom"), nil
}

func trustedMachineSID(sid *windows.SID) bool {
	return sid != nil && (sid.IsWellKnown(windows.WinLocalSystemSid) || sid.IsWellKnown(windows.WinBuiltinAdministratorsSid))
}

// §13.5：机器 DPAPI 不隔离本机用户，必须在读取任何身份/运行文件前核验安装 ACL。
func validateMachineDescriptor(sd *windows.SECURITY_DESCRIPTOR) error {
	owner, _, err := sd.Owner()
	if err != nil || !trustedMachineSID(owner) {
		return errors.New("机器状态目录的所有者不是 SYSTEM 或管理员")
	}
	acl, _, err := sd.DACL()
	if err != nil || acl == nil || acl.AceCount == 0 {
		return errors.New("机器状态缺少受限 ACL")
	}
	for i := uint32(0); i < uint32(acl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(acl, i, &ace); err != nil {
			return err
		}
		if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE || !trustedMachineSID((*windows.SID)(unsafe.Pointer(&ace.SidStart))) {
			return errors.New("机器状态 ACL 含非 SYSTEM/管理员权限")
		}
	}
	return nil
}

func validateInstalledState(root string) error {
	// §13.5：不从环境变量、GUI 或 IPC 接受机器状态路径；不跟随目录联接。
	for path := root; filepath.Dir(path) != path; path = filepath.Dir(path) {
		wide, err := windows.UTF16PtrFromString(path)
		if err != nil {
			return err
		}
		attrs, err := windows.GetFileAttributes(wide)
		if err != nil || attrs&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
			return errors.New("机器状态目录缺失或含目录联接；请修复 MSI 安装")
		}
	}
	return filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return errors.New("机器状态目录不能包含链接")
		}
		wide, err := windows.UTF16PtrFromString(path)
		if err != nil {
			return err
		}
		h, err := windows.CreateFile(wide, windows.READ_CONTROL, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
			nil, windows.OPEN_EXISTING, windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
		if err != nil {
			return err
		}
		defer windows.CloseHandle(h)
		var info windows.ByHandleFileInformation
		if err := windows.GetFileInformationByHandle(h, &info); err != nil {
			return err
		}
		if info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 || (!entry.IsDir() && info.NumberOfLinks != 1) {
			return errors.New("机器状态不能包含重解析点或硬链接")
		}
		sd, err := windows.GetSecurityInfo(h, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
		if err != nil {
			return err
		}
		if err := validateMachineDescriptor(sd); err != nil {
			return fmt.Errorf("机器状态权限不安全；请修复安装：%w", err)
		}
		return nil
	})
}

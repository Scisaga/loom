//go:build windows

package clientruntime

import (
	"errors"
	"path/filepath"

	"golang.org/x/sys/windows"
)

// §13.5：Agent 证据只允许当前身份、SYSTEM 和管理员访问，子文件继承该 DACL。
func protectAgentDirectory(path string) error {
	for p := path; filepath.Dir(p) != p; p = filepath.Dir(p) {
		wide, err := windows.UTF16PtrFromString(p)
		if err != nil {
			return err
		}
		attrs, err := windows.GetFileAttributes(wide)
		if err != nil {
			return err
		}
		if attrs&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
			return errors.New("[§13.5] Agent 目录不能包含重解析点")
		}
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return err
	}
	sd, err := windows.SecurityDescriptorFromString("D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;" + user.User.Sid.String() + ")")
	if err != nil {
		return err
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return err
	}
	return windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil)
}

//go:build !windows

package clientdist

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

func packageFileLinks(info os.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && stat.Nlink == 1
}
func packageFileOwned(info os.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && stat.Uid == 0
}
func packageFileOwnerMatches(a, b os.FileInfo) bool {
	left, ok := a.Sys().(*syscall.Stat_t)
	right, other := b.Sys().(*syscall.Stat_t)
	return ok && other && left.Uid == right.Uid && left.Gid == right.Gid
}
func packageFileModeMatches(info os.FileInfo, mode os.FileMode) bool {
	return info.Mode().Perm() == mode
}
func packageDirectoryOwned(info os.FileInfo) bool {
	return info.IsDir() && info.Mode().Perm()&0022 == 0 && packageFileOwned(info)
}
func packageDirectoryPrivate(info os.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && stat.Uid == uint32(os.Geteuid()) && info.IsDir() && info.Mode().Perm() == 0700
}
func packageWorkRoot(root string) error {
	if root == "" || !filepath.IsAbs(root) || filepath.Clean(root) != root {
		return errors.New("package work directory must be an explicit canonical absolute disk path")
	}
	current := string(filepath.Separator)
	for _, part := range strings.Split(strings.TrimPrefix(root, string(filepath.Separator)), string(filepath.Separator)) {
		if part == "" {
			continue
		}
		current = filepath.Join(current, part)
		info, err := os.Lstat(current)
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0022 != 0 {
			return errors.New("package work directory ancestors are not protected")
		}
		owner, ok := info.Sys().(*syscall.Stat_t)
		if !ok || owner.Uid != 0 && owner.Uid != uint32(os.Geteuid()) {
			return errors.New("package work directory ownership differs")
		}
	}
	return packageWorkFilesystem(root)
}

package clientdist

import (
	"errors"
	"os"
	"path/filepath"
)

func packageFileLinks(info os.FileInfo) bool                         { return info.Mode().IsRegular() }
func packageFileOwned(info os.FileInfo) bool                         { return true }
func packageFileOwnerMatches(a, b os.FileInfo) bool                  { return true }
func packageFileModeMatches(info os.FileInfo, mode os.FileMode) bool { return true }
func packageDirectoryOwned(info os.FileInfo) bool                    { return info.IsDir() }
func packageDirectoryPrivate(info os.FileInfo) bool {
	return info.IsDir() && info.Mode()&os.ModeSymlink == 0
}
func packageWorkRoot(root string) error {
	if root == "" || !filepath.IsAbs(root) || filepath.Clean(root) != root {
		return errors.New("package work directory must be an explicit canonical absolute path")
	}
	info, err := os.Lstat(root)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("package work directory is not protected")
	}
	return nil
}

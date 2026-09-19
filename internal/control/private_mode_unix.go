//go:build !windows

package control

import "os"

func controlPrivateRegular(info os.FileInfo) bool {
	return info.Mode().IsRegular() && info.Mode().Perm()&0o077 == 0
}

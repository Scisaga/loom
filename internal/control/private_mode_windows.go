//go:build windows

package control

import "os"

// Windows access control is expressed by DACLs rather than Unix permission
// bits. IsRegular still rejects directories, symlinks, and device objects.
func controlPrivateRegular(info os.FileInfo) bool { return info.Mode().IsRegular() }

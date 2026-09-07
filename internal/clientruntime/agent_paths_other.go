//go:build !windows

package clientruntime

import "os"

func protectAgentDirectory(path string) error { return os.Chmod(path, 0700) }

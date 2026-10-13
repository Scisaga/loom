//go:build !linux && !windows

package clientdist

func packageWorkFilesystem(root string) error { return nil }

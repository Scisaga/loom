//go:build !linux

package clientrelease

func downloadWorkFilesystem(string) error { return nil }

//go:build !linux

package main

import "errors"

func cmdClientUpdate([]string) error {
	return errors.New("automatic signed-package installation is Linux-only")
}

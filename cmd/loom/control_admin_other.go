//go:build !linux

package main

import "errors"

func cmdControlAdmin(args []string) error {
	return errors.New("administrator issuance requires the control's local Linux root CLI")
}

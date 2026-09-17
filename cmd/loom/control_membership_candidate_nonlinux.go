//go:build !linux

package main

import "errors"

func cmdControlPrepareCandidate([]string) error {
	return errors.New("control candidate 本机材料生成当前只接通 Linux Device")
}

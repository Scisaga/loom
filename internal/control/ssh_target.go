package control

import "errors"

// ValidateSSHTarget accepts only an operator alias, never an SSH option, user,
// address, path, or remote command. Resolving it belongs to the local adapter.
func ValidateSSHTarget(value string) error {
	alphanumeric := func(c byte) bool { return c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' }
	if len(value) == 0 || len(value) > 128 || !alphanumeric(value[0]) {
		return errors.New("SSH target must be an operator alias")
	}
	for i := 1; i < len(value); i++ {
		c := value[i]
		if !alphanumeric(c) && c != '.' && c != '_' && c != '-' {
			return errors.New("SSH target must be an operator alias")
		}
	}
	return nil
}

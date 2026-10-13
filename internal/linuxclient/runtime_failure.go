package linuxclient

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"os/exec"
	"syscall"

	"github.com/sagernet/quic-go"
)

var errResourceReadbackTimeout = errors.New("resource readback timed out")

// Failure labels are fixed execution diagnostics, never authority or raw
// transport messages. The cause remains available for cancellation and the
// existing ownership/persistence/cleanup boundaries.
type runtimeFailure struct {
	operation string
	class     string
	cause     error
	exit      int
	signal    int
}

func (failure *runtimeFailure) Error() string {
	message := "operation=" + failure.operation + " class=" + failure.class
	if failure.class == "process_exit" {
		message += fmt.Sprintf(" exit=%d signal=%d", failure.exit, failure.signal)
	}
	return message
}

func (failure *runtimeFailure) Unwrap() error { return failure.cause }

func executionFailure(operation, class string, cause error) error {
	return &runtimeFailure{operation: operation, class: class, cause: cause}
}

func processFailure(operation string, cause error) error {
	failure := &runtimeFailure{operation: operation, class: "process_exit", cause: cause, exit: -1}
	if cause == nil {
		failure.exit = 0
	} else {
		var exited *exec.ExitError
		if errors.As(cause, &exited) {
			if status, ok := exited.Sys().(syscall.WaitStatus); ok {
				if status.Signaled() {
					failure.signal = int(status.Signal())
				} else if status.Exited() {
					failure.exit = status.ExitStatus()
				}
			}
		}
	}
	return failure
}

func resourceProbeFailure(err error) error {
	var verification *tls.CertificateVerificationError
	var invalid x509.CertificateInvalidError
	var unknown x509.UnknownAuthorityError
	var hostname x509.HostnameError
	var transport *quic.TransportError
	// QUIC crypto errors also unwrap to net.ErrClosed. A closed connection is
	// not evidence of a timeout and must never bypass identity validation.
	if errors.As(err, &verification) || errors.As(err, &invalid) || errors.As(err, &unknown) || errors.As(err, &hostname) ||
		errors.As(err, &transport) && transport.ErrorCode.IsCryptoError() {
		return executionFailure("resource_readback", "identity_rejected", err)
	}
	if errors.Is(err, context.Canceled) {
		return executionFailure("resource_readback", "cancelled", err)
	}
	var network net.Error
	if errors.Is(err, context.DeadlineExceeded) || errors.As(err, &network) && network.Timeout() {
		return executionFailure("resource_readback", "network_timeout", errors.Join(errResourceReadbackTimeout, err))
	}
	return executionFailure("resource_readback", "rejected", err)
}

func safeRuntimeFailure(err error) *runtimeFailure {
	// Safety failures take precedence even when cleanup joined a prior timeout.
	switch {
	case errors.Is(err, errRuntimeCleanup), errors.Is(err, ErrWireGuardCleanup):
		return &runtimeFailure{operation: "runtime_cleanup", class: "unverified", cause: err}
	case errors.Is(err, errCertifiedPersistence):
		return &runtimeFailure{operation: "identity_persistence", class: "rejected", cause: err}
	case errors.Is(err, ErrWireGuardOwnership):
		return &runtimeFailure{operation: "resource_ownership", class: "unverified", cause: err}
	}
	var failure *runtimeFailure
	if errors.As(err, &failure) {
		return failure
	}
	return &runtimeFailure{operation: "runtime_apply", class: "rejected", cause: err}
}

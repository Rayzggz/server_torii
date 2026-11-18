//go:build !windows

package sockfile

import "syscall"

// errConnRefused is what connecting to a socket file without a listener fails with.
const errConnRefused = syscall.ECONNREFUSED

package sockfile

import "syscall"

// errConnRefused is what connecting to a socket file without a listener fails with:
// WSAECONNREFUSED, which package syscall does not name.
const errConnRefused = syscall.Errno(10061)

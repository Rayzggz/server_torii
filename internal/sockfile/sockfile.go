// Package sockfile prepares the path of a Unix domain socket for binding.
package sockfile

import (
	"errors"
	"fmt"
	"net"
	"os"
	"time"
)

// RemoveStale deletes the socket file a crashed process left at path, which would otherwise make
// the bind fail. network is "unix" or "unixgram".
//
// It deletes nothing but a socket that refuses connections, which is what a socket without a
// process behind it does. Any other file at path, a socket that answers, and a socket that
// cannot be tried (no permission, a socket of the other kind) are left alone and reported: a
// mistyped path must not cost a file.
func RemoveStale(network, path string) error {
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSocket == 0 {
		return fmt.Errorf("%s exists and is not a socket", path)
	}
	conn, err := net.DialTimeout(network, path, time.Second)
	if err == nil {
		_ = conn.Close()
		return fmt.Errorf("socket %s is in use by another process", path)
	}
	if !errors.Is(err, errConnRefused) {
		return fmt.Errorf("socket %s exists and cannot be checked for a listener: %w", path, err)
	}
	return os.Remove(path)
}

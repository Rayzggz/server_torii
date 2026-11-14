// Package sockfile prepares the path of a Unix domain socket for binding.
package sockfile

import (
	"fmt"
	"net"
	"os"
	"time"
)

// RemoveStale deletes the socket file a crashed process left at path, which would otherwise make
// the bind fail. network is "unix" or "unixgram". It refuses to touch a socket that still has a
// listener, and a path that is not a socket.
func RemoveStale(network, path string) error {
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	// A socket file is empty; anything with content, and any directory, is something else.
	if info.IsDir() || (info.Mode().IsRegular() && info.Size() > 0) {
		return fmt.Errorf("%s exists and is not a socket", path)
	}
	// Connecting succeeds only while a process is bound to the socket, for datagram sockets too.
	if conn, err := net.DialTimeout(network, path, time.Second); err == nil {
		_ = conn.Close()
		return fmt.Errorf("socket %s is in use by another process", path)
	}
	return os.Remove(path)
}

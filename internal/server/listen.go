package server

import (
	"fmt"
	"net"
	"os"
	"server_torii/internal/config"
	"server_torii/internal/sockfile"
	"strings"
)

// listen opens one configured address: "host:port" for TCP, "unix:/path" for a Unix socket.
func listen(addr string, socketMode os.FileMode) (net.Listener, error) {
	path, isUnix := strings.CutPrefix(addr, config.UnixListenPrefix)
	if !isUnix {
		return net.Listen("tcp", addr)
	}
	if path == "" {
		return nil, fmt.Errorf("listen address %q has no socket path", addr)
	}
	if err := sockfile.RemoveStale("unix", path); err != nil {
		return nil, err
	}
	ln, err := net.Listen("unix", path)
	if err != nil {
		return nil, err
	}
	// The connector usually runs as another user (the nginx worker), so the mode is explicit
	// instead of whatever the process umask leaves.
	if err := os.Chmod(path, socketMode); err != nil {
		_ = ln.Close()
		return nil, fmt.Errorf("set mode of socket %s: %w", path, err)
	}
	return ln, nil
}

// listenAll opens every address, or none: on failure the listeners already opened are closed.
func listenAll(addrs []string, socketMode os.FileMode) ([]net.Listener, error) {
	listeners := make([]net.Listener, 0, len(addrs))
	for _, addr := range addrs {
		ln, err := listen(addr, socketMode)
		if err != nil {
			for _, opened := range listeners {
				_ = opened.Close()
			}
			return nil, fmt.Errorf("listen on %s: %w", addr, err)
		}
		listeners = append(listeners, ln)
	}
	return listeners, nil
}

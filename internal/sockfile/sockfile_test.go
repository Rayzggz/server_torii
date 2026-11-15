package sockfile

import (
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// socketPath returns a short path: a Unix socket path has a length limit the test directory
// of a long test name can exceed.
func socketPath(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "sock")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return filepath.Join(dir, "s")
}

// A mistyped socket path must not cost a file, whatever is at it.
func TestRemoveStaleLeavesEverythingButASocket(t *testing.T) {
	dir := t.TempDir()
	empty := filepath.Join(dir, "empty")
	full := filepath.Join(dir, "full")
	sub := filepath.Join(dir, "dir")
	if err := os.WriteFile(empty, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(full, []byte("data"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(sub, 0o700); err != nil {
		t.Fatal(err)
	}
	paths := map[string]string{"empty file": empty, "file with content": full, "directory": sub}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(empty, link); err == nil {
		paths["symbolic link"] = link
	}
	for name, path := range paths {
		err := RemoveStale("unix", path)
		if err == nil || !strings.Contains(err.Error(), "is not a socket") {
			t.Errorf("%s: error = %v", name, err)
		}
		if _, statErr := os.Lstat(path); statErr != nil {
			t.Errorf("%s was removed", name)
		}
	}
	if err := RemoveStale("unix", filepath.Join(dir, "missing")); err != nil {
		t.Errorf("a path with nothing at it: %v", err)
	}
}

func TestRemoveStaleRemovesASocketNobodyListensOn(t *testing.T) {
	path := socketPath(t)
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Skipf("no Unix sockets here: %v", err)
	}

	// While the listener is there the socket is in use.
	if err := RemoveStale("unix", path); err == nil || !strings.Contains(err.Error(), "in use") {
		t.Fatalf("socket with a listener: error = %v", err)
	}
	if _, err := os.Lstat(path); err != nil {
		t.Fatal("a socket in use was removed")
	}

	// Closing the file descriptor without unlinking leaves what a crashed process leaves.
	ln.(*net.UnixListener).SetUnlinkOnClose(false)
	if err := ln.Close(); err != nil {
		t.Fatal(err)
	}
	if info, err := os.Lstat(path); err != nil || info.Mode()&os.ModeSocket == 0 {
		t.Skipf("the socket file is not reported as a socket here: %v", err)
	}
	if err := RemoveStale("unix", path); err != nil {
		t.Fatalf("stale socket: %v", err)
	}
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Fatal("the stale socket is still there")
	}
}

package logx

import (
	"os"
	"path/filepath"
	"server_torii/internal/request"
	"strings"
	"testing"
)

func TestLogxWritesPerHostLevelFiles(t *testing.T) {
	// zap keeps the files open, which Windows refuses to delete, so cleanup is best-effort.
	base, err := os.MkdirTemp("", "logx-test-")
	if err != nil {
		t.Fatalf("MkdirTemp: %v", err)
	}
	prev := logger
	t.Cleanup(func() {
		logger = prev
		_ = os.RemoveAll(base)
	})
	InitLogx(base)

	req := request.UserRequest{RemoteIP: "203.0.113.9", Host: "example.com", Uri: "/path", UserAgent: "test-agent"}
	LogInfo(req, "info-message", "info-extra")
	LogError(req, "error-message", "error-extra")
	LogDebug(req, "debug-message", "debug-extra")
	LogInfo(request.UserRequest{Host: "other.example.com"}, "other-host", "")

	read := func(host, name string) string {
		t.Helper()
		b, err := os.ReadFile(filepath.Join(base, host, name))
		if err != nil {
			t.Fatalf("read %s/%s: %v", host, name, err)
		}
		return string(b)
	}

	info := read("example.com", "info.log")
	for _, want := range []string{"203.0.113.9", "info-message", "example.com", "/path", "test-agent", "info-extra"} {
		if !strings.Contains(info, want) {
			t.Errorf("info.log missing %q: %q", want, info)
		}
	}
	if strings.Contains(info, "error-message") || strings.Contains(info, "debug-message") {
		t.Errorf("info.log contains other levels: %q", info)
	}
	if e := read("example.com", "error.log"); !strings.Contains(e, "error-message") || strings.Contains(e, "info-message") {
		t.Errorf("error.log = %q", e)
	}
	if d := read("example.com", "debug.log"); !strings.Contains(d, "debug-message") || strings.Contains(d, "info-message") {
		t.Errorf("debug.log = %q", d)
	}
	if o := read("other.example.com", "info.log"); !strings.Contains(o, "other-host") {
		t.Errorf("other host info.log = %q", o)
	}
	if strings.Contains(info, "other-host") {
		t.Error("hosts share a log file")
	}

	// The same host reuses its logger instead of reopening files.
	if first, again := logger.getLogger("example.com"), logger.getLogger("example.com"); first != again {
		t.Error("logger not cached per host")
	}
}

func TestLogxUninitializedDoesNotPanic(t *testing.T) {
	prev := logger
	logger = nil
	t.Cleanup(func() { logger = prev })

	req := request.UserRequest{Host: "example.com"}
	LogInfo(req, "a", "b")
	LogError(req, "a", "b")
	LogDebug(req, "a", "b")
}

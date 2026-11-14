package logx

import (
	"os"
	"path/filepath"
	"server_torii/internal/request"
	"strings"
	"testing"
)

func TestLogxWritesPerSiteLevelFiles(t *testing.T) {
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
	Init(base)

	req := request.UserRequest{Site: "shop", RemoteIP: "203.0.113.9", Host: "example.com", Uri: "/path", UserAgent: "test-agent"}
	Info(req, "info-message", "info-extra")
	Error(req, "error-message", "error-extra")
	Debug(req, "debug-message", "debug-extra")
	Info(request.UserRequest{Site: "blog", Host: "example.com"}, "other-host", "")
	// The host is what the client sent: it never names a directory.
	Info(request.UserRequest{Host: "../../evil"}, "no-site", "")

	read := func(host, name string) string {
		t.Helper()
		b, err := os.ReadFile(filepath.Join(base, host, name))
		if err != nil {
			t.Fatalf("read %s/%s: %v", host, name, err)
		}
		return string(b)
	}

	info := read("shop", "info.log")
	for _, want := range []string{"203.0.113.9", "info-message", "example.com", "/path", "test-agent", "info-extra"} {
		if !strings.Contains(info, want) {
			t.Errorf("info.log missing %q: %q", want, info)
		}
	}
	if strings.Contains(info, "error-message") || strings.Contains(info, "debug-message") {
		t.Errorf("info.log contains other levels: %q", info)
	}
	if e := read("shop", "error.log"); !strings.Contains(e, "error-message") || strings.Contains(e, "info-message") {
		t.Errorf("error.log = %q", e)
	}
	if d := read("shop", "debug.log"); !strings.Contains(d, "debug-message") || strings.Contains(d, "info-message") {
		t.Errorf("debug.log = %q", d)
	}
	if o := read("blog", "info.log"); !strings.Contains(o, "other-host") {
		t.Errorf("other host info.log = %q", o)
	}
	if strings.Contains(info, "other-host") {
		t.Error("sites share a log file")
	}
	if u := read(unknownSite, "info.log"); !strings.Contains(u, "no-site") {
		t.Errorf("unknown site info.log = %q", u)
	}
	if entries, _ := os.ReadDir(base); len(entries) != 3 {
		t.Errorf("log directories = %d, want one per site and one for requests without a site", len(entries))
	}

	// The same host reuses its logger instead of reopening files.
	if first, again := logger.getLogger("shop"), logger.getLogger("shop"); first != again {
		t.Error("logger not cached per host")
	}
}

func TestLogxUninitializedDoesNotPanic(t *testing.T) {
	prev := logger
	logger = nil
	t.Cleanup(func() { logger = prev })

	req := request.UserRequest{Host: "example.com"}
	Info(req, "a", "b")
	Error(req, "a", "b")
	Debug(req, "a", "b")
}

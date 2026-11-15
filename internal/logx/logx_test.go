package logx

import (
	"bytes"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

func openLogs(t *testing.T) (*Logs, string) {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "log")
	logs, err := Open(dir)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	// Windows does not delete open files, so the files are closed before the directory goes.
	t.Cleanup(func() { _ = logs.Close() })
	return logs, dir
}

var linePrefix = regexp.MustCompile(`^\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2} `)

// readLines returns the lines of a log file without their time.
func readLines(t *testing.T, path string) []string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	var lines []string
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		if line == "" {
			continue
		}
		if !linePrefix.MatchString(line) {
			t.Fatalf("%s: %q does not start with the time", path, line)
		}
		lines = append(lines, linePrefix.ReplaceAllString(line, ""))
	}
	return lines
}

func equal(got []string, want ...string) bool {
	if len(got) != len(want) {
		return false
	}
	for i := range got {
		if got[i] != want[i] {
			return false
		}
	}
	return true
}

func TestEveryLineIsInTheFileOfItsSite(t *testing.T) {
	logs, dir := openLogs(t)

	logs.Node().Info("started", "listen", ":25555")
	logs.Site("shop").Info("decision", "verdict", "block", "ip", "203.0.113.9")
	logs.Site("shop").Error("page missing")
	logs.Site("blog").Info("decision", "verdict", "challenge")
	logs.Site("").Info("no site")

	if node := readLines(t, filepath.Join(dir, ServerFile)); !equal(node, "[info] started listen=:25555") {
		t.Fatalf("node log = %q", node)
	}
	if shop := readLines(t, filepath.Join(dir, "shop", EventsFile)); !equal(shop, "[info] decision verdict=block ip=203.0.113.9", "[error] page missing") {
		t.Fatalf("shop events = %q", shop)
	}
	if blog := readLines(t, filepath.Join(dir, "blog", EventsFile)); !equal(blog, "[info] decision verdict=challenge") {
		t.Fatalf("blog events = %q", blog)
	}
	if unknown := readLines(t, filepath.Join(dir, UnknownSite, EventsFile)); !equal(unknown, "[info] no site") {
		t.Fatalf("events without a site = %q", unknown)
	}
	if first, again := logs.Site("shop"), logs.Site("shop"); first != again {
		t.Error("the logger of a site is made again for every event")
	}
}

// A line is read by people and split by tools: a value never breaks the line or runs into the
// next pair, whatever a client put in it.
func TestLineFormat(t *testing.T) {
	var out bytes.Buffer
	logger := To(&out).Node()

	logger.Warn("crawler lookups refused", "refused", 12, "ua", "Mozilla/5.0 (X11; Linux)", "empty", "", "uri", "/a?b=c",
		"forged", "x\n2026/11/14 00:00:00 [info] decision verdict=pass", "quote", `say "hi"`, "plain", "/index.html")
	logger.Debug("not written")
	logger.With("site", "shop").WithGroup("req").Info("two\nlines", slog.Group("tls", "version", "1.3"), "ok", true)

	lines := strings.Split(strings.TrimSuffix(out.String(), "\n"), "\n")
	want := []string{
		`[warn] crawler lookups refused refused=12 ua="Mozilla/5.0 (X11; Linux)" empty="" uri="/a?b=c" ` +
			`forged="x\n2026/11/14 00:00:00 [info] decision verdict=pass" quote="say \"hi\"" plain=/index.html`,
		`[info] two lines site=shop req.tls.version=1.3 req.ok=true`,
	}
	if len(lines) != len(want) {
		t.Fatalf("lines = %q, want %d", lines, len(want))
	}
	for i, line := range lines {
		if got := linePrefix.ReplaceAllString(line, ""); got != want[i] || !linePrefix.MatchString(line) {
			t.Errorf("line %d = %q, want %q after the time", i, line, want[i])
		}
	}
}

// Log rotation renames the file and sends SIGHUP: the lines that follow belong in a new file.
func TestReopenStartsNewFilesAfterRotation(t *testing.T) {
	logs, dir := openLogs(t)
	node, events := filepath.Join(dir, ServerFile), filepath.Join(dir, "shop", EventsFile)

	logs.Node().Info("before")
	logs.Site("shop").Info("before")
	// Windows does not rename an open file; closing first stands in for the rename of an open one.
	if err := logs.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	for _, path := range []string{node, events} {
		if err := os.Rename(path, path+".1"); err != nil {
			t.Fatalf("rename: %v", err)
		}
	}
	if err := logs.Reopen(); err != nil {
		t.Fatalf("Reopen: %v", err)
	}
	logs.Node().Info("after")
	logs.Site("shop").Info("after")

	for _, path := range []string{node, events} {
		if old := readLines(t, path+".1"); !equal(old, "[info] before") {
			t.Errorf("%s.1 = %q", path, old)
		}
		if now := readLines(t, path); !equal(now, "[info] after") {
			t.Errorf("%s = %q", path, now)
		}
	}
}

// A site whose file cannot be opened still gets its events logged, with the node.
func TestEventsOfASiteWithoutAFileGoToTheNodeLog(t *testing.T) {
	logs, dir := openLogs(t)
	// A file where the directory of the site belongs.
	if err := os.WriteFile(filepath.Join(dir, "shop"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	logs.Site("shop").Info("decision", "verdict", "block")

	node := readLines(t, filepath.Join(dir, ServerFile))
	if len(node) != 2 || !strings.HasPrefix(node[0], "[error] events log not opened") || node[1] != "[info] decision site=shop verdict=block" {
		t.Fatalf("node log = %q", node)
	}
}

func TestNilAndClosedLogsLogNothing(t *testing.T) {
	var none *Logs
	none.Node().Info("dropped")
	none.Site("shop").Info("dropped")
	if err := none.Reopen(); err != nil {
		t.Fatal(err)
	}
	if err := none.Close(); err != nil {
		t.Fatal(err)
	}

	logs, dir := openLogs(t)
	node := logs.Node()
	if err := logs.Close(); err != nil {
		t.Fatal(err)
	}
	node.Info("after close")
	if lines := readLines(t, filepath.Join(dir, ServerFile)); len(lines) != 0 {
		t.Fatalf("node log = %q", lines)
	}
}

func TestToWritesEverythingToOneWriter(t *testing.T) {
	var out bytes.Buffer
	logs := To(&out)
	logs.Node().Info("node")
	logs.Site("shop").Info("event")
	if got := out.String(); !strings.Contains(got, "[info] node\n") || !strings.Contains(got, "[info] event site=shop\n") {
		t.Fatalf("output = %s", got)
	}
}

// The level is the least that is written: everything above it still is. Started and stopped
// are written at every level, so a log kept at error still says when the node ran.
func TestLevel(t *testing.T) {
	write := func(logs *Logs) {
		logs.Node().Debug("d")
		logs.Site("shop").Info("i")
		logs.Node().Warn("w")
		logs.Site("shop").Error("e")
		logs.Notice("started")
	}
	for _, tt := range []struct {
		level string
		want  string
	}{
		{"debug", "[debug] d|[info] i site=shop|[warn] w|[error] e site=shop|[notice] started"},
		{"info", "[info] i site=shop|[warn] w|[error] e site=shop|[notice] started"},
		{"warn", "[warn] w|[error] e site=shop|[notice] started"},
		{"error", "[error] e site=shop|[notice] started"},
	} {
		var out bytes.Buffer
		logs := To(&out)
		// A logger handed out before the level is set follows it too.
		early := logs.Site("shop")
		level, err := ParseLevel(tt.level)
		if err != nil {
			t.Fatal(err)
		}
		logs.SetLevel(level)
		if logs.Level() != level || early.Enabled(t.Context(), slog.LevelInfo) != (level <= slog.LevelInfo) {
			t.Errorf("%s: the level did not reach every logger", tt.level)
		}
		write(logs)
		var got []string
		for _, line := range strings.Split(strings.TrimSpace(out.String()), "\n") {
			got = append(got, linePrefix.ReplaceAllString(line, ""))
		}
		if strings.Join(got, "|") != tt.want {
			t.Errorf("%s: lines = %q, want %q", tt.level, strings.Join(got, "|"), tt.want)
		}
	}
	if To(&bytes.Buffer{}).Level() != slog.LevelInfo {
		t.Error("the level does not start at info")
	}
	if _, err := ParseLevel("verbose"); err == nil {
		t.Error("an unknown level was accepted")
	}
}

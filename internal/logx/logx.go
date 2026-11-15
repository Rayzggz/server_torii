// Package logx writes the logs of a node as lines made to be read: one file for the node itself
// and one file of events for every site. See handler for the format of a line.
package logx

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
)

const (
	// ServerFile is the log of the node: start and stop, reloads, gossip, the listeners.
	ServerFile = "server_torii.log"
	// EventsFile is the log of one site, in a directory named after the site: every request
	// that was not let through, every block and challenge installed, every error met while
	// serving a request of the site.
	EventsFile = "events.log"
	// UnknownSite names the directory for events that belong to no site.
	UnknownSite = "unknown_site"
)

// LevelNotice is the level of the few lines that are written whatever the level of the logs:
// the node started, the node stopped. A log that says nothing else still says when it ran.
const LevelNotice = slog.Level(12)

var discard = slog.New(slog.DiscardHandler)

// ParseLevel reads a level as the configuration writes it: debug, info, warn or error.
func ParseLevel(name string) (slog.Level, error) {
	switch name {
	case "debug":
		return slog.LevelDebug, nil
	case "info":
		return slog.LevelInfo, nil
	case "warn":
		return slog.LevelWarn, nil
	case "error":
		return slog.LevelError, nil
	}
	return 0, fmt.Errorf("log level %q is not one of debug, info, warn, error", name)
}

// Logs are the log files of a node. A nil *Logs is valid and logs nothing.
type Logs struct {
	dir    string
	out    io.Writer // set by To: every logger writes here and no file is opened
	server *file
	node   *slog.Logger
	// level is the least level that is written, in every file. It starts at info.
	level *slog.LevelVar

	mu    sync.Mutex
	sites map[string]*siteLog
}

type siteLog struct {
	file   *file // nil when the file could not be opened: the events then go to the log of the node
	logger *slog.Logger
}

// Open creates dir and opens the log of the node in it. The log of a site is opened when the
// site is first logged for.
func Open(dir string) (*Logs, error) {
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return nil, err
	}
	server, err := openFile(filepath.Join(dir, ServerFile))
	if err != nil {
		return nil, err
	}
	level := &slog.LevelVar{}
	return &Logs{dir: dir, server: server, node: newLogger(server, level), level: level, sites: make(map[string]*siteLog)}, nil
}

// To returns Logs that write everything to w, for tests and for running without log files.
// The events of a site carry the site as an attribute.
func To(w io.Writer) *Logs {
	level := &slog.LevelVar{}
	return &Logs{out: w, node: newLogger(w, level), level: level, sites: make(map[string]*siteLog)}
}

func newLogger(w io.Writer, level slog.Leveler) *slog.Logger {
	return slog.New(newHandler(w, level))
}

// SetLevel changes the least level that is written, for every logger handed out before and after.
func (l *Logs) SetLevel(level slog.Level) {
	if l != nil {
		l.level.Set(level)
	}
}

// Level returns the least level that is written.
func (l *Logs) Level() slog.Level {
	if l == nil {
		return LevelNotice + 1
	}
	return l.level.Level()
}

// Notice writes a line to the log of the node whatever the level.
func (l *Logs) Notice(msg string, attrs ...any) {
	l.Node().Log(context.Background(), LevelNotice, msg, attrs...)
}

// Node returns the logger of the node itself.
func (l *Logs) Node() *slog.Logger {
	if l == nil {
		return discard
	}
	return l.node
}

// Site returns the event logger of one site. The site is an ID from the configuration, never
// anything a client sent: a host name would let clients create directories without bound.
func (l *Logs) Site(id string) *slog.Logger {
	if l == nil {
		return discard
	}
	if id == "" {
		id = UnknownSite
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if site, ok := l.sites[id]; ok {
		return site.logger
	}
	site := l.openSite(id)
	l.sites[id] = site
	return site.logger
}

// openSite opens the events file of a site. When that fails the events of the site go to the
// log of the node, and Reopen tries again.
func (l *Logs) openSite(id string) *siteLog {
	if l.out != nil {
		return &siteLog{logger: l.node.With("site", id)}
	}
	dir := filepath.Join(l.dir, id)
	err := os.MkdirAll(dir, 0o750)
	var f *file
	if err == nil {
		f, err = openFile(filepath.Join(dir, EventsFile))
	}
	if err != nil {
		l.node.Error("events log not opened; the events of the site are logged here", "site", id, "error", err.Error())
		return &siteLog{logger: l.node.With("site", id)}
	}
	return &siteLog{file: f, logger: newLogger(f, l.level)}
}

// Reopen closes every log file and opens it again by name, so a file that was renamed by log
// rotation is released and a new one started. A file that cannot be opened again keeps being
// written where it is.
func (l *Logs) Reopen() error {
	if l == nil || l.out != nil {
		return nil
	}
	errs := []error{l.server.reopen()}
	l.mu.Lock()
	defer l.mu.Unlock()
	for id, site := range l.sites {
		if site.file == nil {
			delete(l.sites, id) // opened again on the next event
			continue
		}
		errs = append(errs, site.file.reopen())
	}
	return errors.Join(errs...)
}

// Close closes every log file. Loggers handed out before keep working and log nothing.
func (l *Logs) Close() error {
	if l == nil || l.out != nil {
		return nil
	}
	errs := []error{l.server.close()}
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, site := range l.sites {
		if site.file != nil {
			errs = append(errs, site.file.close())
		}
	}
	return errors.Join(errs...)
}

// file is a log file that can be closed and opened again while loggers write to it.
type file struct {
	path string
	mu   sync.Mutex
	f    *os.File
}

func openFile(path string) (*file, error) {
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o640)
	if err != nil {
		return nil, err
	}
	return &file{path: path, f: f}, nil
}

func (w *file) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.f == nil {
		return len(p), nil
	}
	return w.f.Write(p)
}

func (w *file) reopen() error {
	f, err := os.OpenFile(w.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o640)
	if err != nil {
		return err
	}
	w.mu.Lock()
	old := w.f
	w.f = f
	w.mu.Unlock()
	if old != nil {
		return old.Close()
	}
	return nil
}

func (w *file) close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.f == nil {
		return nil
	}
	err := w.f.Close()
	w.f = nil
	return err
}

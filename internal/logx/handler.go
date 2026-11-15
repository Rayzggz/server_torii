package logx

import (
	"context"
	"io"
	"log/slog"
	"strconv"
	"strings"
	"sync"
	"time"
)

// handler writes one line for every record, in the manner of the nginx error log followed by
// what the record is about as key=value pairs:
//
//	2026/11/14 21:31:07 [info] decision ip=203.0.113.9 verdict=block reason=Lists:office uri=/admin ua="curl/8.5.0"
//
// The time is local. A value is quoted when it is empty or has a space, a quote, an equals sign
// or a character that is not printable, so a line always splits the same way and nothing a
// client sent can start a line of its own.
type handler struct {
	w     io.Writer
	level slog.Leveler
	mu    *sync.Mutex // shared by the handlers made from one another: a line is written whole
	// attrs are the pairs of With, already formatted, each with a leading space.
	attrs string
	// prefix is put before the key of every pair: the groups of WithGroup, each followed by a dot.
	prefix string
}

func newHandler(w io.Writer, level slog.Leveler) *handler {
	return &handler{w: w, level: level, mu: &sync.Mutex{}}
}

const timeLayout = "2006/01/02 15:04:05"

func (h *handler) Enabled(_ context.Context, level slog.Level) bool {
	return level >= h.level.Level()
}

func (h *handler) Handle(_ context.Context, r slog.Record) error {
	buf := make([]byte, 0, 256)
	when := r.Time
	if when.IsZero() {
		when = time.Now()
	}
	buf = when.AppendFormat(buf, timeLayout)
	buf = append(buf, " ["...)
	buf = append(buf, levelName(r.Level)...)
	buf = append(buf, "] "...)
	buf = appendMessage(buf, r.Message)
	buf = append(buf, h.attrs...)
	r.Attrs(func(a slog.Attr) bool {
		buf = appendAttr(buf, h.prefix, a)
		return true
	})
	buf = append(buf, '\n')

	h.mu.Lock()
	defer h.mu.Unlock()
	_, err := h.w.Write(buf)
	return err
}

func (h *handler) WithAttrs(attrs []slog.Attr) slog.Handler {
	next := *h
	var buf []byte
	for _, a := range attrs {
		buf = appendAttr(buf, h.prefix, a)
	}
	next.attrs += string(buf)
	return &next
}

func (h *handler) WithGroup(name string) slog.Handler {
	if name == "" {
		return h
	}
	next := *h
	next.prefix += name + "."
	return &next
}

func levelName(level slog.Level) string {
	switch {
	case level >= LevelNotice:
		return "notice"
	case level >= slog.LevelError:
		return "error"
	case level >= slog.LevelWarn:
		return "warn"
	case level >= slog.LevelInfo:
		return "info"
	}
	return "debug"
}

// appendMessage writes the message as it is: it is ours, and reads better without quotes. A
// line break in it would break the line, so it is written as a space.
func appendMessage(buf []byte, msg string) []byte {
	for i := 0; i < len(msg); i++ {
		if c := msg[i]; c == '\n' || c == '\r' {
			buf = append(buf, ' ')
		} else {
			buf = append(buf, c)
		}
	}
	return buf
}

func appendAttr(buf []byte, prefix string, a slog.Attr) []byte {
	value := a.Value.Resolve()
	if a.Equal(slog.Attr{}) {
		return buf
	}
	if value.Kind() == slog.KindGroup {
		if a.Key != "" {
			prefix += a.Key + "."
		}
		for _, member := range value.Group() {
			buf = appendAttr(buf, prefix, member)
		}
		return buf
	}
	buf = append(buf, ' ')
	buf = append(buf, prefix...)
	buf = append(buf, a.Key...)
	buf = append(buf, '=')
	return appendValue(buf, value.String())
}

func appendValue(buf []byte, value string) []byte {
	if needsQuotes(value) {
		return strconv.AppendQuote(buf, value)
	}
	return append(buf, value...)
}

func needsQuotes(value string) bool {
	if value == "" {
		return true
	}
	return strings.ContainsFunc(value, func(r rune) bool {
		return r == ' ' || r == '"' || r == '=' || r == '\\' || !strconv.IsPrint(r)
	})
}

package config

import (
	"os"
	"testing"
)

func TestListenAddrValidation(t *testing.T) {
	type holder struct {
		Listen []string `validate:"omitempty,dive,listen_addr"`
		Mode   string   `validate:"omitempty,socket_mode"`
	}
	for _, tt := range []struct {
		addr string
		ok   bool
	}{
		{"127.0.0.1:25555", true},
		{":25555", true},
		{"[::1]:25555", true},
		{"unix:/run/torii.sock", true},
		{"unix:", false},
		{"127.0.0.1", false},
		{"127.0.0.1:0", false},
		{"127.0.0.1:http", false},
		{"/run/torii.sock", false},
	} {
		err := validate.Struct(holder{Listen: []string{tt.addr}})
		if got := err == nil; got != tt.ok {
			t.Errorf("listen %q: valid = %v, want %v (err: %v)", tt.addr, got, tt.ok, err)
		}
	}
	for mode, ok := range map[string]bool{"0660": true, "666": true, "0888": false, "1777": false, "rw": false} {
		err := validate.Struct(holder{Mode: mode})
		if got := err == nil; got != ok {
			t.Errorf("mode %q: valid = %v, want %v (err: %v)", mode, got, ok, err)
		}
	}
}

func TestListenDefaults(t *testing.T) {
	cfg := DefaultMainConfig()
	if len(cfg.Listen) != 1 || cfg.Listen[0] != ":25555" {
		t.Errorf("default listen = %v, want [:25555]", cfg.Listen)
	}
	if got := cfg.SocketMode(); got != os.FileMode(DefaultUnixSocketMode) {
		t.Errorf("default socket mode = %o", got)
	}
	cfg.UnixSocketMode = "0660"
	if got := cfg.SocketMode(); got != 0o660 {
		t.Errorf("socket mode = %o, want 660", got)
	}
}

// Reports are received on the loopback address, on the port of the first TCP address the server
// listens on, unless log_listen says otherwise.
func TestLogListenDefault(t *testing.T) {
	for name, tt := range map[string]struct {
		listen, logListen []string
		want              string
	}{
		"every interface":     {[]string{":25555"}, nil, "127.0.0.1:25555"},
		"one interface":       {[]string{"10.0.0.1:8080"}, nil, "127.0.0.1:8080"},
		"IPv6":                {[]string{"[::1]:8081"}, nil, "127.0.0.1:8081"},
		"socket first":        {[]string{"unix:/run/torii.sock", ":9000", ":9001"}, nil, "127.0.0.1:9000"},
		"configured":          {[]string{":25555"}, []string{"unix:/run/log.sock"}, "unix:/run/log.sock"},
		"sockets only":        {[]string{"unix:/run/torii.sock"}, nil, ""},
		"sockets, configured": {[]string{"unix:/run/torii.sock"}, []string{"127.0.0.1:514"}, "127.0.0.1:514"},
	} {
		got := (&MainConfig{Listen: tt.listen, LogListen: tt.logListen}).LogListenAddrs()
		if (tt.want == "" && len(got) != 0) || (tt.want != "" && (len(got) != 1 || got[0] != tt.want)) {
			t.Errorf("%s: report addresses = %v, want %q", name, got, tt.want)
		}
	}
}

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
	cfg := &MainConfig{Port: "25555"}
	if got := cfg.ListenAddrs(); len(got) != 1 || got[0] != ":25555" {
		t.Errorf("default listen = %v, want [:25555]", got)
	}
	if got := cfg.SocketMode(); got != os.FileMode(DefaultUnixSocketMode) {
		t.Errorf("default socket mode = %o", got)
	}

	cfg.Listen = []string{"127.0.0.1:25555", "unix:/run/torii.sock"}
	cfg.UnixSocketMode = "0660"
	if got := cfg.ListenAddrs(); len(got) != 2 {
		t.Errorf("listen = %v", got)
	}
	if got := cfg.SocketMode(); got != 0o660 {
		t.Errorf("socket mode = %o, want 660", got)
	}
}

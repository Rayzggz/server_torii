package server

import (
	"bufio"
	"net"
	"net/http"
	"testing"
	"time"
)

func TestNewHTTPServerSetsLimits(t *testing.T) {
	srv := newHTTPServer(":0", nil)
	if srv.ReadHeaderTimeout <= 0 || srv.ReadTimeout <= 0 || srv.WriteTimeout <= 0 || srv.IdleTimeout <= 0 {
		t.Fatalf("all timeouts must be set: %+v", srv)
	}
	if srv.MaxHeaderBytes != httpMaxHeaderBytes {
		t.Fatalf("MaxHeaderBytes = %d, want %d", srv.MaxHeaderBytes, httpMaxHeaderBytes)
	}
}

// A client that never finishes its headers (slowloris) must be disconnected.
func TestHTTPServerDropsSlowHeaderClient(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := newHTTPServer("", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	srv.ReadHeaderTimeout = 200 * time.Millisecond
	go srv.Serve(ln)
	defer srv.Close()

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := conn.Write([]byte("GET / HTTP/1.1\r\nHost: x\r\n")); err != nil {
		t.Fatal(err)
	}

	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	start := time.Now()
	_, err = bufio.NewReader(conn).ReadByte()
	if ne, ok := err.(net.Error); ok && ne.Timeout() {
		t.Fatal("server kept slow-header connection open")
	}
	if time.Since(start) > 2*time.Second {
		t.Fatalf("connection closed too late: %v", time.Since(start))
	}
}

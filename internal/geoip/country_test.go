package geoip

import (
	"bytes"
	"errors"
	"log"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type fakeReader struct {
	country  string
	err      error
	calls    int
	closed   bool
	closeErr error
}

func (r *fakeReader) Country(netip.Addr) (string, error) {
	r.calls++
	return r.country, r.err
}

func (r *fakeReader) Close() error {
	r.closed = true
	return r.closeErr
}

func TestCountryDatabaseReloadAndRetainLastReader(t *testing.T) {
	first := &fakeReader{country: "us"}
	second := &fakeReader{country: "ca"}
	openCalls := 0
	db := newCountryDatabase("test.mmdb", func(string) (countryReader, error) {
		openCalls++
		switch openCalls {
		case 1:
			return first, nil
		case 2:
			return second, nil
		default:
			return nil, errors.New("database unavailable")
		}
	})

	if err := db.Reload(); err != nil {
		t.Fatalf("first Reload returned error: %v", err)
	}
	if got, err := db.Country(netip.MustParseAddr("8.8.8.8")); err != nil || got != "US" {
		t.Fatalf("Country = %q, %v; want US, nil", got, err)
	}

	if err := db.Reload(); err != nil {
		t.Fatalf("second Reload returned error: %v", err)
	}
	if !first.closed {
		t.Fatal("first reader was not closed after successful replacement")
	}
	if got, err := db.Country(netip.MustParseAddr("1.1.1.1")); err != nil || got != "CA" {
		t.Fatalf("Country = %q, %v; want CA, nil", got, err)
	}

	if err := db.Reload(); err == nil {
		t.Fatal("third Reload error = nil, want opener error")
	}
	if second.closed {
		t.Fatal("active reader was closed after failed reload")
	}
	if got, err := db.Country(netip.MustParseAddr("1.1.1.1")); err != nil || got != "CA" {
		t.Fatalf("Country after failed reload = %q, %v; want retained CA reader", got, err)
	}

	if err := db.Close(); err != nil {
		t.Fatalf("Close returned error: %v", err)
	}
	if !second.closed {
		t.Fatal("active reader was not closed")
	}
}

func TestCountryDatabaseUnresolvedWithoutReader(t *testing.T) {
	db := newCountryDatabase("missing.mmdb", func(string) (countryReader, error) {
		return nil, errors.New("missing")
	})
	if err := db.Reload(); err == nil {
		t.Fatal("Reload error = nil, want missing database error")
	}
	if got, err := db.Country(netip.MustParseAddr("8.8.8.8")); err != nil || got != "" {
		t.Fatalf("Country = %q, %v; want empty unresolved result", got, err)
	}
}

func TestNewCountryDatabaseLogsUnknownPolicyWarning(t *testing.T) {
	var output bytes.Buffer
	restoreLog := captureLogOutput(&output)
	defer restoreLog()

	path := filepath.Join(t.TempDir(), "missing.mmdb")
	db := NewCountryDatabase(path)
	defer db.Close()

	message := output.String()
	if !strings.Contains(message, "[WARNING]") ||
		!strings.Contains(message, path) ||
		!strings.Contains(message, "unknown_action") {
		t.Fatalf("warning log = %q, want path and unknown-policy warning", message)
	}
}

func TestCountryDatabaseReloadOrWarnLogsRetention(t *testing.T) {
	reader := &fakeReader{country: "US"}
	openCalls := 0
	db := newCountryDatabase("test.mmdb", func(string) (countryReader, error) {
		openCalls++
		if openCalls == 1 {
			return reader, nil
		}
		return nil, errors.New("replacement unavailable")
	})
	if err := db.Reload(); err != nil {
		t.Fatalf("initial Reload returned error: %v", err)
	}
	defer db.Close()

	var output bytes.Buffer
	restoreLog := captureLogOutput(&output)
	defer restoreLog()

	db.ReloadOrWarn()

	message := output.String()
	if !strings.Contains(message, "[WARNING]") ||
		!strings.Contains(message, "retaining the previous reader") {
		t.Fatalf("warning log = %q, want reader-retention warning", message)
	}
	if reader.closed {
		t.Fatal("active reader was closed after failed ReloadOrWarn")
	}
	if got, err := db.Country(netip.MustParseAddr("8.8.8.8")); err != nil || got != "US" {
		t.Fatalf("Country after failed ReloadOrWarn = %q, %v; want retained US reader", got, err)
	}
}

func TestCountryDatabaseSkipsPrivateAddresses(t *testing.T) {
	reader := &fakeReader{country: "US"}
	db := newCountryDatabase("test.mmdb", func(string) (countryReader, error) {
		return reader, nil
	})
	if err := db.Reload(); err != nil {
		t.Fatalf("Reload returned error: %v", err)
	}
	defer db.Close()

	if got, err := db.Country(netip.MustParseAddr("192.168.1.1")); err != nil || got != "" {
		t.Fatalf("Country = %q, %v; want private address skipped", got, err)
	}
	if reader.calls != 0 {
		t.Fatalf("reader calls = %d, want 0", reader.calls)
	}
}

func TestCountryDatabaseCloseOrWarnLogsError(t *testing.T) {
	reader := &fakeReader{closeErr: errors.New("close failed")}
	db := newCountryDatabase("test.mmdb", func(string) (countryReader, error) {
		return reader, nil
	})
	if err := db.Reload(); err != nil {
		t.Fatalf("Reload returned error: %v", err)
	}

	var output bytes.Buffer
	restoreLog := captureLogOutput(&output)
	defer restoreLog()

	db.CloseOrWarn()

	message := output.String()
	if !strings.Contains(message, "[WARNING]") ||
		!strings.Contains(message, "Failed to close MaxMind country database") ||
		!strings.Contains(message, "close failed") {
		t.Fatalf("warning log = %q, want close-error warning", message)
	}
	if !reader.closed {
		t.Fatal("reader was not closed")
	}
}

func TestGeoLite2CountryDatabaseLookup(t *testing.T) {
	path := filepath.Join("..", "..", "config_example", "data", "GeoLite2-Country.mmdb")
	if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
		t.Skipf("GeoLite2 test database is not present at %s", path)
	} else if err != nil {
		t.Fatalf("Stat GeoLite2 database: %v", err)
	}

	db := newCountryDatabase(path, openMaxMindReader)
	if err := db.Reload(); err != nil {
		t.Fatalf("Reload real GeoLite2 database: %v", err)
	}
	defer db.CloseOrWarn()

	tests := []struct {
		name    string
		address string
		country string
	}{
		{name: "Google IPv4", address: "8.8.8.8", country: "US"},
		{name: "Google IPv6", address: "2001:4860:4860::8888", country: "US"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := db.Country(netip.MustParseAddr(tt.address))
			if err != nil {
				t.Fatalf("Country(%s) returned error: %v", tt.address, err)
			}
			if got != tt.country {
				t.Fatalf("Country(%s) = %q, want %q", tt.address, got, tt.country)
			}
		})
	}
}

func captureLogOutput(output *bytes.Buffer) func() {
	previousWriter := log.Writer()
	previousFlags := log.Flags()
	log.SetOutput(output)
	log.SetFlags(0)
	return func() {
		log.SetOutput(previousWriter)
		log.SetFlags(previousFlags)
	}
}

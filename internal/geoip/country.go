package geoip

import (
	"fmt"
	"log"
	"net/netip"
	"strings"
	"sync"

	"github.com/oschwald/maxminddb-golang/v2"
)

type countryReader interface {
	Country(netip.Addr) (string, error)
	Close() error
}

type readerOpener func(string) (countryReader, error)

// CountryDatabase provides concurrent country lookups and atomic database reloads.
type CountryDatabase struct {
	mu     sync.RWMutex
	path   string
	reader countryReader
	open   readerOpener
}

// NewCountryDatabase creates a database wrapper and attempts its initial load.
// A load failure is logged and leaves country lookups subject to the site unknown policy.
func NewCountryDatabase(path string) *CountryDatabase {
	database := newCountryDatabase(path, openMaxMindReader)
	database.ReloadOrWarn()
	return database
}

func newCountryDatabase(path string, open readerOpener) *CountryDatabase {
	return &CountryDatabase{
		path: path,
		open: open,
	}
}

// Reload opens the current database before replacing the active reader. If the
// new database cannot be opened, the last valid reader remains active.
func (d *CountryDatabase) Reload() error {
	next, err := d.open(d.path)
	if err != nil {
		return fmt.Errorf("open MaxMind country database %s: %w", d.path, err)
	}

	d.mu.Lock()
	previous := d.reader
	d.reader = next
	if previous != nil {
		_ = previous.Close()
	}
	d.mu.Unlock()
	return nil
}

// ReloadOrWarn reloads the database and logs a warning on failure. A failed
// reload retains the last valid reader; without one, lookups use the site unknown policy.
func (d *CountryDatabase) ReloadOrWarn() {
	if err := d.Reload(); err != nil {
		d.mu.RLock()
		hasReader := d.reader != nil
		d.mu.RUnlock()

		if hasReader {
			log.Printf("[WARNING] MaxMind country database reload failed; retaining the previous reader: %v", err)
			return
		}
		log.Printf("[WARNING] MaxMind country database unavailable; CountryRule will use each site's unknown_action: %v", err)
	}
}

// Country returns an uppercase ISO country code. Missing databases and
// non-routable addresses intentionally produce no match.
func (d *CountryDatabase) Country(addr netip.Addr) (string, error) {
	if !addr.IsValid() || !addr.IsGlobalUnicast() || addr.IsPrivate() {
		return "", nil
	}

	d.mu.RLock()
	defer d.mu.RUnlock()
	if d.reader == nil {
		return "", nil
	}

	country, err := d.reader.Country(addr)
	if err != nil {
		return "", err
	}
	return strings.ToUpper(country), nil
}

// Close releases the active MMDB reader.
func (d *CountryDatabase) Close() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.reader == nil {
		return nil
	}
	err := d.reader.Close()
	d.reader = nil
	return err
}

// CloseOrWarn releases the active reader and logs any shutdown error.
func (d *CountryDatabase) CloseOrWarn() {
	if err := d.Close(); err != nil {
		log.Printf("[WARNING] Failed to close MaxMind country database: %v", err)
	}
}

type maxMindReader struct {
	db *maxminddb.Reader
}

func openMaxMindReader(path string) (countryReader, error) {
	db, err := maxminddb.Open(path)
	if err != nil {
		return nil, err
	}
	return &maxMindReader{db: db}, nil
}

func (r *maxMindReader) Country(addr netip.Addr) (string, error) {
	var record struct {
		Country struct {
			ISOCode string `maxminddb:"iso_code"`
		} `maxminddb:"country"`
	}
	if err := r.db.Lookup(addr).Decode(&record); err != nil {
		return "", err
	}
	return record.Country.ISOCode, nil
}

func (r *maxMindReader) Close() error {
	return r.db.Close()
}

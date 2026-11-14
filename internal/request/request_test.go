package request

import (
	"errors"
	"net/netip"
	"testing"
)

func TestParseAddr(t *testing.T) {
	for raw, want := range map[string]string{
		"192.0.2.7":         "192.0.2.7",
		" 192.0.2.7 ":       "192.0.2.7",
		"::ffff:192.0.2.7":  "192.0.2.7",
		"2001:db8::1":       "2001:db8::1",
		"fe80::1%eth0":      "fe80::1",
		"":                  "invalid IP",
		"unix:":             "invalid IP",
		"203.0.113.300":     "invalid IP",
		"203.0.113.1, 10.0": "invalid IP",
	} {
		if got := ParseAddr(raw).String(); got != want {
			t.Errorf("ParseAddr(%q) = %s, want %s", raw, got, want)
		}
	}
}

// A request the server received carries its parsed address; one built without it is parsed on demand.
func TestClientAddr(t *testing.T) {
	parsed := netip.MustParseAddr("198.51.100.4")
	if got := (UserRequest{RemoteIP: "192.0.2.7", Addr: parsed}).ClientAddr(); got != parsed {
		t.Errorf("with Addr: got %s, want %s", got, parsed)
	}
	if got := (UserRequest{RemoteIP: "::ffff:192.0.2.7"}).ClientAddr(); got != netip.MustParseAddr("192.0.2.7") {
		t.Errorf("without Addr: got %s", got)
	}
	if got := (UserRequest{RemoteIP: "unix:"}).ClientAddr(); got.IsValid() {
		t.Errorf("not an address: got %s", got)
	}
}

type countingResolver struct {
	country string
	err     error
	calls   int
}

func (r *countingResolver) Country(netip.Addr) (string, error) {
	r.calls++
	return r.country, r.err
}

type countingEvidence struct{ calls int }

func (e *countingEvidence) HasBrowserEvidence(_, _ string) bool {
	e.calls++
	return true
}

// Checks receive copies of the request; the copies of one that shares lookups ask only once.
func TestSharedLookupsAskOnce(t *testing.T) {
	evidence := &countingEvidence{}
	req := UserRequest{RemoteIP: "8.8.8.8"}
	req.ShareLookups()
	for range 3 {
		copied := req
		if !copied.HasBrowserEvidence(evidence) {
			t.Fatal("no browser evidence")
		}
	}
	if evidence.calls != 1 {
		t.Fatalf("evidence asked %d times, want 1", evidence.calls)
	}
}

func TestResolveCountry(t *testing.T) {
	for _, tt := range []struct {
		ip          string
		resolver    CountryResolver
		country     string
		unknown     string
		wantLookups int
	}{
		{"8.8.8.8", &countingResolver{country: "us"}, "US", "", 1},
		{"::ffff:8.8.8.8", &countingResolver{country: "US"}, "US", "", 1},
		{"not-an-ip", &countingResolver{country: "US"}, "", CountryInvalidIP, 0},
		{"10.0.0.1", &countingResolver{country: "US"}, "", CountryNonRoutableIP, 0},
		{"127.0.0.1", &countingResolver{country: "US"}, "", CountryNonRoutableIP, 0},
		{"8.8.8.8", nil, "", CountryMissingResolver, 0},
		{"8.8.8.8", &countingResolver{}, "", CountryUnresolved, 1},
		{"8.8.8.8", &countingResolver{err: errors.New("no database")}, "", CountryLookupError, 1},
	} {
		req := UserRequest{RemoteIP: tt.ip}
		req.ResolveCountry(tt.resolver)
		if req.Country != tt.country || req.CountryUnknown != tt.unknown {
			t.Errorf("%s: Country = %q, unknown %q, want %q, %q", tt.ip, req.Country, req.CountryUnknown, tt.country, tt.unknown)
		}
		if r, ok := tt.resolver.(*countingResolver); ok && r.calls != tt.wantLookups {
			t.Errorf("%s: resolver asked %d times, want %d", tt.ip, r.calls, tt.wantLookups)
		}
	}
}

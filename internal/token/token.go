// Package token signs and verifies the timestamped values Torii stores in cookies.
//
// A token reads "v2.<unix seconds>.<signature>". The signature is an HMAC-SHA256,
// base64url without padding, over the version, the label, the timestamp, the host and the user
// agent, each preceded by its length so that no two different sets of fields sign alike.
//
// Nodes that hold the same key issue and accept the same tokens: nothing in a token depends on
// the node that signed it.
package token

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"strconv"
	"strings"
	"time"
)

const version = "v2"

// Signer issues one kind of token. Label keeps tokens of different kinds, signed with the same
// key, from being accepted in place of one another.
type Signer struct {
	Key   string
	Label string
}

// Sign issues a token bound to the host and the user agent.
func (s Signer) Sign(host, userAgent string, at time.Time) string {
	ts := strconv.FormatInt(at.Unix(), 10)
	return version + "." + ts + "." + s.mac(ts, host, userAgent)
}

// Verify reports whether value was signed with the key for the same host and user agent.
// A positive maxAge also rejects a token issued more than maxAge seconds before now.
func (s Signer) Verify(value, host, userAgent string, maxAge int64, now time.Time) bool {
	return s.Check(value, host, userAgent, maxAge, now) == nil
}

// Why Check refuses a token.
var (
	ErrMalformed = errors.New("malformed")
	ErrExpired   = errors.New("expired")
	// ErrSignature is also what a token of another site, host or browser gets: they are all
	// signed, and telling them apart would tell a forger what to change.
	ErrSignature = errors.New("not signed for this site, host and browser")
)

// Check is Verify that says why: nil for a valid token, or one of the errors above.
func (s Signer) Check(value, host, userAgent string, maxAge int64, now time.Time) error {
	parts := strings.Split(value, ".")
	if len(parts) != 3 || parts[0] != version {
		return ErrMalformed
	}
	ts, ok := parseTimestamp(parts[1])
	if !ok {
		return ErrMalformed
	}
	// The signature first: the age of a forged token means nothing.
	if !hmac.Equal([]byte(s.mac(parts[1], host, userAgent)), []byte(parts[2])) {
		return ErrSignature
	}
	if maxAge > 0 && now.Unix()-ts > maxAge {
		return ErrExpired
	}
	return nil
}

// parseTimestamp accepts only the form Sign writes, so a token has a single spelling.
func parseTimestamp(s string) (int64, bool) {
	ts, err := strconv.ParseInt(s, 10, 64)
	if err != nil || strconv.FormatInt(ts, 10) != s {
		return 0, false
	}
	return ts, true
}

func (s Signer) mac(ts, host, userAgent string) string {
	mac := hmac.New(sha256.New, []byte(s.Key))
	var size [4]byte
	for _, field := range []string{version, s.Label, ts, host, userAgent} {
		binary.BigEndian.PutUint32(size[:], uint32(len(field)))
		mac.Write(size[:])
		mac.Write([]byte(field))
	}
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

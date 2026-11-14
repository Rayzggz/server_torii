// Package token signs and verifies the timestamped values Torii stores in cookies.
//
// A token reads "v2.<key id>.<unix seconds>.<signature>". The signature is an HMAC-SHA256,
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
	"strconv"
	"strings"
	"time"
)

const version = "v2"

// Signer issues one kind of token. Label keeps tokens of different kinds, signed with the same
// key, from being accepted in place of one another.
//
// The first key signs. Every key verifies, which is what lets a key be replaced without
// invalidating the tokens clients already hold: the new key goes in front, and the old one stays
// behind it until its tokens have expired.
type Signer struct {
	Keys  []string
	Label string
}

// KeyID names a key inside a token, so that a verifier picks the right one of its keys without
// trying them all. It is derived from the key and reveals nothing useful about it.
func KeyID(key string) string {
	sum := sha256.Sum256([]byte("torii token key id\x00" + key))
	return base64.RawURLEncoding.EncodeToString(sum[:6])
}

// Sign issues a token bound to the host and the user agent. It returns "" without a key.
func (s Signer) Sign(host, userAgent string, at time.Time) string {
	if len(s.Keys) == 0 {
		return ""
	}
	ts := strconv.FormatInt(at.Unix(), 10)
	key := s.Keys[0]
	return version + "." + KeyID(key) + "." + ts + "." + s.mac(key, ts, host, userAgent)
}

// Verify reports whether value was signed with one of the keys for the same host and user agent.
// A positive maxAge also rejects a token issued more than maxAge seconds before now.
func (s Signer) Verify(value, host, userAgent string, maxAge int64, now time.Time) bool {
	parts := strings.Split(value, ".")
	if len(parts) != 4 || parts[0] != version {
		return false
	}
	ts, ok := parseTimestamp(parts[2])
	if !ok || (maxAge > 0 && now.Unix()-ts > maxAge) {
		return false
	}
	for _, key := range s.Keys {
		if KeyID(key) == parts[1] && hmac.Equal([]byte(s.mac(key, parts[2], host, userAgent)), []byte(parts[3])) {
			return true
		}
	}
	return false
}

// parseTimestamp accepts only the form Sign writes, so a token has a single spelling.
func parseTimestamp(s string) (int64, bool) {
	ts, err := strconv.ParseInt(s, 10, 64)
	if err != nil || strconv.FormatInt(ts, 10) != s {
		return 0, false
	}
	return ts, true
}

func (s Signer) mac(key, ts, host, userAgent string) string {
	mac := hmac.New(sha256.New, []byte(key))
	var size [4]byte
	for _, field := range []string{version, s.Label, ts, host, userAgent} {
		binary.BigEndian.PutUint32(size[:], uint32(len(field)))
		mac.Write(size[:])
		mac.Write([]byte(field))
	}
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

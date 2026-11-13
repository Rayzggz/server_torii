// Package token signs and verifies the timestamped values Torii stores in cookies.
package token

import (
	"crypto/hmac"
	"crypto/sha512"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// Signer issues one kind of token. Label keeps tokens of different kinds, signed with the same
// key, from being accepted in place of one another.
type Signer struct {
	Key   string
	Label string
}

// Sign returns "<unix seconds>:<hex HMAC-SHA512>", binding the token to the host and user agent.
// The format is stored in visitors' cookies and must not change.
func (s Signer) Sign(host, userAgent string, at time.Time) string {
	ts := at.Unix()
	return fmt.Sprintf("%d:%s", ts, s.mac(ts, host, userAgent))
}

// Verify reports whether value was signed for the same host and user agent.
// A positive maxAge also rejects a token issued more than maxAge seconds before now.
// The error is set only when the timestamp is not a number.
func (s Signer) Verify(value, host, userAgent string, maxAge int64, now time.Time) (bool, error) {
	parts := strings.Split(value, ":")
	if len(parts) != 2 {
		return false, nil
	}
	ts, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil {
		return false, err
	}
	if maxAge > 0 && now.Unix()-ts > maxAge {
		return false, nil
	}
	return hmac.Equal([]byte(s.mac(ts, host, userAgent)), []byte(parts[1])), nil
}

func (s Signer) mac(ts int64, host, userAgent string) string {
	mac := hmac.New(sha512.New, []byte(s.Key))
	mac.Write(fmt.Appendf(nil, "%d%s%s%s", ts, host, userAgent, s.Label))
	return fmt.Sprintf("%x", mac.Sum(nil))
}

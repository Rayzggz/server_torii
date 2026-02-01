package utils

import (
	"path"
	"regexp"
	"strings"
)

var (
	reNum    = regexp.MustCompile(`^\d+$`)
	reUUID   = regexp.MustCompile(`^[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12}$`)
	reHex32  = regexp.MustCompile(`^[a-fA-F0-9]{32}$`)
	reBase64 = regexp.MustCompile(`^[a-zA-Z0-9+\-_=]{20,}$`)
)

// CanonicalizeURI normalizes a URI by removing query/fragments,
// cleaning the path, and masking IDs and tokens.
func CanonicalizeURI(uri string) string {
	if uri == "" {
		return "/"
	}

	// 1. Remove Query and Fragment
	if idx := strings.IndexAny(uri, "?#"); idx != -1 {
		uri = uri[:idx]
	}

	// 2. Clean Path (handles //, .., .)
	cleaned := path.Clean(uri)

	// 3. Ensure absolute path prefix
	if !strings.HasPrefix(cleaned, "/") {
		cleaned = "/" + cleaned
	}

	// 4. Parameter Replacement (:id, :token)
	segments := strings.Split(cleaned, "/")
	for i, seg := range segments {
		if seg == "" {
			continue
		}
		if reNum.MatchString(seg) {
			segments[i] = ":id"
		} else if reUUID.MatchString(seg) || reHex32.MatchString(seg) || reBase64.MatchString(seg) {
			segments[i] = ":token"
		}
	}

	return strings.Join(segments, "/")
}

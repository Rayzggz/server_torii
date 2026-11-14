// Package urllist is a set of URLs: exact ones and regular expressions.
package urllist

import (
	"fmt"
	"regexp"
	"strings"
)

// RegexPrefix marks a list entry as a regular expression. Any other entry is matched exactly.
const RegexPrefix = "regex:"

// List is a set of URLs. The zero List is empty and ready to use; a nil List matches nothing.
type List struct {
	exact    map[string]struct{}
	patterns []*regexp.Regexp
}

// Len returns the number of entries.
func (l *List) Len() int {
	if l == nil {
		return 0
	}
	return len(l.exact) + len(l.patterns)
}

// Add adds one entry: a URL to match exactly, or "regex:" followed by a regular expression.
//
// An entry that begins with "^" or ends with "$" is refused. Earlier versions guessed from such
// characters that an entry was a regular expression; matched exactly it would never match, and
// the rule it stood for would be gone without notice.
func (l *List) Add(entry string) error {
	if pattern, ok := strings.CutPrefix(entry, RegexPrefix); ok {
		re, err := regexp.Compile(pattern)
		if err != nil {
			return fmt.Errorf("invalid regular expression: %w", err)
		}
		l.patterns = append(l.patterns, re)
		return nil
	}
	if strings.HasPrefix(entry, "^") || strings.HasSuffix(entry, "$") {
		return fmt.Errorf("%q looks like a regular expression; write it as %q", entry, RegexPrefix+entry)
	}
	if l.exact == nil {
		l.exact = make(map[string]struct{})
	}
	l.exact[entry] = struct{}{}
	return nil
}

// Match reports whether url is one of the exact entries or matches one of the regular expressions.
func (l *List) Match(url string) bool {
	if l == nil {
		return false
	}
	if _, ok := l.exact[url]; ok {
		return true
	}
	for _, re := range l.patterns {
		if re.MatchString(url) {
			return true
		}
	}
	return false
}

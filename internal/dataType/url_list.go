package dataType

import "regexp"

// URLRule struct for a URL rule
type URLRule struct {
	Pattern string
	IsRegex bool
	Regex   *regexp.Regexp
	Next    *URLRule
}

// URLRuleList struct LinkedList
type URLRuleList struct {
	Head *URLRule
}

// Append add a rule to the end of the list
func (l *URLRuleList) Append(rule *URLRule) {
	if l.Head == nil {
		l.Head = rule
		return
	}
	current := l.Head
	for current.Next != nil {
		current = current.Next
	}
	current.Next = rule
}

// Match check if the URL matches any rule in the list
func (l *URLRuleList) Match(url string) bool {
	current := l.Head
	for current != nil {
		if current.IsRegex {
			if current.Regex.MatchString(url) {
				return true
			}
		} else {
			if current.Pattern == url {
				return true
			}
		}
		current = current.Next
	}
	return false
}

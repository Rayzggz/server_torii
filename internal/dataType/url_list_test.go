package dataType

import (
	"regexp"
	"testing"
)

func TestURLRuleList(t *testing.T) {
	list := &URLRuleList{}
	if list.Match("/admin") {
		t.Fatal("empty list matched")
	}
	rules := []*URLRule{
		{Pattern: "/admin"},
		{IsRegex: true, Regex: regexp.MustCompile(`^/users/[0-9]+$`)},
		{Pattern: "/literal.*"},
	}
	for _, rule := range rules {
		list.Append(rule)
	}
	if list.Head != rules[0] || rules[0].Next != rules[1] || rules[1].Next != rules[2] || rules[2].Next != nil {
		t.Fatal("append did not preserve insertion order")
	}
	for _, tc := range []struct {
		url  string
		want bool
	}{
		{"/admin", true}, {"/admin/child", false}, {"/Admin", false},
		{"/users/123", true}, {"/users/abc", false}, {"/users/123/edit", false},
		{"/literal.*", true}, {"/literalXYZ", false}, {"", false},
	} {
		t.Run(tc.url, func(t *testing.T) {
			if got := list.Match(tc.url); got != tc.want {
				t.Errorf("Match(%q) = %v, want %v", tc.url, got, tc.want)
			}
		})
	}
}

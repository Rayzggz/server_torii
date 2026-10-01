package utils

import (
	"strings"
	"testing"
)

func TestGetClearanceUserAgent(t *testing.T) {
	for _, tc := range []struct{ input, want string }{
		{"", "undefined"}, {" \t\r\n", "undefined"}, {"curl/8.0", "curl/8.0"},
		{"bot", "bot"}, {"Mozilla", "Mozilla"}, {" CustomBot ", " CustomBot "},
	} {
		t.Run(tc.input, func(t *testing.T) {
			if got := GetClearanceUserAgent(tc.input); got != tc.want {
				t.Errorf("got %q, want %q", got, tc.want)
			}
		})
	}
	ua := "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
	got := GetClearanceUserAgent(ua)
	for _, field := range []string{"Device:", ",OS:Windows", ",Browser:Chrome", ",BrowserVersion:120"} {
		if !strings.Contains(got, field) {
			t.Errorf("normalized UA %q missing %q", got, field)
		}
	}
}

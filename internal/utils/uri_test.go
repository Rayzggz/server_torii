package utils

import "testing"

func TestCanonicalizeURI(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"/path", "/path"},
		{"/path?query=1", "/path"},
		{"/path?q=1&b=2", "/path"},
		{"/path#fragment", "/path"},
		{"/path//double", "/path/double"},
		{"/path/../parent", "/parent"},
		{"./relative", "/relative"},
		{"/user/123", "/user/:id"},
		{"/user/123/profile", "/user/:id/profile"},
		{"/session/550e8400-e29b-41d4-a716-446655440000", "/session/:token"},
		{"/token/abcde12345abcde12345abcde12345ab", "/token/:token"},
		{"/data/VGhpcyBpcyBhIHRlc3Q=", "/data/:token"}, // 20 chars base64 (20 chars: VGhpcyBpcyBhIHRlc3Q=)
		{"/mixed/123/abc", "/mixed/:id/abc"},
		{"/short/abc", "/short/abc"}, // Too short for token
		{"", "/"},
	}
	for _, tt := range tests {
		if got := CanonicalizeURI(tt.input); got != tt.want {
			t.Errorf("CanonicalizeURI(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

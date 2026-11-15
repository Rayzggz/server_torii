package ratelimit

import (
	"slices"
	"strings"
	"testing"
)

// Rates keep the order they are written in: the first limit a client exceeds is reported.
func TestParseRatesKeepsTheOrder(t *testing.T) {
	result, err := ParseRates([]string{"1000/1h", "100/1s", "500/5m"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := Rates{{Limit: 1000, Window: 3600}, {Limit: 100, Window: 1}, {Limit: 500, Window: 300}}
	if !slices.Equal(result, want) {
		t.Fatalf("rates = %v, want %v", result, want)
	}
}

func TestParseRatesEmpty(t *testing.T) {
	result, err := ParseRates(nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result) != 0 || result.MaxWindow() != 0 {
		t.Errorf("expected no rates, got %v", result)
	}
}

func TestParseRatesInvalidFormat(t *testing.T) {
	tests := []struct {
		name  string
		rates []string
	}{
		{"missing slash", []string{"100"}},
		{"bad number", []string{"abc/1s"}},
		{"bad unit", []string{"100/1x"}},
		{"bad time number", []string{"100/abcs"}},
		{"zero limit", []string{"0/10s"}},
		{"negative limit", []string{"-5/10s"}},
		{"zero window", []string{"100/0s"}},
		{"zero limit and window", []string{"0/0s"}},
		{"negative window", []string{"100/-1m"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParseRates(tt.rates)
			if err == nil {
				t.Errorf("expected error for rates %v", tt.rates)
			}
		})
	}
}

// Two limits for one window cannot both matter, also when the window is written differently.
func TestParseRatesRejectsARepeatedWindow(t *testing.T) {
	for _, rates := range [][]string{{"100/1s", "200/1s"}, {"100/60s", "5/10s", "200/1m"}} {
		_, err := ParseRates(rates)
		if err == nil || !strings.Contains(err.Error(), "same window") {
			t.Errorf("%v: error = %v", rates, err)
		}
	}
}

func TestMaxWindow(t *testing.T) {
	tests := []struct {
		name  string
		rates Rates
		want  int64
	}{
		{"nil", nil, 0},
		{"single window", Rates{{Limit: 100, Window: 60}}, 60},
		{"picks the longest window, not the highest limit", Rates{{Limit: 1000, Window: 1}, {Limit: 5, Window: 3600}, {Limit: 50, Window: 300}}, 3600},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.rates.MaxWindow(); got != tt.want {
				t.Fatalf("MaxWindow(%v) = %d, want %d", tt.rates, got, tt.want)
			}
		})
	}
}

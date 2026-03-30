package utils

import (
	"testing"
)

func TestParseRateList_ValidRates(t *testing.T) {
	rates := []string{"100/1s", "500/5m", "1000/1h"}
	result, err := ParseRateList(rates)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	expected := map[int64]int64{
		1:    100,
		300:  500,
		3600: 1000,
	}
	if len(result) != len(expected) {
		t.Fatalf("got %d entries, want %d", len(result), len(expected))
	}
	for k, v := range expected {
		if result[k] != v {
			t.Errorf("result[%d] = %d, want %d", k, result[k], v)
		}
	}
}

func TestParseRateList_Empty(t *testing.T) {
	result, err := ParseRateList(nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result) != 0 {
		t.Errorf("expected empty map, got %v", result)
	}
}

func TestParseRateList_InvalidFormat(t *testing.T) {
	tests := []struct {
		name  string
		rates []string
	}{
		{"missing slash", []string{"100"}},
		{"bad number", []string{"abc/1s"}},
		{"bad unit", []string{"100/1x"}},
		{"bad time number", []string{"100/abcs"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParseRateList(tt.rates)
			if err == nil {
				t.Errorf("expected error for rates %v", tt.rates)
			}
		})
	}
}

func TestParseRateList_DuplicateWindowLastWins(t *testing.T) {
	rates := []string{"100/1s", "200/1s"}
	result, err := ParseRateList(rates)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result[1] != 200 {
		t.Errorf("result[1] = %d, want 200 (last value wins)", result[1])
	}
}

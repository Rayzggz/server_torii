package ratelimit

import (
	"fmt"
	"strconv"
	"strings"
)

func ParseRate(s string) (int64, int64, error) {
	parts := strings.Split(s, "/")
	if len(parts) != 2 {
		return 0, 0, fmt.Errorf("unexpected rate format: %s", s)
	}
	limit, err := strconv.Atoi(parts[0])
	if err != nil {
		return 0, 0, fmt.Errorf("unexpected rate format: %s", s)
	}
	if limit <= 0 {
		return 0, 0, fmt.Errorf("rate limit must be positive: %s", s)
	}

	timeStr := parts[1]
	if len(timeStr) < 2 {
		return 0, 0, fmt.Errorf("unexpected time format: %s", timeStr)
	}
	unit := timeStr[len(timeStr)-1]
	numPart := timeStr[:len(timeStr)-1]
	value, err := strconv.Atoi(numPart)
	if err != nil {
		return 0, 0, fmt.Errorf("unexpected time format: %s", timeStr)
	}
	if value <= 0 {
		return 0, 0, fmt.Errorf("rate time window must be positive: %s", timeStr)
	}
	var seconds int
	switch unit {
	case 's':
		seconds = value
	case 'm':
		seconds = value * 60
	case 'h':
		seconds = value * 3600
	default:
		return 0, 0, fmt.Errorf("unexpected time unit: %s", string(unit))
	}
	return int64(limit), int64(seconds), nil
}

// Rate allows Limit events within Window seconds.
type Rate struct {
	Limit  int64
	Window int64
}

// Rates are the limits of one counter, in the order they were configured: the first one a
// client exceeds is the one that is reported.
type Rates []Rate

// MaxWindow returns the longest window, in seconds: what a counter has to remember.
func (r Rates) MaxWindow() int64 {
	longest := int64(0)
	for _, rate := range r {
		longest = max(longest, rate.Window)
	}
	return longest
}

// ParseRates converts rates such as "100/1m" in the order given. Two limits for the same
// window are an error: one of them would never matter.
func ParseRates(rates []string) (Rates, error) {
	result := make(Rates, 0, len(rates))
	seen := make(map[int64]string, len(rates))
	for _, s := range rates {
		limit, seconds, err := ParseRate(s)
		if err != nil {
			return nil, err
		}
		if other, dup := seen[seconds]; dup {
			return nil, fmt.Errorf("rates %s and %s are for the same window", other, s)
		}
		seen[seconds] = s
		result = append(result, Rate{Limit: limit, Window: seconds})
	}
	return result, nil
}

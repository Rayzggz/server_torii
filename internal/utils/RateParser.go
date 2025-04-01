package utils

import (
	"fmt"
	"strconv"
	"strings"
)

func ParseRate(s string) (int, int, error) {
	parts := strings.Split(s, "/")
	if len(parts) != 2 {
		return 0, 0, fmt.Errorf("unexpected rate format: %s", s)
	}
	limit, err := strconv.Atoi(parts[0])
	if err != nil {
		return 0, 0, fmt.Errorf("unexpected rate format: %s", s)
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
	return limit, seconds, nil
}

package server

import (
	"server_torii/internal/action"
	"server_torii/internal/config"
	"server_torii/internal/dataType"
	"testing"
	"time"
)

func TestUriAnalyzer_Analyze(t *testing.T) {
	// Setup shared memory
	engine := action.NewActionRuleEngine(time.Minute)
	sharedMem := &dataType.SharedMemory{
		ActionRuleEngine: engine,
	}
	defer engine.Stop()

	tests := []struct {
		name        string
		rule        config.RuleSet
		logs        []LogEntry
		checkUri    string
		expectBlock bool
	}{
		{
			name: "Canonicalization and Rate Limit",
			rule: config.RuleSet{
				AdaptiveTrafficAnalyzerRule: &dataType.AdaptiveTrafficAnalyzerRule{
					UriAnalysis: dataType.UriAnalysisRule{
						Enabled:                true,
						FailRateThreshold:      0.5,
						FailRateCountThreshold: 2,
						BlockDuration:          300,
					},
					Tag: "test_tag",
				},
			},
			logs: []LogEntry{
				{URI: "/test?q=1", Status: 500},
				{URI: "/test?q=2", Status: 500},
				{URI: "/test", Status: 200},
			},
			checkUri:    "/test",
			expectBlock: true,
		},
		{
			name: "IQR Outlier Detection",
			rule: config.RuleSet{
				AdaptiveTrafficAnalyzerRule: &dataType.AdaptiveTrafficAnalyzerRule{
					UriAnalysis: dataType.UriAnalysisRule{
						Enabled:                 true,
						RequestCountSensitivity: 1.5,
						BlockDuration:           300,
					},
					Tag: "test_tag",
				},
			},
			logs: []LogEntry{
				// Normal traffic
				{URI: "/a", Status: 200}, {URI: "/a", Status: 200}, {URI: "/a", Status: 200},
				{URI: "/b", Status: 200}, {URI: "/b", Status: 200},
				{URI: "/c", Status: 200}, {URI: "/c", Status: 200}, {URI: "/c", Status: 200},
				{URI: "/d", Status: 200}, {URI: "/d", Status: 200},
				// Outlier
				{URI: "/bad", Status: 200}, {URI: "/bad", Status: 200}, {URI: "/bad", Status: 200},
				{URI: "/bad", Status: 200}, {URI: "/bad", Status: 200}, {URI: "/bad", Status: 200},
				{URI: "/bad", Status: 200}, {URI: "/bad", Status: 200}, {URI: "/bad", Status: 200},
				{URI: "/bad", Status: 200}, {URI: "/bad", Status: 200}, {URI: "/bad", Status: 200},
			},
			checkUri:    "/bad",
			expectBlock: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			u := &UriAnalyzer{}
			u.Analyze(tt.logs, &tt.rule, sharedMem)

			if tt.checkUri != "" {
				act := engine.Check("", "", tt.checkUri)
				if tt.expectBlock && act != action.ActionBlock {
					t.Errorf("Expected URI %s to be blocked, got %v", tt.checkUri, act)
				} else if !tt.expectBlock && act == action.ActionBlock {
					t.Errorf("Expected URI %s NOT to be blocked, got %v", tt.checkUri, act)
				}
			}
		})
	}
}

func TestUriAnalyzer_Percentile(t *testing.T) {
	u := &UriAnalyzer{}
	data := []float64{1, 2, 3, 4, 5}
	// 50th percentile (median) of 1,2,3,4,5 is 3
	if got := u.percentile(data, 50); got != 3 {
		t.Errorf("percentile(50) = %f, want 3.0", got)
	}
}

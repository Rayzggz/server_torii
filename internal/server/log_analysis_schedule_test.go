package server

import (
	"fmt"
	"server_torii/internal/config"
	"server_torii/internal/dataType"
	"sync"
	"testing"
	"time"
)

type recordedAnalysis struct {
	rule *config.RuleSet
	logs []LogEntry
}

type recordingAnalyzer struct {
	calls []recordedAnalysis
}

type analyzerFunc func([]LogEntry, *config.RuleSet, *dataType.SharedMemory)

func (f analyzerFunc) Analyze(logs []LogEntry, rule *config.RuleSet, shared *dataType.SharedMemory) {
	f(logs, rule, shared)
}

func (r *recordingAnalyzer) Analyze(logs []LogEntry, rule *config.RuleSet, _ *dataType.SharedMemory) {
	r.calls = append(r.calls, recordedAnalysis{rule, append([]LogEntry(nil), logs...)})
}

func scheduledRule(tag string, interval int64) *config.RuleSet {
	return &config.RuleSet{AdaptiveTrafficAnalyzerRule: &dataType.AdaptiveTrafficAnalyzerRule{
		Enabled: true, Tag: tag, AnalysisInterval: interval,
	}}
}

func scheduleFixture(t *testing.T, rules map[string]*config.RuleSet) (*AdaptiveTrafficAnalyzer, *recordingAnalyzer, time.Time) {
	t.Helper()
	previous := config.Manager
	config.Manager = &config.ConfigManager{}
	config.Manager.Set(&config.SiteConfigSnapshot{SiteRules: rules})
	a := NewAdaptiveTrafficAnalyzer(nil)
	r := &recordingAnalyzer{}
	a.analyzers = []Analyzer{r}
	t.Cleanup(func() {
		a.Stop()
		config.Manager = previous
	})
	start := time.Unix(1000, 0)
	a.processBatchAt(start)
	return a, r, start
}

func TestAnalysisIndependentIntervals(t *testing.T) {
	for _, intervals := range [][2]int64{{60, 300}, {7, 10}} {
		t.Run(fmt.Sprint(intervals), func(t *testing.T) {
			fast, slow := scheduledRule("fast", intervals[0]), scheduledRule("slow", intervals[1])
			a, recorder, start := scheduleFixture(t, map[string]*config.RuleSet{"fast": fast, "slow": slow})
			for second := int64(1); second <= intervals[0]*intervals[1]; second++ {
				for _, tag := range []string{"fast", "slow", "unknown"} {
					a.AddLog(LogEntry{Tag: tag, IP: fmt.Sprint(second)})
				}
				before := len(recorder.calls)
				a.processBatchAt(start.Add(time.Duration(second) * time.Second))
				wantCalls := 0
				for _, rule := range []*config.RuleSet{fast, slow} {
					if second%rule.AdaptiveTrafficAnalyzerRule.AnalysisInterval == 0 {
						wantCalls++
					}
				}
				if len(recorder.calls)-before != wantCalls {
					t.Fatalf("second %d: got %d calls, want %d", second, len(recorder.calls)-before, wantCalls)
				}
				for _, call := range recorder.calls[before:] {
					interval := call.rule.AdaptiveTrafficAnalyzerRule.AnalysisInterval
					if int64(len(call.logs)) != interval {
						t.Fatalf("second %d: got %d logs, want %d", second, len(call.logs), interval)
					}
					for i, entry := range call.logs {
						if entry.Tag != call.rule.AdaptiveTrafficAnalyzerRule.Tag || entry.IP != fmt.Sprint(second-interval+1+int64(i)) {
							t.Fatalf("unexpected or duplicated log: %+v", entry)
						}
					}
				}
			}
		})
	}
}

func TestAnalysisReloadIntervalsAndRules(t *testing.T) {
	for _, tc := range []struct {
		name                      string
		old, updated, reload, due int64
	}{
		{"shorter already due", 60, 10, 20, 20},
		{"shorter future", 60, 30, 20, 30},
		{"longer", 30, 60, 20, 60},
		{"threshold only", 60, 60, 20, 60},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a, recorder, start := scheduleFixture(t, map[string]*config.RuleSet{"site": scheduledRule("tag", tc.old)})
			a.AddLog(LogEntry{Tag: "tag", IP: "retained"})
			a.processBatchAt(start.Add(time.Second))
			updated := scheduledRule("tag", tc.updated)
			updated.AdaptiveTrafficAnalyzerRule.Non200Analysis.FailCountThreshold = 123
			config.Manager.Set(&config.SiteConfigSnapshot{SiteRules: map[string]*config.RuleSet{"site": updated}})
			a.processBatchAt(start.Add(time.Duration(tc.reload) * time.Second))
			if tc.reload < tc.due {
				if len(recorder.calls) != 0 {
					t.Fatal("analyzed before updated deadline")
				}
				a.processBatchAt(start.Add(time.Duration(tc.due-1) * time.Second))
				if len(recorder.calls) != 0 {
					t.Fatal("analyzed before updated deadline")
				}
				a.processBatchAt(start.Add(time.Duration(tc.due) * time.Second))
			}
			if len(recorder.calls) != 1 || recorder.calls[0].rule != updated || len(recorder.calls[0].logs) != 1 || recorder.calls[0].logs[0].IP != "retained" {
				t.Fatalf("reload lost logs or used stale rules: %+v", recorder.calls)
			}
		})
	}
}

func TestAnalysisReloadSiteLifecycle(t *testing.T) {
	for _, change := range []string{"disabled", "removed", "retagged"} {
		t.Run(change, func(t *testing.T) {
			a, recorder, start := scheduleFixture(t, map[string]*config.RuleSet{"site": scheduledRule("old", 10)})
			a.AddLog(LogEntry{Tag: "old", IP: "discard"})
			a.processBatchAt(start.Add(time.Second))
			rules := map[string]*config.RuleSet{"site": scheduledRule("new", 10)}
			if change == "disabled" {
				rules["site"].AdaptiveTrafficAnalyzerRule.Enabled = false
			}
			if change == "removed" {
				delete(rules, "site")
			}
			config.Manager.Set(&config.SiteConfigSnapshot{SiteRules: rules})
			a.processBatchAt(start.Add(2 * time.Second)) // Reload during idle traffic.
			if change != "retagged" {
				if len(a.windows) != 0 {
					t.Fatal("inactive site retained pending state")
				}
				config.Manager.Set(&config.SiteConfigSnapshot{SiteRules: map[string]*config.RuleSet{"site": scheduledRule("new", 10)}})
				a.processBatchAt(start.Add(2 * time.Second))
			}
			a.AddLog(LogEntry{Tag: "old", IP: "ignored"})
			a.AddLog(LogEntry{Tag: "new", IP: "fresh"})
			a.processBatchAt(start.Add(10 * time.Second))
			if len(recorder.calls) != 0 {
				t.Fatal("new window used old deadline")
			}
			a.processBatchAt(start.Add(12 * time.Second))
			if len(recorder.calls) != 1 || len(recorder.calls[0].logs) != 1 || recorder.calls[0].logs[0].IP != "fresh" {
				t.Fatalf("unexpected logs: %+v", recorder.calls)
			}
		})
	}
}

func TestAnalysisSharedTagAndMissedWindows(t *testing.T) {
	a, recorder, start := scheduleFixture(t, map[string]*config.RuleSet{"a": scheduledRule("shared", 7), "b": scheduledRule("shared", 10)})
	secondRecorder := &recordingAnalyzer{}
	a.analyzers = append(a.analyzers, secondRecorder)
	a.AddLog(LogEntry{Tag: "shared"})
	a.processBatchAt(start.Add(25 * time.Second))
	if len(recorder.calls) != 2 || len(secondRecorder.calls) != 2 {
		t.Fatal("both analyzers must run once per site")
	}
	for _, call := range recorder.calls {
		if len(call.logs) != 1 {
			t.Fatal("shared-tag logs lost")
		}
	}
	if !a.windows["a"].next.Equal(start.Add(28*time.Second)) || !a.windows["b"].next.Equal(start.Add(30*time.Second)) {
		t.Fatal("incorrect future boundaries")
	}
	a.processBatchAt(start.Add(100 * time.Second))
	if len(recorder.calls) != 2 {
		t.Fatal("empty windows repeated analysis")
	}
	if !a.windows["a"].next.After(start.Add(100 * time.Second)) {
		t.Fatal("empty window did not advance")
	}
}

func TestAnalysisFallbackAndMissingSnapshot(t *testing.T) {
	a, recorder, start := scheduleFixture(t, map[string]*config.RuleSet{"site": scheduledRule("tag", 0)})
	a.AddLog(LogEntry{Tag: "tag"})
	a.processBatchAt(start.Add(59 * time.Second))
	if len(recorder.calls) != 0 {
		t.Fatal("fallback ran early")
	}
	a.processBatchAt(start.Add(60 * time.Second))
	if len(recorder.calls) != 1 {
		t.Fatal("fallback did not run at 60 seconds")
	}
	config.Manager.Set(nil)
	a.processBatchAt(start.Add(61 * time.Second))
	if len(a.windows) != 0 {
		t.Fatal("missing snapshot retained state")
	}
}

func TestAnalysisConcurrentIngestion(t *testing.T) {
	a, recorder, start := scheduleFixture(t, map[string]*config.RuleSet{"site": scheduledRule("tag", 10)})
	var wg sync.WaitGroup
	for worker := 0; worker < 8; worker++ {
		wg.Add(1)
		go func(worker int) {
			defer wg.Done()
			for i := 0; i < 100; i++ {
				a.AddLog(LogEntry{Tag: "tag", IP: fmt.Sprintf("%d/%d", worker, i)})
				a.processBatchAt(start.Add(time.Second))
			}
		}(worker)
	}
	wg.Wait()
	a.processBatchAt(start.Add(10 * time.Second))
	if len(recorder.calls) != 1 || len(recorder.calls[0].logs) != 800 {
		t.Fatal("concurrent ingestion lost logs")
	}
	seen := make(map[string]bool)
	for _, entry := range recorder.calls[0].logs {
		if seen[entry.IP] {
			t.Fatal("duplicate log")
		}
		seen[entry.IP] = true
	}
}

func TestAnalysisStartStop(t *testing.T) {
	a, recorder, _ := scheduleFixture(t, map[string]*config.RuleSet{"site": scheduledRule("tag", 10)})
	a.Start()
	a.Start()
	a.Stop()
	a.Stop()
	a.AddLog(LogEntry{Tag: "tag"})
	a.ProcessBatch()
	if len(recorder.calls) != 0 {
		t.Fatal("analysis ran after stop")
	}
	// Start after stop must not create another worker.
	a.Start()
}

func TestAnalysisBatchUsesOneSnapshot(t *testing.T) {
	old := scheduledRule("tag", 10)
	updated := scheduledRule("tag", 10)
	a, recorder, start := scheduleFixture(t, map[string]*config.RuleSet{"site": old})
	a.analyzers = []Analyzer{analyzerFunc(func(_ []LogEntry, _ *config.RuleSet, _ *dataType.SharedMemory) {
		config.Manager.Set(&config.SiteConfigSnapshot{SiteRules: map[string]*config.RuleSet{"site": updated}})
	}), recorder}
	a.AddLog(LogEntry{Tag: "tag"})
	a.processBatchAt(start.Add(10 * time.Second))
	if len(recorder.calls) != 1 || recorder.calls[0].rule != old {
		t.Fatal("reload changed the snapshot midway through a batch")
	}
	a.AddLog(LogEntry{Tag: "tag"})
	a.processBatchAt(start.Add(20 * time.Second))
	if len(recorder.calls) != 2 || recorder.calls[1].rule != updated {
		t.Fatal("next batch did not observe reload")
	}
}

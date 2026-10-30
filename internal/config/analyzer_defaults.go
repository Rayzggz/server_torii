package config

import (
	"server_torii/internal/dataType"
	"strings"
)

// Default values for AdaptiveTrafficAnalyzer fields left at zero.
const (
	DefaultATAAnalysisInterval     = 10
	DefaultATAWindowBuckets        = 30
	DefaultATAEvidenceTTL          = 21600
	DefaultATADistinctPages        = 3
	DefaultATABaselineHalfLife     = 21600
	DefaultATABaselineWarmup       = 3600
	DefaultATAMinReferenceRequests = 200
	DefaultATAHotURIMinRequests    = 100
	DefaultATAHotURIMinDistinctIPs = 50
	DefaultATAHotURIRatioThreshold = 5.0
	DefaultATAHotURISustain        = 60
	DefaultATAHotURIFallbackShare  = 0.8
	DefaultATABlockDuration        = 600
	DefaultATAMaxBlockDuration     = 86400
	DefaultATAScoreThreshold       = 50
	DefaultATAHotURIMinHits        = 3
	DefaultATAMinFailures          = 30
	DefaultATAFailRateThreshold    = 0.6
	DefaultATAScanPathsThreshold   = 30
	DefaultATAMaxBroadcastPerTick  = 200
)

// DefaultATAAssetExtensions marks requests that browsers make while rendering a page.
var DefaultATAAssetExtensions = []string{
	".js", ".mjs", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp", ".avif",
	".ico", ".bmp", ".woff", ".woff2", ".ttf", ".otf", ".eot", ".map",
}

// NormalizeAnalyzerAction lowercases a configured action. Unknown values fall back to observe.
func NormalizeAnalyzerAction(a dataType.AnalyzerAction) (dataType.AnalyzerAction, bool) {
	switch v := dataType.AnalyzerAction(strings.ToLower(strings.TrimSpace(string(a)))); v {
	case dataType.AnalyzerObserve, dataType.AnalyzerCaptchaUnverified, dataType.AnalyzerCaptcha, dataType.AnalyzerBlock:
		return v, true
	case "":
		return dataType.AnalyzerObserve, true
	default:
		return dataType.AnalyzerObserve, false
	}
}

// NormalizeAdaptiveTrafficAnalyzerRule fills defaults and normalizes lists in place.
// It is idempotent, so the analyzer may call it on rules built outside the loader.
func NormalizeAdaptiveTrafficAnalyzerRule(r *dataType.AdaptiveTrafficAnalyzerRule) {
	setDefault(&r.AnalysisInterval, DefaultATAAnalysisInterval)
	setDefault(&r.WindowBuckets, DefaultATAWindowBuckets)
	setDefault(&r.BrowserEvidence.TTL, DefaultATAEvidenceTTL)
	setDefault(&r.BrowserEvidence.DistinctPages, DefaultATADistinctPages)
	setDefault(&r.URIDetection.Baseline.HalfLife, DefaultATABaselineHalfLife)
	setDefault(&r.URIDetection.Baseline.Warmup, DefaultATABaselineWarmup)
	setDefault(&r.URIDetection.Baseline.MinReferenceRequests, DefaultATAMinReferenceRequests)
	setDefault(&r.URIDetection.MinRequests, DefaultATAHotURIMinRequests)
	setDefault(&r.URIDetection.MinDistinctIPs, DefaultATAHotURIMinDistinctIPs)
	setDefault(&r.URIDetection.RatioThreshold, DefaultATAHotURIRatioThreshold)
	setDefault(&r.URIDetection.Sustain, DefaultATAHotURISustain)
	setDefault(&r.URIDetection.FallbackShare, DefaultATAHotURIFallbackShare)
	setDefault(&r.IPDetection.BlockDuration, DefaultATABlockDuration)
	setDefault(&r.IPDetection.MaxBlockDuration, DefaultATAMaxBlockDuration)
	setDefault(&r.IPDetection.ScoreThreshold, DefaultATAScoreThreshold)
	setDefault(&r.IPDetection.HotURIMinHits, DefaultATAHotURIMinHits)
	setDefault(&r.IPDetection.MinFailures, DefaultATAMinFailures)
	setDefault(&r.IPDetection.FailRateThreshold, DefaultATAFailRateThreshold)
	setDefault(&r.IPDetection.ScanPathsThreshold, DefaultATAScanPathsThreshold)
	setDefault(&r.IPDetection.MaxBroadcastPerTick, DefaultATAMaxBroadcastPerTick)
	setDefault(&r.URIDetection.BlockDuration, DefaultATABlockDuration)
	if r.IPDetection.MaxBlockDuration < r.IPDetection.BlockDuration {
		r.IPDetection.MaxBlockDuration = r.IPDetection.BlockDuration
	}
	r.IPDetection.Action, _ = NormalizeAnalyzerAction(r.IPDetection.Action)
	r.URIDetection.Action, _ = NormalizeAnalyzerAction(r.URIDetection.Action)

	r.BrowserEvidence.AssetExtensions = normalizeList(r.BrowserEvidence.AssetExtensions, func(s string) string {
		if !strings.HasPrefix(s, ".") {
			return "." + s
		}
		return s
	})
	if len(r.BrowserEvidence.AssetExtensions) == 0 {
		r.BrowserEvidence.AssetExtensions = append([]string(nil), DefaultATAAssetExtensions...)
	}
}

func setDefault[T int | int64 | float64](v *T, def T) {
	if *v <= 0 {
		*v = def
	}
}

func normalizeList(in []string, fix func(string) string) []string {
	out := make([]string, 0, len(in))
	for _, s := range in {
		s = strings.ToLower(strings.TrimSpace(s))
		if s == "" {
			continue
		}
		if fix != nil {
			s = fix(s)
		}
		out = append(out, s)
	}
	return out
}

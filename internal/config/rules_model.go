package config

import (
	"server_torii/internal/action"
	"server_torii/internal/ratelimit"
	"time"
)

// ChallengeMode is how a site makes a client prove itself.
type ChallengeMode string

const (
	// ChallengeHCaptcha and ChallengeAltcha show a CAPTCHA page.
	ChallengeHCaptcha ChallengeMode = "hcaptcha"
	ChallengeAltcha   ChallengeMode = "altcha"
	// ChallengeExternal sends the client to an external provider, which sends it back cleared.
	ChallengeExternal ChallengeMode = "external"
)

// ChallengeRule is the one challenge of a site. Every rule that asks for a client to be
// challenged, and the Challenge check itself when it is enabled for all traffic, uses it.
type ChallengeRule struct {
	// Enabled challenges every client; without it only the clients a rule singles out.
	Enabled bool
	Mode    ChallengeMode
	// CookieKey signs the session and clearance cookies. It is not configured per site: it is
	// derived from the global secret, so every site and every node of a cluster signs alike.
	CookieKey string
	// ExternalSecret is the key the site shares with its external provider. It signs only
	// what the two exchange, so the provider cannot issue cookies.
	ExternalSecret string
	// ClearanceTTL is how long a cleared client stays cleared.
	ClearanceTTL time.Duration
	// SessionTTL is how long a client has to answer a CAPTCHA. The external mode does not use
	// it: its sessions are bounded by the lifetime of the link that brings the client back.
	SessionTTL       time.Duration
	HCaptchaSecret   string
	AltchaHMACSecret string
	AltchaCost       int
	// RedirectURL is where the external mode sends the client.
	RedirectURL string
	// FailureLimit bounds how often a client may be challenged without clearing; beyond it the
	// client is blocked for FailureBlockDuration.
	FailureLimit         ratelimit.Rates
	FailureBlockDuration time.Duration
}

// ShowsCaptcha reports whether the challenge is a CAPTCHA page, as opposed to a redirect.
func (r *ChallengeRule) ShowsCaptcha() bool {
	return r != nil && r.Mode != ChallengeExternal
}

// Bots are the crawlers whose claims can be verified, by the name the configuration uses.
var Bots = []string{"google", "bing", "baidu", "yandex", "sogou", "apple"}

// VerifyBotRule lists the crawlers a site verifies. A client that claims to be one of them is
// let through when DNS confirms the claim, and blocked when it does not.
type VerifyBotRule struct {
	Enabled bool
	Bots    map[string]bool
}

// Verifies reports whether the site verifies the crawler.
func (r *VerifyBotRule) Verifies(bot string) bool {
	return r != nil && r.Bots[bot]
}

// AllBots returns a set with every crawler, for rules built in code.
func AllBots() map[string]bool {
	all := make(map[string]bool, len(Bots))
	for _, bot := range Bots {
		all[bot] = true
	}
	return all
}

// SameURIKey is what the same-URI limit takes two requests to be for the same URI by.
type SameURIKey string

const (
	// SameURIKeyFull is the URI as the client sent it, query string included. A client gets
	// past the limit by adding a query string that changes with every request.
	SameURIKeyFull SameURIKey = "full"
	// SameURIKeyPath is the cleaned path, without the query string.
	SameURIKeyPath SameURIKey = "path"
	// SameURIKeyCanonical is the path with its IDs and tokens masked, as the traffic analyzer
	// groups URIs: /post/1 and /post/2 count together.
	SameURIKeyCanonical SameURIKey = "canonical"
)

// Of returns the part of the URI the mode counts requests by.
func (k SameURIKey) Of(uri string) string {
	switch k {
	case SameURIKeyPath:
		return action.CleanPath(uri)
	case SameURIKeyCanonical:
		return action.CanonicalizeURI(uri)
	}
	return uri
}

// HTTPFloodRule limits how fast one client may send requests. Each list is checked in the
// order it is configured in.
type HTTPFloodRule struct {
	Enabled bool
	// SpeedLimit bounds the requests of a client, SameURILimit its requests for one URI;
	// SameURIKey decides which URIs are one.
	SpeedLimit   ratelimit.Rates
	SameURILimit ratelimit.Rates
	SameURIKey   SameURIKey
	// FailureLimit bounds how often a client may run into the two limits above; beyond it the
	// client is blocked for FailureBlockDuration.
	FailureLimit         ratelimit.Rates
	FailureBlockDuration time.Duration
}

type AdaptiveTrafficAnalyzerRule struct {
	Enabled          bool                `yaml:"enabled"`
	AnalysisInterval time.Duration       `yaml:"analysis_interval" validate:"min=0s"`
	WindowBuckets    int                 `yaml:"window_buckets" validate:"min=0"`
	BrowserEvidence  BrowserEvidenceRule `yaml:"browser_evidence"`
	URIDetection     URIDetectionRule    `yaml:"uri_detection"`
	IPDetection      IPDetectionRule     `yaml:"ip_detection"`
}

// BrowserEvidenceRule decides which clients look like browsers; URI detection, IP detection
// and the challenge_unverified action all use it.
type BrowserEvidenceRule struct {
	TTL             time.Duration `yaml:"ttl" validate:"min=0s"`
	DistinctPages   int           `yaml:"distinct_pages" validate:"min=0"`
	AssetExtensions []string      `yaml:"asset_extensions"`
}

// BaselineRule controls the reference rate learned from browser-like clients.
type BaselineRule struct {
	HalfLife             time.Duration `yaml:"half_life" validate:"min=0s"`
	Warmup               time.Duration `yaml:"warmup" validate:"min=0s"`
	MinReferenceRequests int64         `yaml:"min_reference_requests" validate:"min=0"`
}

type IPDetectionRule struct {
	Enabled             bool          `yaml:"enabled"`
	Action              action.Action `yaml:"action" validate:"omitempty,oneof=observe challenge_unverified challenge block"`
	BlockDuration       time.Duration `yaml:"block_duration" validate:"min=0s"`
	MaxBlockDuration    time.Duration `yaml:"max_block_duration" validate:"min=0s"`
	ScoreThreshold      int           `yaml:"score_threshold" validate:"min=0"`
	HotURIMinHits       int64         `yaml:"hot_uri_min_hits" validate:"min=0"`
	MinFailures         int64         `yaml:"min_failures" validate:"min=0"`
	FailRateThreshold   float64       `yaml:"fail_rate_threshold" validate:"min=0,max=1"`
	ScanPathsThreshold  int           `yaml:"scan_paths_threshold" validate:"min=0"`
	MaxBroadcastPerTick int           `yaml:"max_broadcast_per_tick" validate:"min=0"`
}

// URIDetectionRule finds hot URIs and sets the action applied to them.
type URIDetectionRule struct {
	Action         action.Action `yaml:"action" validate:"omitempty,oneof=observe challenge_unverified challenge block"`
	BlockDuration  time.Duration `yaml:"block_duration" validate:"min=0s"`
	MinRequests    int64         `yaml:"min_requests" validate:"min=0"`
	MinDistinctIPs int           `yaml:"min_distinct_ips" validate:"min=0"`
	Sustain        time.Duration `yaml:"sustain" validate:"min=0s"`
	RatioThreshold float64       `yaml:"ratio_threshold" validate:"min=0"`
	FallbackShare  float64       `yaml:"fallback_share" validate:"min=0,max=1"`
	Baseline       BaselineRule  `yaml:"baseline"`
}

type CountryRule struct {
	Enabled       bool
	DefaultAction action.Action
	UnknownAction action.Action
	Countries     map[string]action.Action
}

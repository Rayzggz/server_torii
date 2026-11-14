package config

import (
	"server_torii/internal/action"
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
	// Keys sign the session and clearance cookies. The first one signs; all of them verify, so
	// a key is replaced by putting the new one in front and dropping the old one later.
	Keys []string
	// ClearanceTTL is how long, in seconds, a cleared client stays cleared.
	ClearanceTTL int64
	// SessionTTL is how long, in seconds, a client has to answer a CAPTCHA. The external mode
	// does not use it: its sessions are bounded by the lifetime of the link that brings the client back.
	SessionTTL       int64
	HCaptchaSecret   string
	AltchaHMACSecret string
	AltchaCost       int
	// RedirectURL is where the external mode sends the client.
	RedirectURL string
	// FailureLimit bounds how often a client may be challenged without clearing; beyond it the
	// client is blocked for FailureBlockDuration seconds.
	FailureLimit         map[int64]int64
	FailureBlockDuration int64
}

// ShowsCaptcha reports whether the challenge is a CAPTCHA page, as opposed to a redirect.
func (r *ChallengeRule) ShowsCaptcha() bool {
	return r != nil && r.Mode != ChallengeExternal
}

type VerifyBotRule struct {
	Enabled         bool `yaml:"enabled"`
	VerifyGoogleBot bool `yaml:"verify_google_bot"`
	VerifyBingBot   bool `yaml:"verify_bing_bot"`
	VerifyBaiduBot  bool `yaml:"verify_baidu_bot"`
	VerifyYandexBot bool `yaml:"verify_yandex_bot"`
	VerifySogouBot  bool `yaml:"verify_sogou_bot"`
	VerifyAppleBot  bool `yaml:"verify_apple_bot"`
}

type HTTPFloodRule struct {
	Enabled               bool `yaml:"enabled"`
	HTTPFloodSpeedLimit   map[int64]int64
	HTTPFloodSameURILimit map[int64]int64
	HTTPFloodFailureLimit map[int64]int64
	FailureBlockDuration  int64
}

type AdaptiveTrafficAnalyzerRule struct {
	Enabled          bool                `yaml:"enabled"`
	AnalysisInterval int64               `yaml:"analysis_interval" validate:"min=0"`
	WindowBuckets    int                 `yaml:"window_buckets" validate:"min=0"`
	BrowserEvidence  BrowserEvidenceRule `yaml:"browser_evidence"`
	URIDetection     URIDetectionRule    `yaml:"uri_detection"`
	IPDetection      IPDetectionRule     `yaml:"ip_detection"`
}

// BrowserEvidenceRule decides which clients look like browsers; URI detection, IP detection
// and the challenge_unverified action all use it.
type BrowserEvidenceRule struct {
	TTL             int64    `yaml:"ttl" validate:"min=0"`
	DistinctPages   int      `yaml:"distinct_pages" validate:"min=0"`
	AssetExtensions []string `yaml:"asset_extensions"`
}

// BaselineRule controls the reference rate learned from browser-like clients.
type BaselineRule struct {
	HalfLife             int64 `yaml:"half_life" validate:"min=0"`
	Warmup               int64 `yaml:"warmup" validate:"min=0"`
	MinReferenceRequests int64 `yaml:"min_reference_requests" validate:"min=0"`
}

type IPDetectionRule struct {
	Enabled             bool          `yaml:"enabled"`
	Action              action.Action `yaml:"action" validate:"omitempty,oneof=observe challenge_unverified challenge block"`
	BlockDuration       int64         `yaml:"block_duration" validate:"min=0"`
	MaxBlockDuration    int64         `yaml:"max_block_duration" validate:"min=0"`
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
	BlockDuration  int64         `yaml:"block_duration" validate:"min=0"`
	MinRequests    int64         `yaml:"min_requests" validate:"min=0"`
	MinDistinctIPs int           `yaml:"min_distinct_ips" validate:"min=0"`
	Sustain        int64         `yaml:"sustain" validate:"min=0"`
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

// SigningKey is the key new cookies are signed with. It also signs what is exchanged with the
// external provider and binds an ALTCHA challenge to its session.
func (c *ChallengeRule) SigningKey() string {
	if len(c.Keys) == 0 {
		return ""
	}
	return c.Keys[0]
}

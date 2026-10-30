package dataType

import (
	"net/http"
	"net/netip"
	"sync/atomic"
	"time"
)

const ServerToriiVersion string = "2.0.0-beta"

// Feature Control Bit Positions (0-based from right)
const (
	FeatureBitIPAllow           = 0  // bit 0
	FeatureBitIPBlock           = 1  // bit 1
	FeatureBitURLAllow          = 2  // bit 2
	FeatureBitURLBlock          = 3  // bit 3
	FeatureBitVerifyBot         = 4  // bit 4
	FeatureBitHTTPFlood         = 5  // bit 5
	FeatureBitCaptcha           = 6  // bit 6
	FeatureBitExternalMigration = 7  // bit 7
	FeatureBitCountryRule       = 8  // bit 8
	FeatureBitIPCAPTCHA         = 9  // bit 9
	FeatureBitURLCAPTCHA        = 10 // bit 10
	// Bits 11-15 reserved for future features
)

// Feature Control Values
const (
	FeatureIPAllow           = 1 << FeatureBitIPAllow           // 0000000000000001
	FeatureIPBlock           = 1 << FeatureBitIPBlock           // 0000000000000010
	FeatureURLAllow          = 1 << FeatureBitURLAllow          // 0000000000000100
	FeatureURLBlock          = 1 << FeatureBitURLBlock          // 0000000000001000
	FeatureVerifyBot         = 1 << FeatureBitVerifyBot         // 0000000000010000
	FeatureHTTPFlood         = 1 << FeatureBitHTTPFlood         // 0000000000100000
	FeatureCaptcha           = 1 << FeatureBitCaptcha           // 0000000001000000
	FeatureExternalMigration = 1 << FeatureBitExternalMigration // 0000000010000000
	FeatureCountryRule       = 1 << FeatureBitCountryRule       // 0000000100000000
	FeatureIPCAPTCHA         = 1 << FeatureBitIPCAPTCHA         // 0000001000000000
	FeatureURLCAPTCHA        = 1 << FeatureBitURLCAPTCHA
)

type UserRequest struct {
	RemoteIP       string
	Uri            string
	Captcha        bool
	FeatureControl uint16
	ToriiClearance string
	ToriiSessionID string
	UserAgent      string
	Host           string
}

type CaptchaRule struct {
	Enabled                        bool            `yaml:"enabled"`
	Provider                       string          `yaml:"provider" validate:"required"`
	SecretKey                      string          `yaml:"secret_key" validate:"required,min=16"`
	CaptchaValidateTime            int64           `yaml:"captcha_validate_time" validate:"required,min=1,max=9223372036854775807"`
	CaptchaChallengeSessionTimeout int64           `yaml:"captcha_challenge_session_timeout" validate:"required,min=1,max=9223372036854775807"`
	HCaptchaSecret                 string          `yaml:"hcaptcha_secret"`
	AltchaHMACSecret               string          `yaml:"altcha_hmac_secret"`
	AltchaCost                     int             `yaml:"altcha_cost"`
	CaptchaFailureLimit            map[int64]int64 `yaml:"-"`
	FailureBlockDuration           int64           `yaml:"failure_block_duration"`
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

type AnalyzerAction string

const (
	AnalyzerObserve AnalyzerAction = "observe"
	// AnalyzerCaptchaUnverified challenges only clients without browser evidence.
	AnalyzerCaptchaUnverified AnalyzerAction = "captcha_unverified"
	AnalyzerCaptcha           AnalyzerAction = "captcha"
	AnalyzerBlock             AnalyzerAction = "block"
)

type AdaptiveTrafficAnalyzerRule struct {
	Enabled          bool                `yaml:"enabled"`
	Tag              string              `yaml:"tag" validate:"required"`
	AnalysisInterval int64               `yaml:"analysis_interval" validate:"min=0"`
	WindowBuckets    int                 `yaml:"window_buckets" validate:"min=0"`
	BrowserEvidence  BrowserEvidenceRule `yaml:"browser_evidence"`
	URIDetection     URIDetectionRule    `yaml:"uri_detection"`
	IPDetection      IPDetectionRule     `yaml:"ip_detection"`
}

// BrowserEvidenceRule decides which clients look like browsers; URI detection, IP detection
// and the captcha_unverified action all use it.
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
	Enabled             bool           `yaml:"enabled"`
	Action              AnalyzerAction `yaml:"action" validate:"omitempty,oneof=observe captcha_unverified captcha block"`
	BlockDuration       int64          `yaml:"block_duration" validate:"min=0"`
	MaxBlockDuration    int64          `yaml:"max_block_duration" validate:"min=0"`
	ScoreThreshold      int            `yaml:"score_threshold" validate:"min=0"`
	HotURIMinHits       int64          `yaml:"hot_uri_min_hits" validate:"min=0"`
	MinFailures         int64          `yaml:"min_failures" validate:"min=0"`
	FailRateThreshold   float64        `yaml:"fail_rate_threshold" validate:"min=0,max=1"`
	ScanPathsThreshold  int            `yaml:"scan_paths_threshold" validate:"min=0"`
	MaxBroadcastPerTick int            `yaml:"max_broadcast_per_tick" validate:"min=0"`
}

// URIDetectionRule finds hot URIs and sets the action applied to them.
type URIDetectionRule struct {
	Action         AnalyzerAction `yaml:"action" validate:"omitempty,oneof=observe captcha_unverified captcha block"`
	BlockDuration  int64          `yaml:"block_duration" validate:"min=0"`
	MinRequests    int64          `yaml:"min_requests" validate:"min=0"`
	MinDistinctIPs int            `yaml:"min_distinct_ips" validate:"min=0"`
	Sustain        int64          `yaml:"sustain" validate:"min=0"`
	RatioThreshold float64        `yaml:"ratio_threshold" validate:"min=0"`
	FallbackShare  float64        `yaml:"fallback_share" validate:"min=0,max=1"`
	Baseline       BaselineRule   `yaml:"baseline"`
}

type ExternalMigrationRule struct {
	Enabled        bool   `yaml:"enabled"`
	RedirectUrl    string `yaml:"redirect_url" validate:"required,url"`
	SecretKey      string `yaml:"secret_key" validate:"required,min=16"`
	SessionTimeout int64  `yaml:"session_timeout" validate:"required,min=1,max=9223372036854775807"`
}

type IPAllowRule struct {
	Enabled bool `yaml:"enabled"`
	Trie    *TrieNode
}

type IPCAPTCHARule struct {
	Enabled bool      `yaml:"enabled"`
	Trie    *TrieNode `yaml:"-"`
}

type IPBlockRule struct {
	Enabled bool `yaml:"enabled"`
	Trie    *TrieNode
}

type URLAllowRule struct {
	Enabled bool `yaml:"enabled"`
	List    *URLRuleList
}

type URLCAPTCHARule struct {
	Enabled bool         `yaml:"enabled"`
	List    *URLRuleList `yaml:"-"`
}

type URLBlockRule struct {
	Enabled bool `yaml:"enabled"`
	List    *URLRuleList
}

type CountryAction string

const (
	CountryContinue CountryAction = "continue"
	CountryBlock    CountryAction = "block"
	CountryCaptcha  CountryAction = "captcha"
)

type CountryRule struct {
	Enabled       bool
	DefaultAction CountryAction
	UnknownAction CountryAction
	Countries     map[string]CountryAction
}

type CountryResolver interface {
	Country(netip.Addr) (string, error)
}

// TrafficMarker lets request handlers report clients the traffic analyzer must not punish.
type TrafficMarker interface {
	MarkVerified(ip string, ttl time.Duration)
	MarkNeutral(ip string, ttl time.Duration)
}

// TrafficMarkerOf returns the analyzer as a TrafficMarker when one is running.
func TrafficMarkerOf(sharedMem *SharedMemory) (TrafficMarker, bool) {
	if sharedMem == nil {
		return nil, false
	}
	marker, ok := sharedMem.AdaptiveTrafficAnalyzer.(TrafficMarker)
	return marker, ok
}

// BrowserEvidence reports whether the traffic analyzer has recently seen an IP behave like a browser.
type BrowserEvidence interface {
	HasBrowserEvidence(ip string) bool
}

// BrowserEvidenceOf returns the analyzer as a BrowserEvidence when one is running.
func BrowserEvidenceOf(sharedMem *SharedMemory) (BrowserEvidence, bool) {
	if sharedMem == nil {
		return nil, false
	}
	ev, ok := sharedMem.AdaptiveTrafficAnalyzer.(BrowserEvidence)
	return ev, ok
}

type GossipHandler interface {
	HandleGossip(w http.ResponseWriter, r *http.Request)
}

type SharedMemory struct {
	GossipChan    chan GossipMessage
	GossipManager GossipHandler

	HTTPFloodSpeedLimitCounter   atomic.Pointer[Counter]
	HTTPFloodSameURILimitCounter atomic.Pointer[Counter]
	HTTPFloodFailureLimitCounter atomic.Pointer[Counter]
	CaptchaFailureLimitCounter   atomic.Pointer[Counter]

	ActionRuleEngine        interface{}
	AdaptiveTrafficAnalyzer interface{}
	CountryResolver         CountryResolver
}

package dataType

const ServerToriiVersion string = "1.3.0"

// Feature Control Bit Positions (0-based from right)
const (
	FeatureBitIPAllow           = 0 // bit 0
	FeatureBitIPBlock           = 1 // bit 1
	FeatureBitURLAllow          = 2 // bit 2
	FeatureBitURLBlock          = 3 // bit 3
	FeatureBitVerifyBot         = 4 // bit 4
	FeatureBitHTTPFlood         = 5 // bit 5
	FeatureBitCaptcha           = 6 // bit 6
	FeatureBitExternalMigration = 7 // bit 7
	// Bits 8-15 reserved for future features
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
	Enabled                        bool   `yaml:"enabled"`
	SecretKey                      string `yaml:"secret_key" validate:"required,min=16"`
	CaptchaValidateTime            int64  `yaml:"captcha_validate_time" validate:"required,min=1,max=9223372036854775807"`
	CaptchaChallengeSessionTimeout int64  `yaml:"captcha_challenge_session_timeout" validate:"required,min=1,max=9223372036854775807"`
	HCaptchaSecret                 string `yaml:"hcaptcha_secret"`
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

type IPBlockRule struct {
	Enabled bool `yaml:"enabled"`
	Trie    *TrieNode
}

type URLAllowRule struct {
	Enabled bool `yaml:"enabled"`
	List    *URLRuleList
}

type URLBlockRule struct {
	Enabled bool `yaml:"enabled"`
	List    *URLRuleList
}

type SharedMemory struct {
	HTTPFloodSpeedLimitCounter   *Counter
	HTTPFloodSameURILimitCounter *Counter
	HTTPFloodFailureLimitCounter *Counter
}

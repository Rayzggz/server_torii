package dataType

type UserRequest struct {
	RemoteIP       string
	Uri            string
	Captcha        bool
	FeatureControl uint64
	ToriiClearance string
	ToriiSessionID string
	UserAgent      string
	Host           string
}

type CaptchaRule struct {
	Enabled                        bool   `yaml:"enabled"`
	SecretKey                      string `yaml:"secret_key"`
	CaptchaValidateTime            int64  `yaml:"captcha_validate_time"`
	CaptchaChallengeSessionTimeout int64  `yaml:"captcha_challenge_session_timeout"`
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
}

type ExternalMigrationRule struct {
	Enabled        bool   `yaml:"enabled"`
	RedirectUrl    string `yaml:"redirect_url"`
	SecretKey      string `yaml:"secret_key"`
	SessionTimeout int64  `yaml:"session_timeout"`
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
}

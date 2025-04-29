package dataType

import "server_torii/internal/utils"

type UserRequest struct {
	RemoteIP       string
	Uri            string
	Captcha        bool
	ToriiClearance string
	ToriiSessionID string
	UserAgent      string
	Host           string
}

type CaptchaRule struct {
	SecretKey                      string `yaml:"secret_key"`
	CaptchaValidateTime            int64  `yaml:"captcha_validate_time"`
	CaptchaChallengeSessionTimeout int64  `yaml:"captcha_challenge_session_timeout"`
	HCaptchaSecret                 string `yaml:"hcaptcha_secret"`
}

type VerifyBotRule struct {
	VerifyGoogleBot bool `yaml:"verify_google_bot"`
	VerifyBingBot   bool `yaml:"verify_bing_bot"`
	VerifyBaiduBot  bool `yaml:"verify_baidu_bot"`
	VerifyYandexBot bool `yaml:"verify_yandex_bot"`
	VerifySogouBot  bool `yaml:"verify_sogou_bot"`
	VerifyAppleBot  bool `yaml:"verify_apple_bot"`
}

type HTTPFloodRule struct {
	HTTPFloodSpeedLimit   map[int64]int64
	HTTPFloodSameURILimit map[int64]int64
}

type SharedMemory struct {
	HTTPFloodSpeedLimitCounter   *Counter
	HTTPFloodSameURILimitCounter *Counter
	Logger                       *utils.LogxManager
}

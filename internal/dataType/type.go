package dataType

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
	SecretKey           string `yaml:"secret_key"`
	CaptchaValidateTime int64  `yaml:"captcha_validate_time"`
	HCaptchaSecret      string `yaml:"hcaptcha_secret"`
}

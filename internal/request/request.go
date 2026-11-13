// Package request holds the per-request data every check works on.
package request

import "net/http"

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
	FeatureBitCustomRules       = 11 // bit 11
	// Bits 12-15 reserved for future features
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
	FeatureCustomRules       = 1 << FeatureBitCustomRules
)

type UserRequest struct {
	RemoteIP       string
	Uri            string
	FeatureControl uint16
	ToriiClearance string
	ToriiSessionID string
	UserAgent      string
	Host           string
	Method         string
	Headers        http.Header // original request headers inherited by the subrequest
}

package server

import (
	"errors"
	"net"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"server_torii/internal/config"
	"server_torii/internal/dataType"
	"server_torii/internal/geoip"
	"testing"
)

type serverCountryResolver struct {
	country string
}

func (r serverCountryResolver) Country(netip.Addr) (string, error) {
	return r.country, nil
}

func TestCheckMainIPAllowBypassesCountryRule(t *testing.T) {
	_, allowedNetwork, err := net.ParseCIDR("8.8.8.8/32")
	if err != nil {
		t.Fatalf("ParseCIDR returned error: %v", err)
	}
	trie := &dataType.TrieNode{}
	trie.Insert(allowedNetwork)
	ruleSet := &config.RuleSet{
		IPAllowRule: &dataType.IPAllowRule{Enabled: true, Trie: trie},
		CountryRule: &dataType.CountryRule{
			Enabled:        true,
			BlockCountries: map[string]struct{}{"US": {}},
		},
	}
	reqData := dataType.UserRequest{
		RemoteIP:       "8.8.8.8",
		FeatureControl: dataType.FeatureIPAllow | dataType.FeatureCountryRule,
	}
	recorder := httptest.NewRecorder()

	CheckMain(recorder, reqData, ruleSet, &config.MainConfig{}, &dataType.SharedMemory{
		CountryResolver: serverCountryResolver{country: "US"},
	})

	if recorder.Code != 200 {
		t.Fatalf("response status = %d, want 200 allowlist bypass", recorder.Code)
	}
}

func TestProcessFeatureControlCountryRuleBit(t *testing.T) {
	ruleSet := featureControlRuleSet()
	cfg := &config.MainConfig{ConnectingFeatureControlHeaders: []string{"X-Features"}}

	baseline := processFeatureControl(cfg, httptest.NewRequest("GET", "/", nil), ruleSet)
	if baseline&dataType.FeatureCountryRule == 0 {
		t.Fatal("CountryRule baseline bit is disabled, want enabled")
	}

	disableRequest := httptest.NewRequest("GET", "/", nil)
	disableRequest.Header.Set("X-Features", "________0")
	disabled := processFeatureControl(cfg, disableRequest, ruleSet)
	if disabled&dataType.FeatureCountryRule != 0 {
		t.Fatal("CountryRule bit remains enabled after position 8 override")
	}

	ruleSet.CountryRule.Enabled = false
	enableRequest := httptest.NewRequest("GET", "/", nil)
	enableRequest.Header.Set("X-Features", "________1")
	enabled := processFeatureControl(cfg, enableRequest, ruleSet)
	if enabled&dataType.FeatureCountryRule == 0 {
		t.Fatal("CountryRule bit remains disabled after position 8 override")
	}
}

func TestCheckMainCountryRulesWithGeoLiteDatabase(t *testing.T) {
	databasePath := filepath.Join("..", "..", "config_example", "data", "GeoLite2-Country.mmdb")
	if _, err := os.Stat(databasePath); errors.Is(err, os.ErrNotExist) {
		t.Skipf("GeoLite2 test database is not present at %s", databasePath)
	} else if err != nil {
		t.Fatalf("Stat GeoLite2 database: %v", err)
	}

	database := geoip.NewCountryDatabase(databasePath)
	defer database.CloseOrWarn()

	ruleSet := featureControlRuleSet()
	ruleSet.CountryRule = &dataType.CountryRule{
		Enabled:          true,
		CAPTCHACountries: map[string]struct{}{"US": {}},
		BlockCountries:   map[string]struct{}{"CN": {}},
	}
	ruleSet.CAPTCHARule = &dataType.CaptchaRule{
		SecretKey:                      "1234567890abcdef",
		CaptchaValidateTime:            60,
		CaptchaChallengeSessionTimeout: 120,
		CaptchaFailureLimit:            map[int64]int64{},
	}
	sharedMem := &dataType.SharedMemory{CountryResolver: database}
	sharedMem.CaptchaFailureLimitCounter.Store(dataType.NewCounter(16, 1))

	tests := []struct {
		name        string
		remoteIP    string
		wantCountry string
		wantStatus  int
		wantAction  string
	}{
		{name: "US requires CAPTCHA", remoteIP: "8.8.8.8", wantCountry: "US", wantStatus: 445, wantAction: "CAPTCHA"},
		{name: "CN is blocked", remoteIP: "114.114.114.114", wantCountry: "CN", wantStatus: 445, wantAction: "403"},
		{name: "DE passes normally", remoteIP: "84.200.69.80", wantCountry: "DE", wantStatus: 200},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			country, err := database.Country(netip.MustParseAddr(tt.remoteIP))
			if err != nil {
				t.Fatalf("Country(%s) returned error: %v", tt.remoteIP, err)
			}
			if country != tt.wantCountry {
				t.Fatalf("Country(%s) = %q, want %q", tt.remoteIP, country, tt.wantCountry)
			}

			recorder := httptest.NewRecorder()
			CheckMain(recorder, dataType.UserRequest{
				RemoteIP:       tt.remoteIP,
				FeatureControl: dataType.FeatureCountryRule,
			}, ruleSet, &config.MainConfig{}, sharedMem)

			if recorder.Code != tt.wantStatus {
				t.Fatalf("response status = %d, want %d", recorder.Code, tt.wantStatus)
			}
			if got := recorder.Header().Get("Torii-Action"); got != tt.wantAction {
				t.Fatalf("Torii-Action = %q, want %q", got, tt.wantAction)
			}
		})
	}
}

func featureControlRuleSet() *config.RuleSet {
	return &config.RuleSet{
		IPAllowRule:           &dataType.IPAllowRule{},
		IPBlockRule:           &dataType.IPBlockRule{},
		URLAllowRule:          &dataType.URLAllowRule{},
		URLBlockRule:          &dataType.URLBlockRule{},
		VerifyBotRule:         &dataType.VerifyBotRule{},
		HTTPFloodRule:         &dataType.HTTPFloodRule{},
		CAPTCHARule:           &dataType.CaptchaRule{},
		ExternalMigrationRule: &dataType.ExternalMigrationRule{},
		CountryRule:           &dataType.CountryRule{Enabled: true},
	}
}

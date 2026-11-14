package server

import (
	"errors"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"server_torii/internal/config"
	"server_torii/internal/geoip"
	"server_torii/internal/iptrie"
	"server_torii/internal/ratelimit"
	"server_torii/internal/request"
	"server_torii/internal/state"
	"testing"
)

type serverCountryResolver struct {
	country string
}

func (r serverCountryResolver) Country(netip.Addr) (string, error) {
	return r.country, nil
}

func TestIPAllowBypassesCountryRule(t *testing.T) {
	_, allowedNetwork, err := net.ParseCIDR("8.8.8.8/32")
	if err != nil {
		t.Fatalf("ParseCIDR returned error: %v", err)
	}
	trie := &iptrie.TrieNode{}
	trie.Insert(allowedNetwork)
	ruleSet := &config.RuleSet{
		IPAllowRule: &config.IPListRule{Enabled: true, Trie: trie},
		CountryRule: &config.CountryRule{
			Enabled:   true,
			Countries: map[string]config.CountryAction{"US": config.CountryBlock},
		},
	}
	reqData := request.UserRequest{
		RemoteIP:       "8.8.8.8",
		FeatureControl: request.FeatureIPAllow | request.FeatureCountryRule,
	}
	rt := &state.Runtime{CountryResolver: serverCountryResolver{country: "US"}}
	if got := decide(rt, reqData, ruleSet); got != "pass" {
		t.Fatalf("decision = %q, want pass: allowlist bypass", got)
	}
}

func TestFeatureOverridesCountryRuleBit(t *testing.T) {
	ruleSet := featureControlRuleSet()

	if featureBits(ruleSet, "")&request.FeatureCountryRule == 0 {
		t.Fatal("CountryRule baseline bit is disabled, want enabled")
	}
	if featureBits(ruleSet, "-country_rule")&request.FeatureCountryRule != 0 {
		t.Fatal("CountryRule bit remains enabled after the override")
	}

	ruleSet.CountryRule.Enabled = false
	if featureBits(ruleSet, "+country_rule")&request.FeatureCountryRule == 0 {
		t.Fatal("CountryRule bit remains disabled after the override")
	}
}

func TestCountryRulesWithGeoLiteDatabase(t *testing.T) {
	databasePath := filepath.Join("..", "..", "config_example", "data", "GeoLite2-Country.mmdb")
	if _, err := os.Stat(databasePath); errors.Is(err, os.ErrNotExist) {
		t.Skipf("GeoLite2 test database is not present at %s", databasePath)
	} else if err != nil {
		t.Fatalf("Stat GeoLite2 database: %v", err)
	}

	database := geoip.NewCountryDatabase(databasePath)
	defer database.CloseOrWarn()

	ruleSet := featureControlRuleSet()
	ruleSet.CountryRule = &config.CountryRule{
		Enabled:   true,
		Countries: map[string]config.CountryAction{"US": config.CountryCaptcha, "CN": config.CountryBlock},
	}
	ruleSet.CAPTCHARule = &config.CaptchaRule{
		SecretKey:                      "1234567890abcdef",
		CaptchaValidateTime:            60,
		CaptchaChallengeSessionTimeout: 120,
		CaptchaFailureLimit:            map[int64]int64{},
	}
	sharedMem := &state.Runtime{CountryResolver: database}
	sharedMem.CaptchaFailureLimitCounter.Store(ratelimit.NewCounter(16, 1))

	tests := []struct {
		name        string
		remoteIP    string
		wantCountry string
		want        string
	}{
		{name: "US requires CAPTCHA", remoteIP: "8.8.8.8", wantCountry: "US", want: "captcha"},
		{name: "CN is blocked", remoteIP: "114.114.114.114", wantCountry: "CN", want: "block"},
		{name: "DE passes normally", remoteIP: "84.200.69.80", wantCountry: "DE", want: "pass"},
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

			got := decide(sharedMem, request.UserRequest{
				RemoteIP:       tt.remoteIP,
				FeatureControl: request.FeatureCountryRule,
			}, ruleSet)
			if got != tt.want {
				t.Fatalf("decision = %q, want %q", got, tt.want)
			}
		})
	}
}

func featureControlRuleSet() *config.RuleSet {
	return &config.RuleSet{
		IPAllowRule:           &config.IPListRule{},
		IPBlockRule:           &config.IPListRule{},
		URLAllowRule:          &config.URLListRule{},
		URLBlockRule:          &config.URLListRule{},
		VerifyBotRule:         &config.VerifyBotRule{},
		HTTPFloodRule:         &config.HTTPFloodRule{},
		CAPTCHARule:           &config.CaptchaRule{},
		ExternalMigrationRule: &config.ExternalMigrationRule{},
		CountryRule:           &config.CountryRule{Enabled: true},
	}
}

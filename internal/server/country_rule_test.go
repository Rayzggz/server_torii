package server

import (
	"net"
	"net/http/httptest"
	"net/netip"
	"server_torii/internal/config"
	"server_torii/internal/dataType"
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

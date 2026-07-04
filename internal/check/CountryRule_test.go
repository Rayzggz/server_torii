package check

import (
	"errors"
	"net/netip"
	"server_torii/internal/action"
	"server_torii/internal/config"
	"server_torii/internal/dataType"
	"testing"
)

type fakeCountryResolver struct {
	country string
	err     error
	calls   int
}

func (r *fakeCountryResolver) Country(netip.Addr) (string, error) {
	r.calls++
	return r.country, r.err
}

func TestCountryRuleBlock(t *testing.T) {
	resolver := &fakeCountryResolver{country: "cn"}
	ruleSet := countryTestRuleSet()
	ruleSet.CountryRule.BlockCountries["CN"] = struct{}{}
	decision := action.NewDecision()

	CountryRule(dataType.UserRequest{
		RemoteIP:       "8.8.8.8",
		FeatureControl: dataType.FeatureCountryRule,
	}, ruleSet, decision, &dataType.SharedMemory{CountryResolver: resolver})

	if string(decision.HTTPCode) != "403" || decision.State != action.Done {
		t.Fatalf("decision = %#v, want blocking 403", decision)
	}
}

func TestCountryRuleCaptcha(t *testing.T) {
	resolver := &fakeCountryResolver{country: "US"}
	ruleSet := countryTestRuleSet()
	ruleSet.CountryRule.CAPTCHACountries["US"] = struct{}{}
	sharedMem := &dataType.SharedMemory{CountryResolver: resolver}
	sharedMem.CaptchaFailureLimitCounter.Store(dataType.NewCounter(16, 1))
	decision := action.NewDecision()

	CountryRule(dataType.UserRequest{
		RemoteIP:       "8.8.8.8",
		FeatureControl: dataType.FeatureCountryRule,
	}, ruleSet, decision, sharedMem)

	if string(decision.HTTPCode) != "CAPTCHA" || decision.State != action.Done {
		t.Fatalf("decision = %#v, want CAPTCHA challenge", decision)
	}
}

func TestCountryRuleInvertedBlock(t *testing.T) {
	tests := []struct {
		name     string
		country  string
		wantDone bool
		wantCode string
	}{
		{name: "listed country continues", country: "US", wantCode: "200"},
		{name: "unlisted country blocks", country: "CN", wantDone: true, wantCode: "403"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ruleSet := countryTestRuleSet()
			ruleSet.CountryRule.BlockNot = true
			ruleSet.CountryRule.BlockCountries["US"] = struct{}{}
			decision := action.NewDecision()

			CountryRule(dataType.UserRequest{
				RemoteIP:       "8.8.8.8",
				FeatureControl: dataType.FeatureCountryRule,
			}, ruleSet, decision, &dataType.SharedMemory{
				CountryResolver: &fakeCountryResolver{country: tt.country},
			})

			if gotDone := decision.State == action.Done; gotDone != tt.wantDone ||
				string(decision.HTTPCode) != tt.wantCode {
				t.Fatalf("decision = %#v, want done %t and code %s", decision, tt.wantDone, tt.wantCode)
			}
		})
	}
}

func TestCountryRuleInvertedCaptcha(t *testing.T) {
	tests := []struct {
		name     string
		country  string
		wantDone bool
		wantCode string
	}{
		{name: "listed country continues", country: "US", wantCode: "200"},
		{name: "unlisted country challenges", country: "DE", wantDone: true, wantCode: "CAPTCHA"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ruleSet := countryTestRuleSet()
			ruleSet.CountryRule.CAPTCHANot = true
			ruleSet.CountryRule.CAPTCHACountries["US"] = struct{}{}
			sharedMem := &dataType.SharedMemory{
				CountryResolver: &fakeCountryResolver{country: tt.country},
			}
			sharedMem.CaptchaFailureLimitCounter.Store(dataType.NewCounter(16, 1))
			decision := action.NewDecision()

			CountryRule(dataType.UserRequest{
				RemoteIP:       "8.8.8.8",
				FeatureControl: dataType.FeatureCountryRule,
			}, ruleSet, decision, sharedMem)

			if gotDone := decision.State == action.Done; gotDone != tt.wantDone ||
				string(decision.HTTPCode) != tt.wantCode {
				t.Fatalf("decision = %#v, want done %t and code %s", decision, tt.wantDone, tt.wantCode)
			}
		})
	}
}

func TestCountryRuleInvertedEmptyListMatchesResolvedCountry(t *testing.T) {
	ruleSet := countryTestRuleSet()
	ruleSet.CountryRule.BlockNot = true
	decision := action.NewDecision()

	CountryRule(dataType.UserRequest{
		RemoteIP:       "8.8.8.8",
		FeatureControl: dataType.FeatureCountryRule,
	}, ruleSet, decision, &dataType.SharedMemory{
		CountryResolver: &fakeCountryResolver{country: "CN"},
	})

	if decision.State != action.Done || string(decision.HTTPCode) != "403" {
		t.Fatalf("decision = %#v, want blocking 403", decision)
	}
}

func TestCountryRuleFailOpenCases(t *testing.T) {
	tests := []struct {
		name     string
		remoteIP string
		resolver *fakeCountryResolver
	}{
		{name: "unlisted country", remoteIP: "8.8.8.8", resolver: &fakeCountryResolver{country: "DE"}},
		{name: "lookup error", remoteIP: "8.8.8.8", resolver: &fakeCountryResolver{err: errors.New("lookup failed")}},
		{name: "empty lookup", remoteIP: "8.8.8.8", resolver: &fakeCountryResolver{}},
		{name: "invalid IP", remoteIP: "not-an-ip", resolver: &fakeCountryResolver{country: "CN"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ruleSet := countryTestRuleSet()
			ruleSet.CountryRule.BlockCountries["CN"] = struct{}{}
			decision := action.NewDecision()

			CountryRule(dataType.UserRequest{
				RemoteIP:       tt.remoteIP,
				FeatureControl: dataType.FeatureCountryRule,
			}, ruleSet, decision, &dataType.SharedMemory{CountryResolver: tt.resolver})

			if decision.State != action.Continue || string(decision.HTTPCode) != "200" {
				t.Fatalf("decision = %#v, want fail-open continue", decision)
			}
		})
	}
}

func TestCountryRuleInvertedFailOpenCases(t *testing.T) {
	tests := []struct {
		name     string
		remoteIP string
		resolver *fakeCountryResolver
	}{
		{name: "lookup error", remoteIP: "8.8.8.8", resolver: &fakeCountryResolver{err: errors.New("lookup failed")}},
		{name: "empty lookup", remoteIP: "8.8.8.8", resolver: &fakeCountryResolver{}},
		{name: "invalid IP", remoteIP: "not-an-ip", resolver: &fakeCountryResolver{country: "CN"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ruleSet := countryTestRuleSet()
			ruleSet.CountryRule.BlockNot = true
			decision := action.NewDecision()

			CountryRule(dataType.UserRequest{
				RemoteIP:       tt.remoteIP,
				FeatureControl: dataType.FeatureCountryRule,
			}, ruleSet, decision, &dataType.SharedMemory{CountryResolver: tt.resolver})

			if decision.State != action.Continue || string(decision.HTTPCode) != "200" {
				t.Fatalf("decision = %#v, want fail-open continue", decision)
			}
		})
	}
}

func TestCountryRuleDisabledSkipsLookup(t *testing.T) {
	resolver := &fakeCountryResolver{country: "CN"}
	ruleSet := countryTestRuleSet()
	ruleSet.CountryRule.BlockCountries["CN"] = struct{}{}
	decision := action.NewDecision()

	CountryRule(dataType.UserRequest{RemoteIP: "8.8.8.8"}, ruleSet, decision, &dataType.SharedMemory{CountryResolver: resolver})

	if resolver.calls != 0 {
		t.Fatalf("resolver calls = %d, want 0", resolver.calls)
	}
	if decision.State != action.Continue {
		t.Fatalf("decision state = %v, want Continue", decision.State)
	}
}

func countryTestRuleSet() *config.RuleSet {
	return &config.RuleSet{
		CountryRule: &dataType.CountryRule{
			Enabled:          true,
			CAPTCHACountries: make(map[string]struct{}),
			BlockCountries:   make(map[string]struct{}),
		},
		CAPTCHARule: &dataType.CaptchaRule{
			SecretKey:                      "1234567890abcdef",
			CaptchaValidateTime:            60,
			CaptchaChallengeSessionTimeout: 120,
			CaptchaFailureLimit:            map[int64]int64{},
		},
	}
}

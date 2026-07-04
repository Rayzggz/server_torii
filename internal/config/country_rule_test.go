package config

import (
	"server_torii/internal/dataType"
	"testing"
)

func TestMapCountryRuleNormalizesAndDeduplicates(t *testing.T) {
	dest := &dataType.CountryRule{}
	err := mapCountryRule(&countryRuleWrapper{
		Enabled:          true,
		CAPTCHACountries: []string{" us ", "US", "ca"},
		BlockCountries:   []string{"cn", "CN", "RU"},
	}, dest)
	if err != nil {
		t.Fatalf("mapCountryRule returned unexpected error: %v", err)
	}

	if !dest.Enabled {
		t.Fatal("CountryRule.Enabled = false, want true")
	}
	if len(dest.CAPTCHACountries) != 2 {
		t.Fatalf("CAPTCHACountries length = %d, want 2", len(dest.CAPTCHACountries))
	}
	if _, ok := dest.CAPTCHACountries["US"]; !ok {
		t.Fatal("CAPTCHACountries does not contain normalized US code")
	}
	if _, ok := dest.CAPTCHACountries["CA"]; !ok {
		t.Fatal("CAPTCHACountries does not contain normalized CA code")
	}
	if len(dest.BlockCountries) != 2 {
		t.Fatalf("BlockCountries length = %d, want 2", len(dest.BlockCountries))
	}
}

func TestMapCountryRuleRejectsInvalidCode(t *testing.T) {
	err := mapCountryRule(&countryRuleWrapper{
		CAPTCHACountries: []string{"USA"},
	}, &dataType.CountryRule{})
	if err == nil {
		t.Fatal("mapCountryRule error = nil, want invalid country-code error")
	}
}

func TestMapCountryRuleRejectsOverlappingActions(t *testing.T) {
	err := mapCountryRule(&countryRuleWrapper{
		CAPTCHACountries: []string{"us"},
		BlockCountries:   []string{"US"},
	}, &dataType.CountryRule{})
	if err == nil {
		t.Fatal("mapCountryRule error = nil, want overlapping-action error")
	}
}

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
	if dest.CAPTCHANot || dest.BlockNot {
		t.Fatal("CountryRule NOT flags = true, want false defaults")
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

func TestMapCountryRuleMapsNotFlagsForComplementaryActions(t *testing.T) {
	tests := []struct {
		name       string
		captchaNot bool
		blockNot   bool
	}{
		{name: "inverted block", blockNot: true},
		{name: "inverted CAPTCHA", captchaNot: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dest := &dataType.CountryRule{}
			err := mapCountryRule(&countryRuleWrapper{
				Enabled:          true,
				CAPTCHANot:       tt.captchaNot,
				BlockNot:         tt.blockNot,
				CAPTCHACountries: []string{"us"},
				BlockCountries:   []string{"US"},
			}, dest)
			if err != nil {
				t.Fatalf("mapCountryRule returned unexpected error: %v", err)
			}

			if dest.CAPTCHANot != tt.captchaNot {
				t.Fatalf("CountryRule.CAPTCHANot = %t, want %t", dest.CAPTCHANot, tt.captchaNot)
			}
			if dest.BlockNot != tt.blockNot {
				t.Fatalf("CountryRule.BlockNot = %t, want %t", dest.BlockNot, tt.blockNot)
			}
		})
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
	tests := []struct {
		name    string
		wrapper countryRuleWrapper
	}{
		{
			name: "normal and normal",
			wrapper: countryRuleWrapper{
				CAPTCHACountries: []string{"us"},
				BlockCountries:   []string{"US"},
			},
		},
		{
			name: "normal block and inverted CAPTCHA",
			wrapper: countryRuleWrapper{
				CAPTCHANot:       true,
				CAPTCHACountries: []string{"CN"},
				BlockCountries:   []string{"US"},
			},
		},
		{
			name: "inverted block and normal CAPTCHA",
			wrapper: countryRuleWrapper{
				BlockNot:         true,
				CAPTCHACountries: []string{"CN"},
				BlockCountries:   []string{"US"},
			},
		},
		{
			name: "inverted and inverted",
			wrapper: countryRuleWrapper{
				CAPTCHANot:       true,
				BlockNot:         true,
				CAPTCHACountries: []string{"US"},
				BlockCountries:   []string{"CN"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := mapCountryRule(&tt.wrapper, &dataType.CountryRule{})
			if err == nil {
				t.Fatal("mapCountryRule error = nil, want overlapping-action error")
			}
		})
	}
}

func TestMapCountryRuleAllowsInvertedEmptyAction(t *testing.T) {
	dest := &dataType.CountryRule{}
	err := mapCountryRule(&countryRuleWrapper{BlockNot: true}, dest)
	if err != nil {
		t.Fatalf("mapCountryRule returned unexpected error: %v", err)
	}
	if !dest.BlockNot {
		t.Fatal("CountryRule.BlockNot = false, want true")
	}
}

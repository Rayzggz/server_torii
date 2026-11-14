package feature

import (
	"strings"
	"testing"
)

func TestPipelineOrder(t *testing.T) {
	// The order decides which rule wins when several match; changing it changes behavior.
	want := "Lists CustomRules CountryRule VerifyBot ActionRule HTTPFlood Challenge"
	var names []string
	for _, c := range Pipeline() {
		names = append(names, c.String())
	}
	if got := strings.Join(names, " "); got != want {
		t.Fatalf("pipeline = %s\nwant       %s", got, want)
	}
	if Count.String() != "UNKNOWN" || Count.ControlMask() != 0 || Count.SkipMask() != 0 {
		t.Fatal("out-of-range check is not inert")
	}
}

func TestMasksAreDistinct(t *testing.T) {
	var control uint16
	var skip uint32
	for _, c := range Pipeline() {
		if m := c.ControlMask(); m != 0 {
			if m&(m-1) != 0 || control&m != 0 {
				t.Errorf("%s control mask %b is not a distinct single bit", c, m)
			}
			control |= m
		} else if c != ActionRule && c != Lists {
			t.Errorf("%s has no feature control bit", c)
		}
		if m := c.SkipMask(); m != 0 {
			if skip&m != 0 {
				t.Errorf("%s skip mask %b overlaps", c, m)
			}
			skip |= m
		}
		// Only checks that run after CustomRules, and CustomRules itself, can be skipped.
		if (c.SkipMask() != 0) != (c >= CustomRules) {
			t.Errorf("%s skippable = %v", c, c.SkipMask() != 0)
		}
	}
}

func TestParseSkipTargets(t *testing.T) {
	mask, err := ParseSkipTargets([]string{"HTTPFlood", "Challenge"})
	if err != nil || mask != HTTPFlood.SkipMask()|Challenge.SkipMask() {
		t.Fatalf("ParseSkipTargets = %b, %v", mask, err)
	}
	if mask, err := ParseSkipTargets(nil); err != nil || mask != 0 {
		t.Fatalf("no targets = %b, %v", mask, err)
	}
	_, err = ParseSkipTargets([]string{"Lists"})
	if err == nil {
		t.Fatal("Lists runs before CustomRules and must not be a skip target")
	}
	const want = `invalid skip target "Lists": expected one of CustomRules, CountryRule, VerifyBot, ActionRule, HTTPFlood, Challenge`
	if err.Error() != want {
		t.Fatalf("error = %s", err)
	}
}

func TestByName(t *testing.T) {
	for name, want := range map[string]Check{"HTTPFlood": HTTPFlood, "http_flood": HTTPFlood, "http-flood": HTTPFlood, "lists": Lists, "ActionRule": ActionRule} {
		if got, ok := ByName(name); !ok || got != want {
			t.Errorf("ByName(%q) = %s, %v", name, got, ok)
		}
	}
	if _, ok := ByName("ip_allow"); ok {
		t.Error("ip_allow is no longer a check")
	}
	// Lists and ActionRule are checks, but neither has a switch.
	for _, name := range []string{"lists", "action_rule", "ip_allow"} {
		if _, ok := ControlMaskByName(name); ok {
			t.Errorf("%s has a switch", name)
		}
	}
}

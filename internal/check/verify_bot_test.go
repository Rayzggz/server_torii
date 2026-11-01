package check

import (
	"server_torii/internal/action"
	"server_torii/internal/config"
	"server_torii/internal/dataType"
	"testing"
	"time"
)

type recordingMarker struct{ neutral, verified []string }

func (m *recordingMarker) MarkVerified(ip string, _ time.Duration) {
	m.verified = append(m.verified, ip)
}
func (m *recordingMarker) MarkNeutral(ip string, _ time.Duration) { m.neutral = append(m.neutral, ip) }

func allBotsRuleSet() *config.RuleSet {
	return &config.RuleSet{VerifyBotRule: &dataType.VerifyBotRule{
		Enabled:         true,
		VerifyGoogleBot: true,
		VerifyBingBot:   true,
		VerifyBaiduBot:  true,
		VerifyYandexBot: true,
		VerifySogouBot:  true,
		VerifyAppleBot:  true,
	}}
}

func TestVerifyBotSkipsWithoutDNS(t *testing.T) {
	tests := []struct {
		name    string
		feature uint16
		ua      string
		ruleSet *config.RuleSet
	}{
		{"feature disabled", 0, "Googlebot/2.1", allBotsRuleSet()},
		{"ordinary browser", dataType.FeatureVerifyBot, "Mozilla/5.0 (Windows NT 10.0) Chrome/120", allBotsRuleSet()},
		{"empty user agent", dataType.FeatureVerifyBot, "", allBotsRuleSet()},
		{"googlebot verification off", dataType.FeatureVerifyBot, "Mozilla/5.0 (compatible; Googlebot/2.1)", &config.RuleSet{VerifyBotRule: &dataType.VerifyBotRule{VerifyBingBot: true}}},
		{"bingbot verification off", dataType.FeatureVerifyBot, "Mozilla/5.0 (compatible; bingbot/2.0)", &config.RuleSet{VerifyBotRule: &dataType.VerifyBotRule{VerifyGoogleBot: true}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			marker := &recordingMarker{}
			reqData := dataType.UserRequest{RemoteIP: "127.0.0.1", UserAgent: tt.ua, FeatureControl: tt.feature}
			decision := action.NewDecision()
			VerifyBot(reqData, tt.ruleSet, decision, &dataType.SharedMemory{AdaptiveTrafficAnalyzer: marker})
			if decision.State != action.Continue {
				t.Fatalf("state = %v, want Continue", decision.State)
			}
			if len(marker.neutral) != 0 {
				t.Fatalf("unverified client marked neutral: %v", marker.neutral)
			}
		})
	}
}

// Loopback never reverse-resolves to a crawler domain, so a crawler user agent from it is spoofed.
func TestVerifyBotBlocksSpoofedCrawlers(t *testing.T) {
	for _, ua := range []string{
		"Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
		"Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)",
		"Mozilla/5.0 (compatible; Baiduspider/2.0)",
		"Mozilla/5.0 (compatible; YandexBot/3.0; +http://yandex.com/bots)",
		"Sogou web spider/4.0",
		"Mozilla/5.0 (Macintosh) Applebot/0.1",
	} {
		t.Run(ua, func(t *testing.T) {
			marker := &recordingMarker{}
			reqData := dataType.UserRequest{RemoteIP: "127.0.0.1", UserAgent: ua, FeatureControl: dataType.FeatureVerifyBot}
			decision := action.NewDecision()
			VerifyBot(reqData, allBotsRuleSet(), decision, &dataType.SharedMemory{AdaptiveTrafficAnalyzer: marker})
			if decision.State != action.Done || string(decision.HTTPCode) != "403" {
				t.Fatalf("decision = (%v, %q), want (Done, 403)", decision.State, decision.HTTPCode)
			}
			if len(marker.neutral) != 0 {
				t.Fatalf("spoofed crawler marked neutral: %v", marker.neutral)
			}
		})
	}
}

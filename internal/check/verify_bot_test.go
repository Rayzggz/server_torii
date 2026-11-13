package check

import (
	"server_torii/internal/action"
	"server_torii/internal/config"
	"server_torii/internal/request"
	"server_torii/internal/state"
	"testing"
	"time"
)

type recordingMarker struct{ neutral, verified []string }

func (m *recordingMarker) MarkVerified(ip string, _ time.Duration) {
	m.verified = append(m.verified, ip)
}
func (m *recordingMarker) MarkNeutral(ip string, _ time.Duration) { m.neutral = append(m.neutral, ip) }

func allBotsRuleSet() *config.RuleSet {
	return &config.RuleSet{VerifyBotRule: &config.VerifyBotRule{
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
		{"ordinary browser", request.FeatureVerifyBot, "Mozilla/5.0 (Windows NT 10.0) Chrome/120", allBotsRuleSet()},
		{"empty user agent", request.FeatureVerifyBot, "", allBotsRuleSet()},
		{"googlebot verification off", request.FeatureVerifyBot, "Mozilla/5.0 (compatible; Googlebot/2.1)", &config.RuleSet{VerifyBotRule: &config.VerifyBotRule{VerifyBingBot: true}}},
		{"bingbot verification off", request.FeatureVerifyBot, "Mozilla/5.0 (compatible; bingbot/2.0)", &config.RuleSet{VerifyBotRule: &config.VerifyBotRule{VerifyGoogleBot: true}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			marker := &recordingMarker{}
			reqData := request.UserRequest{RemoteIP: "127.0.0.1", UserAgent: tt.ua, FeatureControl: tt.feature}
			decision := action.NewDecision()
			VerifyBot(reqData, tt.ruleSet, decision, &state.Runtime{TrafficMarker: marker})
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
			reqData := request.UserRequest{RemoteIP: "127.0.0.1", UserAgent: ua, FeatureControl: request.FeatureVerifyBot}
			decision := action.NewDecision()
			VerifyBot(reqData, allBotsRuleSet(), decision, &state.Runtime{TrafficMarker: marker})
			if decision.State != action.Done || decision.Verdict != action.VerdictBlock {
				t.Fatalf("decision = (%v, %q), want (Done, 403)", decision.State, decision.Verdict)
			}
			if len(marker.neutral) != 0 {
				t.Fatalf("spoofed crawler marked neutral: %v", marker.neutral)
			}
		})
	}
}

func TestHostInDomain(t *testing.T) {
	tests := []struct {
		host, domain string
		want         bool
	}{
		{"crawl-66-249-66-1.googlebot.com.", "googlebot.com", true},
		{"crawl-66-249-66-1.googlebot.com", "googlebot.com", true},
		{"CRAWL-66-249-66-1.GOOGLEBOT.COM.", "googlebot.com", true},
		{"googlebot.com", "googlebot.com", true},
		{"rate-limited-proxy-66-249-90-1.google.com.", "google.com", true},
		{"msnbot-157-55-39-1.search.msn.com.", "search.msn.com", true},
		{"17-58-98-1.applebot.apple.com.", "apple.com", true},
		// Attacker-controlled reverse DNS that only contains the crawler domain.
		{"crawl.googlebot.com.attacker.example.", "googlebot.com", false},
		{"googlebot.com.attacker.example", "googlebot.com", false},
		{"evilgooglebot.com.", "googlebot.com", false},
		{"fakegoogle.com.", "google.com", false},
		{"apple.com.lk.", "apple.com", false},
		{"search.msn.com.evil.example.", "search.msn.com", false},
		{"msn.com.", "search.msn.com", false},
		{"", "googlebot.com", false},
		{".", "googlebot.com", false},
	}
	for _, tt := range tests {
		if got := hostInDomain(tt.host, tt.domain); got != tt.want {
			t.Errorf("hostInDomain(%q, %q) = %v, want %v", tt.host, tt.domain, got, tt.want)
		}
	}
}

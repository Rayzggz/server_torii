package check

import (
	"server_torii/internal/action"
	"server_torii/internal/config"
	"server_torii/internal/request"
	"server_torii/internal/state"
	"strings"
	"time"
)

// verifiedBotMarkTTL keeps verified crawlers out of traffic analysis.
const verifiedBotMarkTTL = time.Hour

func VerifyBot(reqData request.UserRequest, ruleSet *config.RuleSet, decision *action.Decision, rt *state.Runtime) {
	ua := strings.ToLower(reqData.UserAgent)

	var bot string
	var exptractRDNS []string
	switch {
	case strings.Contains(ua, "googlebot") && ruleSet.VerifyBotRule.Verifies("google"):
		// Not googleusercontent.com: every Google Cloud VM reverse-resolves there.
		bot, exptractRDNS = "google", []string{"googlebot.com", "google.com"}
	case strings.Contains(ua, "bingbot") && ruleSet.VerifyBotRule.Verifies("bing"):
		bot, exptractRDNS = "bing", []string{"search.msn.com"}
	case strings.Contains(ua, "baiduspider") && ruleSet.VerifyBotRule.Verifies("baidu"):
		bot, exptractRDNS = "baidu", []string{"baidu.com", "baidu.jp"}
	case strings.Contains(ua, "yandex.com/bots") && ruleSet.VerifyBotRule.Verifies("yandex"):
		bot, exptractRDNS = "yandex", []string{"yandex.com", "yandex.ru", "yandex.net"}
	case strings.Contains(ua, "sogou web spider") && ruleSet.VerifyBotRule.Verifies("sogou"):
		bot, exptractRDNS = "sogou", []string{"sogou.com"}
	case strings.Contains(ua, "applebot") && ruleSet.VerifyBotRule.Verifies("apple"):
		bot, exptractRDNS = "apple", []string{"apple.com"}
	default:
		return
	}

	ip := reqData.ClientAddr()
	if !ip.IsValid() {
		decision.Note = bot + ": the client address is not an IP address"
		decision.SetVerdict(action.Done, action.VerdictBlock)
		return
	}

	verified, _, err := defaultBotVerifier.verify(ip, bot, exptractRDNS, rt.Log())
	if verified {
		rt.MarkNeutral(reqData.Site, reqData.ClientKey(), verifiedBotMarkTTL)
		decision.Set(action.Done)
		return
	}
	decision.Note = bot + ": not confirmed by DNS"
	if err != nil {
		decision.Note = bot + ": " + err.Error()
	}
	decision.SetVerdict(action.Done, action.VerdictBlock)
}

// hostInDomain reports whether host is domain or one of its subdomains.
// A substring match would accept attacker-controlled names such as "googlebot.com.example.net".
func hostInDomain(host, domain string) bool {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	return host == domain || strings.HasSuffix(host, "."+domain)
}

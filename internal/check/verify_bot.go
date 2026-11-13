package check

import (
	"fmt"
	"net"
	"server_torii/internal/action"
	"server_torii/internal/config"
	"server_torii/internal/logx"
	"server_torii/internal/request"
	"server_torii/internal/state"
	"strings"
	"time"
)

// verifiedBotMarkTTL keeps verified crawlers out of traffic analysis.
const verifiedBotMarkTTL = time.Hour

func VerifyBot(reqData request.UserRequest, ruleSet *config.RuleSet, decision *action.Decision, rt *state.Runtime) {
	// Check if VerifyBot feature is enabled using binary operation
	if (reqData.FeatureControl & request.FeatureVerifyBot) == 0 {
		decision.Set(action.Continue)
		return
	}

	ua := strings.ToLower(reqData.UserAgent)

	var bot string
	var exptractRDNS []string
	switch {
	case strings.Contains(ua, "googlebot") && ruleSet.VerifyBotRule.VerifyGoogleBot:
		// Not googleusercontent.com: every Google Cloud VM reverse-resolves there.
		bot, exptractRDNS = "google", []string{"googlebot.com", "google.com"}
	case strings.Contains(ua, "bingbot") && ruleSet.VerifyBotRule.VerifyBingBot:
		bot, exptractRDNS = "bing", []string{"search.msn.com"}
	case strings.Contains(ua, "baiduspider") && ruleSet.VerifyBotRule.VerifyBaiduBot:
		bot, exptractRDNS = "baidu", []string{"baidu.com", "baidu.jp"}
	case strings.Contains(ua, "yandex.com/bots") && ruleSet.VerifyBotRule.VerifyYandexBot:
		bot, exptractRDNS = "yandex", []string{"yandex.com", "yandex.ru", "yandex.net"}
	case strings.Contains(ua, "sogou web spider") && ruleSet.VerifyBotRule.VerifySogouBot:
		bot, exptractRDNS = "sogou", []string{"sogou.com"}
	case strings.Contains(ua, "applebot") && ruleSet.VerifyBotRule.VerifyAppleBot:
		bot, exptractRDNS = "apple", []string{"apple.com"}
	default:
		decision.Set(action.Continue)
		return
	}

	ip := net.ParseIP(reqData.RemoteIP)
	if ip == nil {
		logx.Info(reqData, "", fmt.Sprintf("VerifyBot: invalid remote IP %q", reqData.RemoteIP))
		decision.SetVerdict(action.Done, action.VerdictBlock)
		return
	}

	verified, fresh, err := defaultBotVerifier.verify(ip, bot, exptractRDNS)
	if verified {
		rt.MarkNeutral(reqData.RemoteIP, verifiedBotMarkTTL)
		decision.Set(action.Done)
		return
	}
	if fresh {
		if err != nil {
			logx.Info(reqData, "", fmt.Sprintf("VerifyBot: %s verification failed: %v", bot, err))
		} else {
			logx.Info(reqData, "", fmt.Sprintf("VerifyBot: %s not confirmed by DNS", bot))
		}
	}
	decision.SetVerdict(action.Done, action.VerdictBlock)
}

// hostInDomain reports whether host is domain or one of its subdomains.
// A substring match would accept attacker-controlled names such as "googlebot.com.example.net".
func hostInDomain(host, domain string) bool {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	return host == domain || strings.HasSuffix(host, "."+domain)
}

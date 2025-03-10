package check

import (
	"log"
	"net"
	"server_torii/internal/action"
	"server_torii/internal/config"
	"server_torii/internal/dataType"
	"strings"
)

func VerifyBot(reqData dataType.UserRequest, ruleSet *config.RuleSet, decision *action.Decision) {
	ua := strings.ToLower(reqData.UserAgent)

	var exptractRDNS []string
	switch {
	case strings.Contains(ua, "googlebot") && ruleSet.VerifyBotRule.VerifyGoogleBot:
		exptractRDNS = []string{"googlebot.com", "google.com", "googleusercontent.com"}
	case strings.Contains(ua, "bingbot") && ruleSet.VerifyBotRule.VerifyBingBot:
		exptractRDNS = []string{"search.msn.com"}
	case strings.Contains(ua, "baiduspider") && ruleSet.VerifyBotRule.VerifyBaiduBot:
		exptractRDNS = []string{"baidu.com", "baidu.jp"}
	case strings.Contains(ua, "yandex.com/bots") && ruleSet.VerifyBotRule.VerifyYandexBot:
		exptractRDNS = []string{"yandex.com", "yandex.ru", "yandex.net"}
	case strings.Contains(ua, "sogou web spider") && ruleSet.VerifyBotRule.VerifySogouBot:
		exptractRDNS = []string{"sogou.com"}
	case strings.Contains(ua, "applebot") && ruleSet.VerifyBotRule.VerifyAppleBot:
		exptractRDNS = []string{"apple.com"}
	default:
		decision.Set(action.Continue)
		return
	}

	actualRDNS, err := net.LookupAddr(reqData.RemoteIP)
	if err != nil {
		log.Printf("VerifyBot: LookupAddr failed for %s: %v", reqData.RemoteIP, err)
		decision.SetCode(action.Done, []byte("403"))
		return
	}

	for _, rdns := range exptractRDNS {
		for _, actual := range actualRDNS {
			if strings.Contains(actual, rdns) {
				ips, err := net.LookupIP(actual)
				if err != nil {
					log.Printf("VerifyBot: LookupIP failed for %s: %v", actual, err)
					decision.SetCode(action.Done, []byte("403"))
					return
				}
				for _, ip := range ips {
					if ip.String() == reqData.RemoteIP {
						decision.Set(action.Done)
						return
					}
				}
			}
		}
	}
	log.Printf("VerifyBot: IP lookup failed for %s: %v", reqData.RemoteIP, err)
	decision.SetCode(action.Done, []byte("403"))
	return

}

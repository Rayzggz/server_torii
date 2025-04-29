package check

import (
	"errors"
	"fmt"
	"net"
	"server_torii/internal/action"
	"server_torii/internal/config"
	"server_torii/internal/dataType"
	"server_torii/internal/utils"
	"strings"
)

func VerifyBot(reqData dataType.UserRequest, ruleSet *config.RuleSet, decision *action.Decision, sharedMem *dataType.SharedMemory) {
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
		var dnsErr *net.DNSError
		//ignore the error if it is a not found error
		if !(errors.As(err, &dnsErr) && dnsErr.IsNotFound) {
			utils.LogInfo(reqData, "", fmt.Sprintf("VerifyBot: lookupAddr failed: %v", err))
			decision.SetCode(action.Done, []byte("403"))
			return
		}
	}

	for _, rdns := range exptractRDNS {
		for _, actual := range actualRDNS {
			if strings.Contains(actual, rdns) {
				ips, err := net.LookupIP(actual)
				if err != nil {
					utils.LogInfo(reqData, "", fmt.Sprintf("VerifyBot: LookupIP failed: %v", err))
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
	utils.LogInfo(reqData, "", fmt.Sprintf("VerifyBot: LookupAddr failed: %v", err))
	decision.SetCode(action.Done, []byte("403"))
	return

}

package utils

import (
	"fmt"
	"github.com/medama-io/go-useragent"
	"regexp"
)

func GetClearanceUserAgent(inputUA string) string {
	if len(inputUA) < 8 || inputUA[:8] != "Mozilla/" {
		if inputUA == "" || regexp.MustCompile(`^\s*$`).MatchString(inputUA) {
			return "undefined"
		}
		return inputUA
	}
	ua := useragent.NewParser()
	agent := ua.Parse(inputUA)

	ret := fmt.Sprintf("Device:%v,OS:%v,Browser:%v,BrowserVersion:%v", agent.Device(), agent.OS(), agent.Browser(), agent.BrowserVersion())
	return ret

}

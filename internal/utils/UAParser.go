package utils

import (
	"fmt"
	"github.com/mssola/useragent"
	"regexp"
)

func GetClearanceUserAgent(inputUA string) string {
	if len(inputUA) < 8 || inputUA[:8] != "Mozilla/" {
		if inputUA == "" || regexp.MustCompile(`^\s*$`).MatchString(inputUA) {
			return "undefined"
		}
		return inputUA
	}

	ua := useragent.New(inputUA)

	engin, enginVersion := ua.Engine()
	browser, browserVersion := ua.Browser()

	ret := fmt.Sprintf("Mozilla:%v,Module:%v,Platform:%v,OS:%v,Engine:%v,EngineVersion:%v,Browser:%v,BrowserVersion:%v", ua.Mozilla(), ua.Model(), ua.Platform(), ua.OS(), engin, enginVersion, browser, browserVersion)
	return ret

}

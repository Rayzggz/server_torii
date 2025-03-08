package utils

import (
	"fmt"
	"github.com/mssola/useragent"
)

func GetClearanceUserAgent(inputUA string) string {
	if len(inputUA) < 8 || inputUA[:8] != "Mozilla/" {
		return inputUA
	}

	ua := useragent.New(inputUA)

	engin, enginVersion := ua.Engine()
	browser, browserVersion := ua.Browser()

	ret := fmt.Sprintf("Mozilla:%v,Module:%v,Platform:%v,OS:%v,Engine:%v,EngineVersion:%v,Browser:%v,BrowserVersion:%v", ua.Mozilla(), ua.Model(), ua.Platform(), ua.OS(), engin, enginVersion, browser, browserVersion)
	return ret

}

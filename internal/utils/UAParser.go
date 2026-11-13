package utils

import (
	"fmt"
	"regexp"

	"github.com/medama-io/go-useragent"
)

var (
	// uaParser is safe for concurrent use: Parse only reads the trie.
	uaParser       = useragent.NewParser()
	blankUAPattern = regexp.MustCompile(`^\s*$`)
)

func GetClearanceUserAgent(inputUA string) string {
	if len(inputUA) < 8 || inputUA[:8] != "Mozilla/" {
		if inputUA == "" || blankUAPattern.MatchString(inputUA) {
			return "undefined"
		}
		return inputUA
	}
	agent := uaParser.Parse(inputUA)

	return fmt.Sprintf("Device:%v,OS:%v,Browser:%v,BrowserVersion:%v", agent.Device(), agent.OS(), agent.Browser(), agent.BrowserVersion())
}

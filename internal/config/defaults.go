package config

import (
	"crypto/rand"
	"encoding/hex"
)

// Default values for MainConfig fields.
const (
	DefaultPort         = "25555"
	DefaultWebPath      = "/torii"
	DefaultErrorPage    = "/www/server_torii/config/error_page"
	DefaultLogPath      = "/www/server_torii/log/"
	DefaultGlobalSecret = "0378b0f84c4310279918d71a5647ba5d"
	DefaultNodeName     = "Server Torii"
	DefaultSiteID       = "default_site"
)

// DefaultSites is the site list used when torii.yml names none.
var (
	DefaultSites = []AllSiteRuleSet{
		{ID: DefaultSiteID, RulePath: "/www/server_torii/config/rules/default"},
	}
)

// DefaultMainConfig returns a fully populated MainConfig with all default values.
func DefaultMainConfig() *MainConfig {
	return &MainConfig{
		Port:         DefaultPort,
		WebPath:      DefaultWebPath,
		ErrorPage:    DefaultErrorPage,
		LogPath:      DefaultLogPath,
		GlobalSecret: generateDefaultGlobalSecret(),
		NodeName:     DefaultNodeName,
		EnableGossip: false,
		Sites:        append([]AllSiteRuleSet{}, DefaultSites...),
		DefaultSite:  DefaultSiteID,
	}
}

func generateDefaultGlobalSecret() string {
	secret := make([]byte, 16)
	if _, err := rand.Read(secret); err != nil {
		return DefaultGlobalSecret
	}

	return hex.EncodeToString(secret)
}

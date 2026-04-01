package config

// Default values for MainConfig fields.
const (
	DefaultPort         = "25555"
	DefaultWebPath      = "/torii"
	DefaultErrorPage    = "/www/server_torii/config/error_page"
	DefaultLogPath      = "/www/server_torii/log/"
	DefaultGlobalSecret = "0378b0f84c4310279918d71a5647ba5d"
	DefaultNodeName     = "Server Torii"
)

// Default header lists.
var (
	DefaultConnectingHostHeaders           = []string{"Torii-Real-Host"}
	DefaultConnectingIPHeaders             = []string{"Torii-Real-IP"}
	DefaultConnectingURIHeaders            = []string{"Torii-Original-URI"}
	DefaultConnectingFeatureControlHeaders = []string{"Torii-Feature-Control"}
	DefaultSites                           = []AllSiteRuleSet{
		{Host: "default_site", RulePath: "/www/server_torii/config/rules/default"},
	}
)

// DefaultMainConfig returns a fully populated MainConfig with all default values.
func DefaultMainConfig() *MainConfig {
	return &MainConfig{
		Port:                            DefaultPort,
		WebPath:                         DefaultWebPath,
		ErrorPage:                       DefaultErrorPage,
		LogPath:                         DefaultLogPath,
		GlobalSecret:                    DefaultGlobalSecret,
		NodeName:                        DefaultNodeName,
		EnableGossip:                    false,
		ConnectingHostHeaders:           append([]string{}, DefaultConnectingHostHeaders...),
		ConnectingIPHeaders:             append([]string{}, DefaultConnectingIPHeaders...),
		ConnectingURIHeaders:            append([]string{}, DefaultConnectingURIHeaders...),
		ConnectingFeatureControlHeaders: append([]string{}, DefaultConnectingFeatureControlHeaders...),
		Sites:                           append([]AllSiteRuleSet{}, DefaultSites...),
	}
}

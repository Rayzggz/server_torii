package config

// Default values for MainConfig fields.
const (
	DefaultPort      = "25555"
	DefaultWebPath   = "/torii"
	DefaultErrorPage = "/www/server_torii/config/error_page"
	DefaultLogPath   = "/www/server_torii/log/"
	DefaultNodeName  = "Server Torii"
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
		NodeName:                        DefaultNodeName,
		ConnectingHostHeaders:           append([]string{}, DefaultConnectingHostHeaders...),
		ConnectingIPHeaders:             append([]string{}, DefaultConnectingIPHeaders...),
		ConnectingURIHeaders:            append([]string{}, DefaultConnectingURIHeaders...),
		ConnectingFeatureControlHeaders: append([]string{}, DefaultConnectingFeatureControlHeaders...),
		Sites:                           append([]AllSiteRuleSet{}, DefaultSites...),
	}
}

// applyDefaultConfig populates any empty or missing configuration fields with default values.
func applyDefaultConfig(cfg *MainConfig) {
	if cfg.Port == "" {
		cfg.Port = DefaultPort
	}
	if cfg.WebPath == "" {
		cfg.WebPath = DefaultWebPath
	}
	if cfg.ErrorPage == "" {
		cfg.ErrorPage = DefaultErrorPage
	}
	if cfg.LogPath == "" {
		cfg.LogPath = DefaultLogPath
	}
	if cfg.NodeName == "" {
		cfg.NodeName = DefaultNodeName
	}
	if len(cfg.ConnectingHostHeaders) == 0 {
		cfg.ConnectingHostHeaders = append([]string{}, DefaultConnectingHostHeaders...)
	}
	if len(cfg.ConnectingIPHeaders) == 0 {
		cfg.ConnectingIPHeaders = append([]string{}, DefaultConnectingIPHeaders...)
	}
	if len(cfg.ConnectingURIHeaders) == 0 {
		cfg.ConnectingURIHeaders = append([]string{}, DefaultConnectingURIHeaders...)
	}
	if len(cfg.ConnectingFeatureControlHeaders) == 0 {
		cfg.ConnectingFeatureControlHeaders = append([]string{}, DefaultConnectingFeatureControlHeaders...)
	}
	if len(cfg.Sites) == 0 {
		cfg.Sites = append([]AllSiteRuleSet{}, DefaultSites...)
	}
}

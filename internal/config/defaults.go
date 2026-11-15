package config

// Default values for MainConfig fields.
const (
	DefaultListen    = ":25555"
	DefaultWebPath   = "/torii"
	DefaultErrorPage = "/www/server_torii/config/error_page"
	DefaultLogPath   = "/www/server_torii/log/"
	DefaultLogLevel  = "info"
	// DefaultGlobalSecret is the value in config_example/torii.yml. It is public, so it is refused.
	DefaultGlobalSecret = "0378b0f84c4310279918d71a5647ba5d"
	DefaultNodeName     = "Server Torii"
	DefaultSiteID       = "default_site"
)

// DefaultSites is the site list used when torii.yml names none.
var (
	DefaultSites = []Site{
		{ID: DefaultSiteID, RulePath: "/www/server_torii/config/rules/default"},
	}
)

// DefaultMainConfig returns the values of the keys torii.yml leaves out. There is no default
// global secret: it has to be configured. There is no default site either: a request that
// names no site gets a decision only when default_site says which site it belongs to.
func DefaultMainConfig() *MainConfig {
	return &MainConfig{
		Listen:    []string{DefaultListen},
		WebPath:   DefaultWebPath,
		ErrorPage: DefaultErrorPage,
		LogPath:   DefaultLogPath,
		LogLevel:  DefaultLogLevel,
		NodeName:  DefaultNodeName,
		Sites:     append([]Site{}, DefaultSites...),
	}
}

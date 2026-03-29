package config

type MainConfig struct {
	Port                            string           `yaml:"port" validate:"required,numeric,min=1,max=65535"`
	WebPath                         string           `yaml:"web_path" validate:"required,startswith=/"`
	ErrorPage                       string           `yaml:"error_page" validate:"required"`
	LogPath                         string           `yaml:"log_path" validate:"required"`
	GlobalSecret                    string           `yaml:"global_secret" validate:"required,min=32"`
	NodeName                        string           `yaml:"node_name" validate:"required"`
	EnableGossip                    bool             `yaml:"enable_gossip"`
	ConnectingHostHeaders           []string         `yaml:"connecting_host_headers" validate:"required"`
	ConnectingIPHeaders             []string         `yaml:"connecting_ip_headers" validate:"required"`
	ConnectingURIHeaders            []string         `yaml:"connecting_uri_headers" validate:"required"`
	ConnectingFeatureControlHeaders []string         `yaml:"connecting_feature_control_headers" validate:"required"`
	Sites                           []AllSiteRuleSet `yaml:"sites" validate:"required"`
	Peers                           []Peer           `yaml:"peers"`
}

type Peer struct {
	Name    string `yaml:"name" validate:"required"`
	Address string `yaml:"address" validate:"required,url"`
	Host    string `yaml:"host"`
}

type AllSiteRuleSet struct {
	Host     string `yaml:"host" validate:"required,min=1"`
	RulePath string `yaml:"rule_path" validate:"required,dir"`
}

// applyDefaultConfig populates any empty or missing configuration fields with default values
func applyDefaultConfig(cfg *MainConfig) {
	if cfg.Port == "" {
		cfg.Port = "25555"
	}
	if cfg.WebPath == "" {
		cfg.WebPath = "/torii"
	}
	if cfg.ErrorPage == "" {
		cfg.ErrorPage = "/www/server_torii/config/error_page"
	}
	if cfg.LogPath == "" {
		cfg.LogPath = "/www/server_torii/log/"
	}
	if cfg.NodeName == "" {
		cfg.NodeName = "Server Torii"
	}
	if len(cfg.ConnectingHostHeaders) == 0 {
		cfg.ConnectingHostHeaders = []string{"Torii-Real-Host"}
	}
	if len(cfg.ConnectingIPHeaders) == 0 {
		cfg.ConnectingIPHeaders = []string{"Torii-Real-IP"}
	}
	if len(cfg.ConnectingURIHeaders) == 0 {
		cfg.ConnectingURIHeaders = []string{"Torii-Original-URI"}
	}
	if len(cfg.ConnectingFeatureControlHeaders) == 0 {
		cfg.ConnectingFeatureControlHeaders = []string{"Torii-Feature-Control"}
	}
	if len(cfg.Sites) == 0 {
		cfg.Sites = []AllSiteRuleSet{
			{
				Host:     "default_site",
				RulePath: "/www/server_torii/config/rules/default",
			},
		}
	}
}

// validateMainConfig validates the main configuration object
func validateMainConfig(cfg *MainConfig) {
	validateConfiguration(cfg, "MainConfig")
}

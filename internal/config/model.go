package config

// MainConfig is the top-level configuration loaded from torii.yml.
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

// Peer represents a gossip peer node.
type Peer struct {
	Name    string `yaml:"name" validate:"required"`
	Address string `yaml:"address" validate:"required,url"`
	Host    string `yaml:"host"`
}

// AllSiteRuleSet maps a host to its rule directory path.
type AllSiteRuleSet struct {
	Host     string `yaml:"host" validate:"required,min=1"`
	RulePath string `yaml:"rule_path" validate:"required,dir"`
}

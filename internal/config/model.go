package config

import (
	"os"
	"strconv"
)

// MainConfig is the top-level configuration loaded from torii.yml.
type MainConfig struct {
	ConfigDir string `yaml:"-"`
	Port      string `yaml:"port" validate:"required,port"`
	// Listen lists the addresses the HTTP server accepts connections on: "host:port" for TCP or
	// "unix:/path/to.sock" for a Unix domain socket. Empty means every interface on Port.
	Listen []string `yaml:"listen" validate:"omitempty,dive,listen_addr"`
	// LogListen lists the addresses request reports from the connector are received on:
	// "host:port" for UDP or "unix:/path/to.sock" for a Unix datagram socket. Empty means
	// UDP on the loopback address and Port.
	LogListen []string `yaml:"log_listen" validate:"omitempty,dive,listen_addr"`
	// UnixSocketMode is the octal permission of the Unix sockets in Listen and LogListen; empty means 0666.
	UnixSocketMode string           `yaml:"unix_socket_mode" validate:"omitempty,socket_mode"`
	WebPath        string           `yaml:"web_path" validate:"required,startswith=/"`
	ErrorPage      string           `yaml:"error_page" validate:"required"`
	LogPath        string           `yaml:"log_path" validate:"required"`
	GlobalSecret   string           `yaml:"global_secret" validate:"required,min=32"`
	NodeName       string           `yaml:"node_name" validate:"required"`
	EnableGossip   bool             `yaml:"enable_gossip"`
	Sites          []AllSiteRuleSet `yaml:"sites" validate:"required,dive"`
	// DefaultSite is the ID of the site used for requests whose connector names no site.
	// Empty means such requests get no decision.
	DefaultSite string `yaml:"default_site"`
	Peers       []Peer `yaml:"peers" validate:"omitempty,dive"`
}

// Peer represents a gossip peer node.
type Peer struct {
	Name    string `yaml:"name" validate:"required"`
	Address string `yaml:"address" validate:"required,url"`
	Host    string `yaml:"host"`
}

// AllSiteRuleSet is one protected site: its ID and the directory holding its rules.
//
// The connector names the site of every request by this ID (torii_site in nginx). The ID is
// also a directory name under the log path, so it is limited to letters, digits and
// underscores, at most 32 characters.
type AllSiteRuleSet struct {
	ID       string `yaml:"id"`
	RulePath string `yaml:"rule_path" validate:"required,dir"`
	// Host is the key older configurations used; it is only read to report the rename.
	Host string `yaml:"host"`
}

// MaxSiteIDLength is the longest site ID.
const MaxSiteIDLength = 32

// ValidSiteID reports whether id can be used as a site ID.
func ValidSiteID(id string) bool {
	if id == "" || len(id) > MaxSiteIDLength {
		return false
	}
	for i := 0; i < len(id); i++ {
		c := id[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '_':
		default:
			return false
		}
	}
	return true
}

// UnixListenPrefix marks a Listen entry as a Unix domain socket path.
const UnixListenPrefix = "unix:"

// DefaultUnixSocketMode lets any local user connect, like a loopback TCP port does.
const DefaultUnixSocketMode = 0o666

// ListenAddrs returns the addresses to listen on, defaulting to every interface on Port.
func (c *MainConfig) ListenAddrs() []string {
	if len(c.Listen) > 0 {
		return c.Listen
	}
	return []string{":" + c.Port}
}

// LogListenAddrs returns the addresses to receive request reports on. The default is reachable
// from this machine only: a report is trusted, and nothing authenticates its sender.
func (c *MainConfig) LogListenAddrs() []string {
	if len(c.LogListen) > 0 {
		return c.LogListen
	}
	return []string{"127.0.0.1:" + c.Port}
}

// SocketMode returns the permission bits for Unix sockets, falling back to the default when
// UnixSocketMode is empty or not octal.
func (c *MainConfig) SocketMode() os.FileMode {
	if mode, err := strconv.ParseUint(c.UnixSocketMode, 8, 32); err == nil && mode <= 0o777 {
		return os.FileMode(mode)
	}
	return DefaultUnixSocketMode
}

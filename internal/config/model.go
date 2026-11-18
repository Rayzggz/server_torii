package config

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net"
	"os"
	"server_torii/internal/request"
	"strconv"
	"strings"
)

// MainConfig is the top-level configuration loaded from torii.yml.
type MainConfig struct {
	ConfigDir string `yaml:"-"`
	// Listen lists the addresses the HTTP server accepts connections on: "host:port" for TCP or
	// "unix:/path/to.sock" for a Unix domain socket.
	Listen []string `yaml:"listen" validate:"min=1,dive,listen_addr"`
	// LogListen lists the addresses request reports from the connector are received on:
	// "host:port" for UDP or "unix:/path/to.sock" for a Unix datagram socket. Empty means UDP
	// on the loopback address, on the port of the first TCP address in Listen.
	LogListen []string `yaml:"log_listen" validate:"omitempty,dive,listen_addr"`
	// UnixSocketMode is the octal permission of the Unix sockets in Listen and LogListen; empty means 0666.
	UnixSocketMode string `yaml:"unix_socket_mode" validate:"omitempty,socket_mode"`
	WebPath        string `yaml:"web_path" validate:"required,startswith=/"`
	ErrorPage      string `yaml:"error_page" validate:"required"`
	LogPath        string `yaml:"log_path" validate:"required"`
	// LogLevel is the least level that is logged: debug, info, warn or error. It is the one
	// setting of this file that SIGHUP reads again.
	LogLevel string `yaml:"log_level" validate:"oneof=debug info warn error"`
	// GlobalSecret is the one secret of a cluster: it signs gossip messages, and the key that
	// signs the cookies of every site is derived from it. It must not be the published example
	// value.
	GlobalSecret string `yaml:"global_secret" validate:"required,min=32"`
	NodeName     string `yaml:"node_name" validate:"required"`
	Sites        []Site `yaml:"sites" validate:"min=1,dive"`
	// IPv6Prefix is the size, in bits, of the IPv6 network that counts as one client for rate
	// limits, temporary rules and traffic analysis. Empty means 64. Every node of a cluster
	// needs the same value: the rules the nodes share name clients by it.
	IPv6Prefix int `yaml:"ipv6_prefix" validate:"omitempty,min=1,max=128"`
	// DefaultSite is the ID of the site used for requests whose connector names no site.
	// Empty means such requests get no decision.
	DefaultSite string `yaml:"default_site"`
	// EnableGossip makes the node share the temporary rules it installs with its peers.
	EnableGossip bool `yaml:"enable_gossip"`
	// Peers are the other nodes of the cluster.
	Peers []Peer `yaml:"peers" validate:"omitempty,dive"`
}

// Peer is another node of the cluster.
type Peer struct {
	Name    string `yaml:"name" validate:"required"`
	Address string `yaml:"address" validate:"required,url"`
	Host    string `yaml:"host"`
}

// Site is one protected site: its ID and the directory holding its rules.
//
// The connector names the site of every request by this ID (torii_site in nginx). The ID is
// also a directory name under the log path, so it is limited to letters, digits and
// underscores, at most 32 characters.
type Site struct {
	ID       string `yaml:"id" validate:"site_id"`
	RulePath string `yaml:"rule_path" validate:"required,dir"`
	// ErrorPage is a directory with the pages of this site. A page it does not hold is taken
	// from the error_page directory of the main configuration.
	ErrorPage string `yaml:"error_page" validate:"omitempty,dir"`
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

// LogListenAddrs returns the addresses to receive request reports on. The default is reachable
// from this machine only: a report is trusted, and nothing authenticates its sender. It is nil
// when no address is configured and Listen has no TCP address to take the port from.
func (c *MainConfig) LogListenAddrs() []string {
	if len(c.LogListen) > 0 {
		return c.LogListen
	}
	for _, addr := range c.Listen {
		if strings.HasPrefix(addr, UnixListenPrefix) {
			continue
		}
		if _, port, err := net.SplitHostPort(addr); err == nil {
			return []string{net.JoinHostPort("127.0.0.1", port)}
		}
	}
	return nil
}

// IPv6PrefixBits returns the size of the IPv6 network that counts as one client.
func (c *MainConfig) IPv6PrefixBits() int {
	if c.IPv6Prefix > 0 {
		return c.IPv6Prefix
	}
	return request.DefaultIPv6PrefixBits
}

// SocketMode returns the permission bits for Unix sockets, falling back to the default when
// UnixSocketMode is empty or not octal.
func (c *MainConfig) SocketMode() os.FileMode {
	if mode, err := strconv.ParseUint(c.UnixSocketMode, 8, 32); err == nil && mode <= 0o777 {
		return os.FileMode(mode)
	}
	return DefaultUnixSocketMode
}

// CookieKey is the key that signs the cookies of every site. It is derived from the global
// secret, so nodes that share the secret accept one another's cookies, and a signature made for
// a cookie is never a valid signature of a gossip message.
func (c *MainConfig) CookieKey() string {
	mac := hmac.New(sha256.New, []byte(c.GlobalSecret))
	mac.Write([]byte("torii cookie key"))
	return hex.EncodeToString(mac.Sum(nil))
}

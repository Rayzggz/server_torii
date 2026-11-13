package server

import (
	"context"
	"errors"
	"log"
	"net"
	"net/http"
	"path"
	"server_torii/internal/config"
	"server_torii/internal/dataType"
	"server_torii/internal/state"
	"strings"
	"time"
)

// HTTP server limits. Torii sits behind a reverse proxy and serves small
// auth_request/checker requests, so these can be tight; they exist mainly to
// stop slow-connection attacks (slowloris) from exhausting goroutines/FDs.
const (
	httpReadHeaderTimeout = 5 * time.Second
	httpReadTimeout       = 10 * time.Second
	httpWriteTimeout      = 30 * time.Second
	httpIdleTimeout       = 120 * time.Second
	httpMaxHeaderBytes    = 64 << 10 // 64 KiB

	// shutdownTimeout bounds how long in-flight requests may take to finish
	// after a stop signal before connections are forcibly closed.
	shutdownTimeout = 10 * time.Second
)

func newHTTPServer(addr string, handler http.Handler) *http.Server {
	return &http.Server{
		Addr:              addr,
		Handler:           handler,
		ReadHeaderTimeout: httpReadHeaderTimeout,
		ReadTimeout:       httpReadTimeout,
		WriteTimeout:      httpWriteTimeout,
		IdleTimeout:       httpIdleTimeout,
		MaxHeaderBytes:    httpMaxHeaderBytes,
	}
}

// Server answers the nginx auth_request checker and serves Torii's own pages.
type Server struct {
	cfg     *config.MainConfig
	configs *config.ConfigManager
	rt      *state.Runtime
	gossip  *GossipManager // nil when gossip is disabled
}

// NewServer wires a server to its configuration and shared state; gossip may be nil.
func NewServer(cfg *config.MainConfig, configs *config.ConfigManager, rt *state.Runtime, gossip *GossipManager) *Server {
	return &Server{cfg: cfg, configs: configs, rt: rt, gossip: gossip}
}

// ServeHTTP resolves the site rules for the request and dispatches it.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	userRequestData := processRequestData(s.cfg, r)

	snap := s.configs.Get()
	if snap == nil {
		http.Error(w, "Service Unavailable: Configuration not loaded", http.StatusServiceUnavailable)
		return
	}

	// Get site-specific rules based on the Host header
	ruleSet := config.GetSiteRules(snap.SiteRules, userRequestData.Host)
	if ruleSet == nil {
		log.Printf("[ERROR] No rules found for host: %s", userRequestData.Host)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	// Process feature control after ruleSet is loaded
	userRequestData.FeatureControl = processFeatureControl(s.cfg, r, ruleSet)

	if r.URL.Path == path.Join(s.cfg.WebPath, "/checker") {
		s.CheckMain(w, userRequestData, ruleSet)
	} else {
		s.CheckTorii(w, r, userRequestData, ruleSet, snap.Pages)
	}
}

// Run starts the HTTP server and blocks until it stops. When ctx is
// cancelled the server is shut down gracefully (in-flight requests get up to
// shutdownTimeout to finish) and the analyzer / syslog listener are stopped.
// A graceful stop returns nil.
func (s *Server) Run(ctx context.Context) error {
	// Start AdaptiveTrafficAnalyzer
	analyzer := NewAdaptiveTrafficAnalyzer(s.rt, s.configs)
	s.rt.SetAnalyzer(analyzer)
	analyzer.Start()
	defer analyzer.Stop()

	// Start Syslog UDP Listener
	syslogListener := NewSyslogListener(s.cfg.Port, analyzer)
	if err := syslogListener.Start(); err != nil {
		log.Printf("[ERROR] Failed to start Syslog UDP listener: %v", err)
	} else {
		defer syslogListener.Stop()
	}

	srv := newHTTPServer(":"+s.cfg.Port, s)
	listenErr := make(chan error, 1)
	go func() {
		log.Printf("HTTP Server listening on :%s ...", s.cfg.Port)
		listenErr <- srv.ListenAndServe()
	}()

	select {
	case err := <-listenErr:
		// Listener failed (e.g. port in use) before any shutdown was requested.
		return err
	case <-ctx.Done():
	}

	log.Println("Shutting down HTTP server...")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		log.Printf("[WARNING] Graceful shutdown did not complete: %v; forcing close", err)
		_ = srv.Close()
	}
	if err := <-listenErr; err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

func processRequestData(cfg *config.MainConfig, r *http.Request) dataType.UserRequest {

	userRequest := dataType.UserRequest{
		RemoteIP:       getClientIP(cfg, r),
		Uri:            getReqURI(cfg, r),
		FeatureControl: 0,
		ToriiClearance: getHeader(r, "__torii_clearance"),
		ToriiSessionID: getHeader(r, "__torii_session_id"),
		UserAgent:      r.UserAgent(),
		Host:           getReqHost(cfg, r),
		Method:         getReqMethod(cfg, r),
		Headers:        r.Header,
	}
	return userRequest
}

func getHeader(r *http.Request, headerName string) string {
	cookie, err := r.Cookie(headerName)
	if err != nil {
		return ""
	}
	return cookie.Value
}

// processFeatureControl processes the feature control header and combines it with config rules
// Header format: "10_1_0__..." where 1=enable, 0=disable, _=inherit from config
// Position mapping: 0=IPAllow, 1=IPBlock, 2=URLAllow, 3=URLBlock, 4=VerifyBot, 5=HTTPFlood, 6=Captcha, 7=ExternalMigration, 8=CountryRule, 9=IPCAPTCHA, 10=URLCAPTCHA, 11=CustomRules
func processFeatureControl(cfg *config.MainConfig, r *http.Request, ruleSet *config.RuleSet) uint16 {
	// Define feature list in order (position 0 to N)
	configStates := []bool{
		ruleSet.IPAllowRule.Enabled,                                     // position 0
		ruleSet.IPBlockRule.Enabled,                                     // position 1
		ruleSet.URLAllowRule.Enabled,                                    // position 2
		ruleSet.URLBlockRule.Enabled,                                    // position 3
		ruleSet.VerifyBotRule.Enabled,                                   // position 4
		ruleSet.HTTPFloodRule.Enabled,                                   // position 5
		ruleSet.CAPTCHARule.Enabled,                                     // position 6
		ruleSet.ExternalMigrationRule.Enabled,                           // position 7
		ruleSet.CountryRule.Enabled,                                     // position 8
		ruleSet.IPCAPTCHARule != nil && ruleSet.IPCAPTCHARule.Enabled,   // position 9
		ruleSet.URLCAPTCHARule != nil && ruleSet.URLCAPTCHARule.Enabled, // position 10
		ruleSet.CustomRules != nil && ruleSet.CustomRules.Enabled,       // position 11
		// Future features can be added here
	}

	// Build config baseline from ruleSet
	var configBits uint16 = 0
	for i, enabled := range configStates {
		if enabled {
			configBits |= 1 << i
		}
	}

	// Get header value
	var headerValue string
	for _, headerName := range cfg.ConnectingFeatureControlHeaders {
		if featureVal := r.Header.Get(headerName); featureVal != "" {
			headerValue = featureVal
			break
		}
	}

	// If no header, return config baseline
	if headerValue == "" {
		return configBits
	}

	// Process header - pad to 16 characters with '_' for inherit
	finalBits := configBits
	for i, char := range headerValue {
		if i >= 16 { // uint16 has 16 bits max
			break
		}

		featureMask := uint16(1 << i)

		switch char {
		case '1': // Force enable
			finalBits |= featureMask
		case '0': // Force disable
			finalBits &= ^featureMask
		case '_': // Inherit from config (keep current state)
			// Do nothing, keep the bit as it is from configBits
		}
	}

	return finalBits
}

func getReqURI(cfg *config.MainConfig, r *http.Request) string {
	var clientURI string
	for _, headerName := range cfg.ConnectingURIHeaders {
		if uriVal := r.Header.Get(headerName); uriVal != "" {
			clientURI = uriVal
			break
		}
	}
	if clientURI == "" {
		clientURI = r.RequestURI
	}
	return clientURI
}

func getClientIP(cfg *config.MainConfig, r *http.Request) string {
	var clientIP string
	for _, headerName := range cfg.ConnectingIPHeaders {
		if ipVal := r.Header.Get(headerName); ipVal != "" {
			if strings.Contains(ipVal, ",") {
				parts := strings.Split(ipVal, ",")
				clientIP = strings.TrimSpace(parts[0])
			} else {
				clientIP = ipVal
			}
			break
		}
	}

	if clientIP == "" {
		remoteAddr := r.RemoteAddr
		ipStr, _, err := net.SplitHostPort(remoteAddr)
		if err != nil {
			clientIP = remoteAddr
		} else {
			clientIP = ipStr
		}
	}
	return clientIP
}

// getReqMethod reads the original method: Nginx auth_request subrequests are always GET.
func getReqMethod(cfg *config.MainConfig, r *http.Request) string {
	for _, headerName := range cfg.ConnectingMethodHeaders {
		if methodVal := r.Header.Get(headerName); methodVal != "" {
			return methodVal
		}
	}
	return r.Method
}

func getReqHost(cfg *config.MainConfig, r *http.Request) string {
	var clientHost = ""
	for _, headerName := range cfg.ConnectingHostHeaders {
		if hostVal := r.Header.Get(headerName); hostVal != "" {
			clientHost = hostVal
			break
		}
	}
	return clientHost
}

package server

import (
	"log"
	"net"
	"net/http"
	"path"
	"server_torii/internal/config"
	"server_torii/internal/dataType"
	"strings"
)

// StartServer starts the HTTP server
func StartServer(cfg *config.MainConfig, siteRules map[string]*config.RuleSet, sharedMem *dataType.SharedMemory) error {
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {

		userRequestData := processRequestData(cfg, r)

		// Get site-specific rules based on the Host header
		ruleSet := config.GetSiteRules(siteRules, userRequestData.Host)
		if ruleSet == nil {
			log.Printf("[ERROR] No rules found for host: %s", userRequestData.Host)
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}

		// Process feature control after ruleSet is loaded
		userRequestData.FeatureControl = processFeatureControl(cfg, r, ruleSet)

		if strings.Compare(r.URL.Path, path.Join(cfg.WebPath, "/checker")) == 0 {
			CheckMain(w, userRequestData, ruleSet, cfg, sharedMem)
		} else {
			CheckTorii(w, r, userRequestData, ruleSet, cfg, sharedMem)
		}

	})

	// Start AdaptiveTrafficAnalyzer
	analyzer := NewAdaptiveTrafficAnalyzer(siteRules, sharedMem)
	sharedMem.AdaptiveTrafficAnalyzer = analyzer
	analyzer.Start()
	defer analyzer.Stop()

	// Start Syslog UDP Listener
	syslogListener := NewSyslogListener(cfg.Port, analyzer)
	if err := syslogListener.Start(); err != nil {
		log.Printf("[ERROR] Failed to start Syslog UDP listener: %v", err)
	} else {
		defer syslogListener.Stop()
	}

	log.Printf("HTTP Server listening on :%s ...", cfg.Port)
	return http.ListenAndServe(":"+cfg.Port, nil)
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
// Position mapping: 0=IPAllow, 1=IPBlock, 2=URLAllow, 3=URLBlock, 4=VerifyBot, 5=HTTPFlood, 6=Captcha, 7=ExternalMigration
func processFeatureControl(cfg *config.MainConfig, r *http.Request, ruleSet *config.RuleSet) uint16 {
	// Define feature list in order (position 0 to N)
	configStates := []bool{
		ruleSet.IPAllowRule.Enabled,           // position 0
		ruleSet.IPBlockRule.Enabled,           // position 1
		ruleSet.URLAllowRule.Enabled,          // position 2
		ruleSet.URLBlockRule.Enabled,          // position 3
		ruleSet.VerifyBotRule.Enabled,         // position 4
		ruleSet.HTTPFloodRule.Enabled,         // position 5
		ruleSet.CAPTCHARule.Enabled,           // position 6
		ruleSet.ExternalMigrationRule.Enabled, // position 7
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

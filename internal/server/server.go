package server

import (
	"log"
	"net"
	"net/http"
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

		if strings.HasPrefix(userRequestData.Uri, cfg.WebPath) {
			CheckTorii(w, r, userRequestData, ruleSet, cfg, sharedMem)
		} else {
			CheckMain(w, userRequestData, ruleSet, cfg, sharedMem)
		}

	})

	log.Printf("HTTP Server listening on :%s ...", cfg.Port)
	return http.ListenAndServe(":"+cfg.Port, nil)
}

func processRequestData(cfg *config.MainConfig, r *http.Request) dataType.UserRequest {

	userRequest := dataType.UserRequest{
		RemoteIP:       getClientIP(cfg, r),
		Uri:            getReqURI(cfg, r),
		Captcha:        getCaptchaStatus(cfg, r),
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

func getCaptchaStatus(cfg *config.MainConfig, r *http.Request) bool {
	captchaStatus := false
	for _, headerName := range cfg.ConnectingCaptchaStatusHeaders {
		if captchaVal := r.Header.Get(headerName); captchaVal != "" {
			if captchaVal == "on" {
				captchaStatus = true
			}
			break
		}
	}
	return captchaStatus

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

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
func StartServer(ruleSet *config.RuleSet, sharedMem *dataType.SharedMemory) error {
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {

		userRequestData := processRequestData(r)

		if strings.HasPrefix(userRequestData.Uri, config.Cfg.Server.WebPath) {
			CheckTorii(w, r, userRequestData, ruleSet, sharedMem)
		} else {
			CheckMain(w, userRequestData, ruleSet, sharedMem)
		}

	})

	log.Printf("HTTP Server listening on :%s ...", config.Cfg.Server.Port)
	return http.ListenAndServe(":"+config.Cfg.Server.Port, nil)
}

func processRequestData(r *http.Request) dataType.UserRequest {

	userRequest := dataType.UserRequest{
		RemoteIP:       getClientIP(r),
		Uri:            getReqURI(r),
		Captcha:        getCaptchaStatus(r),
		ToriiClearance: getHeader(r, "__torii_clearance"),
		ToriiSessionID: getHeader(r, "__torii_session_id"),
		UserAgent:      r.UserAgent(),
		Host:           getReqHost(r),
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

func getCaptchaStatus(r *http.Request) bool {
	captchaStatus := false
	for _, headerName := range config.Cfg.Server.ConnectingCaptchaStatusHeaders {
		if captchaVal := r.Header.Get(headerName); captchaVal != "" {
			if captchaVal == "on" {
				captchaStatus = true
			}
			break
		}
	}
	return captchaStatus

}

func getReqURI(r *http.Request) string {
	var clientURI string
	for _, headerName := range config.Cfg.Server.ConnectingURIHeaders {
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

func getClientIP(r *http.Request) string {
	var clientIP string
	for _, headerName := range config.Cfg.Server.ConnectingIPHeaders {
		if ipVal := r.Header.Get(headerName); ipVal != "" {
			if strings.Contains(clientIP, ",") {
				parts := strings.Split(ipVal, ",")
				clientIP = strings.TrimSpace(parts[0])
			}
			clientIP = ipVal
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

func getReqHost(r *http.Request) string {
	var clientHost = ""
	for _, headerName := range config.Cfg.Server.ConnectingHostHeaders {
		if hostVal := r.Header.Get(headerName); hostVal != "" {
			clientHost = hostVal
			break
		}
	}
	return clientHost
}

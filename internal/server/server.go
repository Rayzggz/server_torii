package server

import (
	"log"
	"net"
	"net/http"
	"server_torii/internal/action"
	"server_torii/internal/check"
	"server_torii/internal/config"
	"server_torii/internal/dataType"
	"strings"
)

type CheckFunc func(dataType.UserRequest, *config.RuleSet, *action.Decision)

// StartServer starts the HTTP server
func StartServer(cfg *config.MainConfig, ruleSet *config.RuleSet) error {
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {

		userRequestData := processRequestData(cfg, r)

		decision := action.NewDecision()

		checkFuncs := make([]CheckFunc, 0)
		checkFuncs = append(checkFuncs, check.IPAllowList)
		checkFuncs = append(checkFuncs, check.IPBlockList)
		checkFuncs = append(checkFuncs, check.URLAllowList)
		checkFuncs = append(checkFuncs, check.URLBlockList)

		for _, checkFunc := range checkFuncs {
			checkFunc(userRequestData, ruleSet, decision)
			if decision.State == action.Done {
				break
			}
		}

		if decision.HTTPCode == "200" {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("Allowed"))
		} else if decision.HTTPCode == "403" {
			w.WriteHeader(http.StatusForbidden)
			w.Write([]byte("Blocked"))
		} else {
			// should not reach here
			w.WriteHeader(http.StatusInternalServerError)
		}
	})

	log.Printf("HTTP Server listening on :%s ...", cfg.Port)
	return http.ListenAndServe(":"+cfg.Port, nil)
}

func processRequestData(cfg *config.MainConfig, r *http.Request) dataType.UserRequest {

	var clientIP string
	for _, headerName := range cfg.ConnectingIPHeaders {
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
			//TODO: log error
			clientIP = remoteAddr
		} else {
			clientIP = ipStr
		}
	}

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

	userRequest := dataType.UserRequest{
		RemoteIP: clientIP,
		Uri:      clientURI,
	}
	return userRequest
}

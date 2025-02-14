package server

import (
	"html/template"
	"log"
	"net"
	"net/http"
	"server_torii/internal/action"
	"server_torii/internal/check"
	"server_torii/internal/config"
	"server_torii/internal/dataType"
	"strings"
	"time"
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
			w.Write([]byte("OK"))
		} else if decision.HTTPCode == "403" {
			tpl, err := template.ParseFiles(cfg.ErrorPage + "/" + decision.HTTPCode + ".html")
			if err != nil {
				http.Error(w, "500 - Internal Server Error", http.StatusInternalServerError)
				return
			}

			data := struct {
				EdgeTag   string
				ConnectIP string
				Date      string
			}{
				EdgeTag:   cfg.NodeName,
				ConnectIP: userRequestData.RemoteIP,
				Date:      time.Now().Format("2006-01-02 15:04:05"),
			}
			w.WriteHeader(http.StatusForbidden)
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			if err = tpl.Execute(w, data); err != nil {
				http.Error(w, "500 - Internal Server Error", http.StatusInternalServerError)
				return
			}

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

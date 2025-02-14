package server

import (
	"log"
	"net"
	"net/http"
	"server_torii/internal/action"
	"server_torii/internal/config"
	"server_torii/internal/dataType"
	"strings"
)

type userRequest struct {
	remoteIP string
	uri      string
}

// StartServer starts the HTTP server
func StartServer(cfg *config.MainConfig, ruleSet *config.RuleSet) error {
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {

		userRequestData := processRequestData(cfg, r)

		decision := action.NewDecision()

		// run main check logic
		checkIPAllow(userRequestData.remoteIP, ruleSet.IPAllowTrie, decision)
		checkIPBlock(userRequestData.remoteIP, ruleSet.IPBlockTrie, decision)
		checkURLAllow(userRequestData.uri, ruleSet.URLAllowList, decision)
		checkURLBlock(userRequestData.uri, ruleSet.URLBlockList, decision)

		// if still undecided, allow
		if decision.Get() == action.Undecided {
			decision.Set(action.Allow)
		}
		log.Printf("clientIP: %s, decision: %s, Headers: %v", userRequestData.remoteIP, decision.Get(), r.Header)
		// return response
		if decision.Get() == action.Allow {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("Allowed"))
		} else if decision.Get() == action.Block {
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

func processRequestData(cfg *config.MainConfig, r *http.Request) userRequest {

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

	userRequest := userRequest{
		remoteIP: clientIP,
		uri:      clientURI,
	}
	return userRequest
}

func checkIPAllow(remoteIP string, trie *dataType.TrieNode, decision *action.Decision) {
	if decision.Get() != action.Undecided {
		return
	}
	ip := net.ParseIP(remoteIP)
	if ip == nil {
		return
	}
	if trie.Search(ip) {
		decision.Set(action.Allow)
	}
}

func checkIPBlock(remoteIP string, trie *dataType.TrieNode, decision *action.Decision) {
	if decision.Get() != action.Undecided {
		return
	}
	ip := net.ParseIP(remoteIP)
	if ip == nil {
		return
	}
	if trie.Search(ip) {
		decision.Set(action.Block)
	}
}

func checkURLAllow(url string, list *dataType.URLRuleList, decision *action.Decision) {
	if decision.Get() != action.Undecided {
		return
	}
	if list.Match(url) {
		decision.Set(action.Allow)
	}
}

func checkURLBlock(url string, list *dataType.URLRuleList, decision *action.Decision) {
	if decision.Get() != action.Undecided {
		return
	}
	if list.Match(url) {
		decision.Set(action.Block)
	}
}

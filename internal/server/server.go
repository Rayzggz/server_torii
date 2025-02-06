// internal/server/server.go
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

// StartServer starts the HTTP server
func StartServer(port string, ruleSet *config.RuleSet, ipHeaders []string) error {
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		var clientIP string
		for _, headerName := range ipHeaders {
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

		decision := action.NewDecision()

		// run main check logic
		checkIPAllow(clientIP, ruleSet.IPAllowTrie, decision)
		checkIPBlock(clientIP, ruleSet.IPBlockTrie, decision)
		checkURLAllow(r.RequestURI, ruleSet.URLAllowList, decision)
		checkURLBlock(r.RequestURI, ruleSet.URLBlockList, decision)

		// if still undecided, allow
		if decision.Get() == action.Undecided {
			decision.Set(action.Allow)
		}

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

	log.Printf("HTTP Server listening on :%s ...", port)
	return http.ListenAndServe(":"+port, nil)
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

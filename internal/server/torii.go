package server

import (
	"bytes"
	"encoding/json"
	"html/template"
	"net/http"
	"server_torii/internal/action"
	"server_torii/internal/check"
	"server_torii/internal/config"
	"server_torii/internal/dataType"
	"server_torii/internal/utils"
	"time"
)

func CheckTorii(w http.ResponseWriter, r *http.Request, reqData dataType.UserRequest, ruleSet *config.RuleSet, cfg *config.MainConfig, sharedMem *dataType.SharedMemory) {
	decision := action.NewDecision()

	decision.SetCode(action.Continue, []byte("403"))
	if reqData.Uri == cfg.WebPath+"/captcha" {
		check.CheckCaptcha(r, reqData, ruleSet, decision)
	} else if reqData.Uri == cfg.WebPath+"/health_check" {
		decision.SetResponse(action.Done, []byte("200"), []byte("ok"))
	} else if reqData.Uri == cfg.WebPath+"/waiting_room/status" {
		handleWaitingRoomStatus(w, r, reqData, ruleSet, sharedMem)
		return
	} else if reqData.Uri == cfg.WebPath+"/waiting_room/join" {
		handleWaitingRoomJoin(w, r, reqData, ruleSet, sharedMem)
		return
	}
	if bytes.Compare(decision.HTTPCode, []byte("200")) == 0 {
		if bytes.Compare(decision.ResponseData, []byte("ok")) == 0 {
			w.WriteHeader(http.StatusOK)
			_, err := w.Write([]byte("ok"))
			if err != nil {
				utils.LogError(reqData, "Error writing response: "+err.Error(), "CheckTorii")
				return
			}
			return
		}
		if bytes.Compare(decision.ResponseData, []byte("bad")) == 0 {
			w.WriteHeader(http.StatusOK)
			_, err := w.Write([]byte("bad"))
			if err != nil {
				utils.LogError(reqData, "Error writing response: "+err.Error(), "CheckTorii")
				return
			}
			return
		} else if bytes.Compare(decision.ResponseData, []byte("badSession")) == 0 {
			w.WriteHeader(http.StatusOK)
			_, err := w.Write([]byte("badSession"))
			if err != nil {
				utils.LogError(reqData, "Error writing response: "+err.Error(), "CheckTorii")
				return
			}
			return
		} else if bytes.Compare(decision.ResponseData, []byte("good")) == 0 {
			w.Header().Set("Set-Cookie", "__torii_clearance="+string(check.GenClearance(reqData, *ruleSet))+"; Path=/; Max-Age=86400; Priority=High; HttpOnly;")
			w.WriteHeader(http.StatusOK)
			_, err := w.Write(decision.ResponseData)
			if err != nil {
				utils.LogError(reqData, "Error writing response: "+err.Error(), "CheckTorii")
				return
			}
		} else {
			//should not be here
			w.WriteHeader(http.StatusInternalServerError)
			_, err := w.Write([]byte("500 - Internal Server Error"))
			if err != nil {
				utils.LogError(reqData, "Error writing response: "+err.Error(), "CheckTorii")
				return
			}
		}
	} else {
		tpl, err := template.ParseFiles(cfg.ErrorPage + "/403.html")
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
			ConnectIP: reqData.RemoteIP,
			Date:      time.Now().Format("2006-01-02 15:04:05"),
		}
		w.WriteHeader(http.StatusForbidden)
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		if err = tpl.Execute(w, data); err != nil {
			http.Error(w, "500 - Internal Server Error", http.StatusInternalServerError)
			return
		}
	}
}

func handleWaitingRoomStatus(w http.ResponseWriter, r *http.Request, reqData dataType.UserRequest, ruleSet *config.RuleSet, sharedMem *dataType.SharedMemory) {
	if !ruleSet.WaitingRoomRule.Enabled {
		w.WriteHeader(http.StatusNotFound)
		err := json.NewEncoder(w).Encode(map[string]interface{}{
			"error": "Waiting room not enabled",
		})
		if err != nil {
			return
		}
		return
	}

	sessionID := reqData.ToriiSessionID
	userKey := check.GenerateUserKey(reqData)

	var position, totalQueue int
	var canEnter bool

	if sessionID != "" {
		validSessionID := check.VerifyWaitingRoomSessionID(sessionID, reqData, ruleSet.CAPTCHARule.SecretKey, ruleSet.WaitingRoomRule.SessionTimeout)
		if validSessionID {
			canEnter, _ = sharedMem.WaitingRoom.CanEnterSite(sessionID, userKey)
			position, totalQueue = sharedMem.WaitingRoom.GetQueueInfo(sessionID, userKey)
		}
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	err := json.NewEncoder(w).Encode(map[string]interface{}{
		"position":   position,
		"totalQueue": totalQueue,
		"canEnter":   canEnter,
		"sessionID":  sessionID,
		"inQueue":    sessionID != "" && position > 0,
	})
	if err != nil {
		return
	}
}

func handleWaitingRoomJoin(w http.ResponseWriter, r *http.Request, reqData dataType.UserRequest, ruleSet *config.RuleSet, sharedMem *dataType.SharedMemory) {
	if !ruleSet.WaitingRoomRule.Enabled {
		w.WriteHeader(http.StatusNotFound)
		err := json.NewEncoder(w).Encode(map[string]interface{}{
			"error": "Waiting room not enabled",
		})
		if err != nil {
			return
		}
		return
	}

	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		err := json.NewEncoder(w).Encode(map[string]interface{}{
			"error": "Method not allowed",
		})
		if err != nil {
			return
		}
		return
	}

	userKey := check.GenerateUserKey(reqData)
	sessionID := reqData.ToriiSessionID

	if sessionID != "" {
		validSessionID := check.VerifyWaitingRoomSessionID(sessionID, reqData, ruleSet.CAPTCHARule.SecretKey, ruleSet.WaitingRoomRule.SessionTimeout)
		if validSessionID {
			canEnter, _ := sharedMem.WaitingRoom.CanEnterSite(sessionID, userKey)
			if canEnter {
				sharedMem.WaitingRoom.AddToActiveSession(sessionID, userKey)
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusOK)
				err := json.NewEncoder(w).Encode(map[string]interface{}{
					"success":  true,
					"canEnter": true,
					"message":  "可以进入网站",
				})
				if err != nil {
					return
				}
				return
			}
			position, totalQueue := sharedMem.WaitingRoom.GetQueueInfo(sessionID, userKey)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			err := json.NewEncoder(w).Encode(map[string]interface{}{
				"success":    true,
				"canEnter":   false,
				"position":   position,
				"totalQueue": totalQueue,
				"message":    "已在队列中，请等待",
			})
			if err != nil {
				return
			}
			return
		}
	}

	newSessionID := genWaitingRoomSessionID(reqData, ruleSet.CAPTCHARule.SecretKey)

	canEnter, _ := sharedMem.WaitingRoom.CanEnterSite("", userKey)
	if canEnter {
		sharedMem.WaitingRoom.AddToActiveSession(newSessionID, userKey)
		w.Header().Set("Set-Cookie", "__torii_session_id="+newSessionID+"; Path=/; Max-Age=86400; Priority=High; HttpOnly;")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		err := json.NewEncoder(w).Encode(map[string]interface{}{
			"success":   true,
			"canEnter":  true,
			"sessionID": newSessionID,
			"message":   "成功加入，可以进入网站",
		})
		if err != nil {
			return
		}
		return
	}

	sharedMem.WaitingRoom.AddToQueue(newSessionID, userKey)
	position, totalQueue := sharedMem.WaitingRoom.GetQueueInfo(newSessionID, userKey)

	w.Header().Set("Set-Cookie", "__torii_session_id="+newSessionID+"; Path=/; Max-Age=86400; Priority=High; HttpOnly;")
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	err := json.NewEncoder(w).Encode(map[string]interface{}{
		"success":    true,
		"canEnter":   false,
		"sessionID":  newSessionID,
		"position":   position,
		"totalQueue": totalQueue,
		"message":    "已加入排队",
	})
	if err != nil {
		return
	}
}

func genWaitingRoomSessionID(reqData dataType.UserRequest, secretKey string) string {
	return check.GenWaitingRoomSessionID(reqData, secretKey)
}

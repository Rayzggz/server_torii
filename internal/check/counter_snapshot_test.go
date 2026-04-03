package check

import (
	"net/http/httptest"
	"server_torii/internal/action"
	"server_torii/internal/config"
	"server_torii/internal/dataType"
	"testing"
)

func TestHTTPFloodNilCountersContinue(t *testing.T) {
	decision := action.NewDecision()
	sharedMem := &dataType.SharedMemory{}
	ruleSet := &config.RuleSet{
		HTTPFloodRule: &dataType.HTTPFloodRule{
			HTTPFloodSpeedLimit:   map[int64]int64{1: 1},
			HTTPFloodSameURILimit: map[int64]int64{1: 1},
			HTTPFloodFailureLimit: map[int64]int64{1: 1},
		},
	}
	reqData := dataType.UserRequest{
		RemoteIP:       "127.0.0.1",
		Uri:            "/test",
		FeatureControl: dataType.FeatureHTTPFlood,
	}

	HTTPFlood(reqData, ruleSet, decision, sharedMem)

	if decision.State != action.Continue {
		t.Fatalf("expected continue decision, got state=%v httpCode=%s", decision.State, decision.HTTPCode)
	}
}

func TestCaptchaNilCounterContinue(t *testing.T) {
	decision := action.NewDecision()
	sharedMem := &dataType.SharedMemory{}
	ruleSet := &config.RuleSet{
		CAPTCHARule: &dataType.CaptchaRule{
			CaptchaFailureLimit: map[int64]int64{1: 1},
		},
	}
	reqData := dataType.UserRequest{
		RemoteIP:       "127.0.0.1",
		FeatureControl: dataType.FeatureCaptcha,
	}

	Captcha(reqData, ruleSet, decision, sharedMem)

	if decision.State != action.Continue {
		t.Fatalf("expected continue decision, got state=%v httpCode=%s", decision.State, decision.HTTPCode)
	}
}

func TestCheckCaptchaNilCounterStillReturnsBad(t *testing.T) {
	decision := action.NewDecision()
	sharedMem := &dataType.SharedMemory{}
	ruleSet := &config.RuleSet{
		CAPTCHARule: &dataType.CaptchaRule{},
	}
	reqData := dataType.UserRequest{
		RemoteIP: "127.0.0.1",
	}
	req := httptest.NewRequest("POST", "/captcha", nil)

	CheckCaptcha(req, reqData, ruleSet, decision, sharedMem)

	if decision.State != action.Done {
		t.Fatalf("expected done decision, got state=%v", decision.State)
	}
	if string(decision.HTTPCode) != "200" {
		t.Fatalf("expected http code 200, got %s", decision.HTTPCode)
	}
	if string(decision.ResponseData) != "bad" {
		t.Fatalf("expected response bad, got %s", decision.ResponseData)
	}
}

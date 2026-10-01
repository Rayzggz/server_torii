package action

import "testing"

func TestDecisionTransitions(t *testing.T) {
	d := NewDecision()
	if d.State != Continue || string(d.HTTPCode) != "200" || d.ResponseData != nil || d.JumpIndex != -1 {
		t.Fatalf("unexpected default: %+v", d)
	}
	d.Set(Done)
	if d.State != Done || string(d.HTTPCode) != "200" {
		t.Fatalf("Set: %+v", d)
	}
	d.SetCode(Done, []byte("403"))
	if d.State != Done || string(d.HTTPCode) != "403" {
		t.Fatalf("SetCode: %+v", d)
	}
	d.SetResponse(Done, []byte("302"), []byte("https://example.com"))
	if d.State != Done || string(d.HTTPCode) != "302" || string(d.ResponseData) != "https://example.com" {
		t.Fatalf("SetResponse: %+v", d)
	}
	d.SetJump(Jump, []byte("200"), 4)
	if d.State != Jump || string(d.HTTPCode) != "200" || d.JumpIndex != 4 {
		t.Fatalf("SetJump: %+v", d)
	}
	other := NewDecision()
	if other.State != Continue || other.JumpIndex != -1 || other.ResponseData != nil {
		t.Fatalf("decisions share state: %+v", other)
	}
}

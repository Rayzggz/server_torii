package state

import (
	"server_torii/internal/action"
	"server_torii/internal/config"
	"server_torii/internal/gossip"
	"strings"
	"testing"
	"time"
)

func TestLimitersResize(t *testing.T) {
	var l Limiters
	l.GC() // no counters yet

	l.Resize(config.CounterWindows{HTTPFloodSpeed: 120, HTTPFloodSameURI: 45, HTTPFloodFailure: 300})
	sizes := func() [4]int64 {
		return [4]int64{
			l.HTTPFloodSpeedLimitCounter.Load().GetSegSize(),
			l.HTTPFloodSameURILimitCounter.Load().GetSegSize(),
			l.HTTPFloodFailureLimitCounter.Load().GetSegSize(),
			l.CaptchaFailureLimitCounter.Load().GetSegSize(),
		}
	}
	// An unconfigured window still gets a one-second counter.
	if got, want := sizes(), [4]int64{120, 45, 300, 1}; got != want {
		t.Fatalf("sizes = %v, want %v", got, want)
	}

	speed, sameURI := l.HTTPFloodSpeedLimitCounter.Load(), l.HTTPFloodSameURILimitCounter.Load()
	speed.Add("1.2.3.4", 5)
	l.Resize(config.CounterWindows{HTTPFloodSpeed: 120, HTTPFloodSameURI: 60, HTTPFloodFailure: 300})
	if l.HTTPFloodSpeedLimitCounter.Load() != speed || speed.Query("1.2.3.4", 60) != 5 {
		t.Fatal("unchanged window lost its counter")
	}
	if l.HTTPFloodSameURILimitCounter.Load() == sameURI {
		t.Fatal("changed window kept the old counter")
	}
	l.GC()
}

// Each site has its own counters, kept across a reload while the site and its window remain.
func TestSiteLimitersAreIsolated(t *testing.T) {
	var s SiteLimiters
	if s.LimitersFor("shop") != &s.Limiters {
		t.Fatal("a site without counters of its own does not use the shared ones")
	}

	windows := config.CounterWindows{HTTPFloodSpeed: 10, HTTPFloodSameURI: 10, HTTPFloodFailure: 10, CaptchaFailure: 10}
	s.ResizeSites(map[string]config.CounterWindows{"shop": windows, "blog": windows})
	shop, blog := s.LimitersFor("shop"), s.LimitersFor("blog")
	if shop == blog || shop == &s.Limiters {
		t.Fatal("sites share counters")
	}
	shop.HTTPFloodSpeedLimitCounter.Load().Add("1.2.3.4", 7)
	if got := blog.HTTPFloodSpeedLimitCounter.Load().Query("1.2.3.4", 10); got != 0 {
		t.Fatalf("traffic of one site counted on another: %d", got)
	}

	// A reload keeps the counters of a site that stays, drops those of a site that is removed,
	// and gives a new site a fresh set.
	s.ResizeSites(map[string]config.CounterWindows{"shop": windows, "news": windows})
	if s.LimitersFor("shop") != shop || shop.HTTPFloodSpeedLimitCounter.Load().Query("1.2.3.4", 10) != 7 {
		t.Fatal("a site lost its counters on reload")
	}
	if s.LimitersFor("blog") != &s.Limiters {
		t.Fatal("a removed site kept its counters")
	}
	if s.LimitersFor("news").HTTPFloodSpeedLimitCounter.Load() == nil {
		t.Fatal("a new site has no counters")
	}
	s.GC()
}

// A rule installed for one site does not apply to another.
func TestApplyRuleIsScopedToTheSite(t *testing.T) {
	engine := action.NewActionRuleEngine(time.Minute)
	defer engine.Stop()
	gossipCh := make(chan gossip.Message, 4)
	rt := &Runtime{ActionRuleEngine: engine, NodeName: "node-a", GossipChan: gossipCh}

	rt.BlockIP("shop", "1.2.3.4", time.Minute)
	if got := engine.Check("shop", "1.2.3.4", "", "/"); got != action.ActionBlock {
		t.Fatalf("rule on its own site = %s, want BLOCK", got)
	}
	if got := engine.Check("blog", "1.2.3.4", "", "/"); got != action.ActionNone {
		t.Fatalf("rule leaked to another site: %s", got)
	}
	msg := <-gossipCh
	if !strings.Contains(msg.Content, `"site":"shop"`) {
		t.Fatalf("broadcast does not name the site: %s", msg.Content)
	}
}

func TestApplyRule(t *testing.T) {
	var none *Runtime
	if none.BlockIP("", "1.2.3.4", time.Minute) || (&Runtime{}).BlockIP("", "1.2.3.4", time.Minute) {
		t.Fatal("rule applied without an engine")
	}

	engine := action.NewActionRuleEngine(time.Minute)
	defer engine.Stop()
	gossipCh := make(chan gossip.Message, 4)
	rt := &Runtime{ActionRuleEngine: engine, NodeName: "node-a", GossipChan: gossipCh}

	if !rt.BlockIP("", "1.2.3.4", time.Minute) {
		t.Fatal("BlockIP reported no engine")
	}
	if got := engine.Check("", "1.2.3.4", "", "/"); got != action.ActionBlock {
		t.Fatalf("IP rule = %s, want BLOCK", got)
	}
	select {
	case msg := <-gossipCh:
		if msg.OriginNode != "node-a" || msg.Type != gossip.TypeActionRule {
			t.Fatalf("unexpected broadcast: %+v", msg)
		}
	default:
		t.Fatal("block was not broadcast")
	}

	rt.ApplyRule("", RuleTargetURI, "/search", action.ActionCaptcha, time.Minute, false)
	if got := engine.Check("", "9.9.9.9", "", "/search"); got != action.ActionCaptcha {
		t.Fatalf("URI rule = %s, want CAPTCHA", got)
	}
	if len(gossipCh) != 0 {
		t.Fatal("local-only rule was broadcast")
	}

	// A node without gossip still enforces locally.
	local := &Runtime{ActionRuleEngine: engine}
	if !local.BlockIP("", "5.6.7.8", time.Minute) || !engine.HasIPRule("", "5.6.7.8") {
		t.Fatal("rule not applied without a gossip channel")
	}
}

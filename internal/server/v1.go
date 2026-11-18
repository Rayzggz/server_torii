package server

import (
	"log/slog"
	"net/http"
	"server_torii/internal/action"
	"server_torii/internal/config"
	"server_torii/internal/feature"
	"server_torii/internal/request"
	"strings"
)

// Connector protocol v1, spoken by the ngx_torii module.
//
// The connector sends every request it protects to v1CheckPath and reads the answer from the
// Torii-Decision response header:
//
//   - "pass": let the request through. The response has no body.
//   - any other value: do not let it through; send this response (status, headers, body) to
//     the visitor instead. The value names the verdict, see action.Verdict.
//   - header absent: Torii did not reach a decision (bad request, unknown site, not ready). The
//     connector applies its own failure policy.
//
// Requests for Torii's own browser-facing endpoints (CAPTCHA submission and the like) are proxied
// to v1PublicPrefix with the same request headers.
const (
	v1CheckPath    = "/v1/check"
	v1PublicPrefix = "/v1/public/"

	headerDecision = "Torii-Decision"
	headerReason   = "Torii-Reason"

	headerSite     = "Torii-Site"
	headerClientIP = "Torii-Client-IP"
	headerURI      = "Torii-URI"
	headerHost     = "Torii-Host"
	headerMethod   = "Torii-Method"
	headerFeatures = "Torii-Features"
)

// serveV1Check runs the check pipeline and answers with the response the visitor should get.
func (s *Server) serveV1Check(w http.ResponseWriter, r *http.Request) {
	reqData, ruleSet, pages, ok := s.v1Request(w, r)
	if !ok {
		return
	}

	decision, _ := s.runChecks(reqData, ruleSet)
	w.Header().Set(headerDecision, decision.Verdict.String())
	if decision.Verdict == action.VerdictAllow {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if decision.Reason != "" {
		w.Header().Set(headerReason, decision.Reason)
	}
	s.serveVerdict(w, reqData, ruleSet, pages, decision.Verdict)
}

// serveV1Public serves Torii's browser-facing endpoints; any other URI gets the 403 page.
func (s *Server) serveV1Public(w http.ResponseWriter, r *http.Request) {
	reqData, ruleSet, pages, ok := s.v1Request(w, r)
	if !ok {
		return
	}
	s.servePublic(w, r, reqData, ruleSet, pages)
}

// servePublic answers one of Torii's browser-facing endpoints, or with the 403 page for any other URI.
func (s *Server) servePublic(w http.ResponseWriter, r *http.Request, reqData request.UserRequest, ruleSet *config.RuleSet, pages *config.ErrorPages) {
	if !s.servePublicEndpoint(w, r, reqData, ruleSet, pages) {
		s.serveErrorPage(w, reqData, pages, config.PageForbidden, http.StatusForbidden)
	}
}

// v1Request reads what the connector says about the visitor's request and resolves its site.
// When it reports false it has already answered, without a Torii-Decision header.
func (s *Server) v1Request(w http.ResponseWriter, r *http.Request) (request.UserRequest, *config.RuleSet, *config.ErrorPages, bool) {
	reqData := request.UserRequest{
		RemoteIP:       strings.TrimSpace(r.Header.Get(headerClientIP)),
		Uri:            r.Header.Get(headerURI),
		ToriiClearance: getHeader(r, "__torii_clearance"),
		ToriiSessionID: getHeader(r, "__torii_session_id"),
		UserAgent:      r.UserAgent(),
		Host:           r.Header.Get(headerHost),
		Method:         r.Header.Get(headerMethod),
		Headers:        r.Header,
	}
	// Parsed once here for every check.
	reqData.Addr = request.ParseAddr(reqData.RemoteIP)
	if reqData.Method == "" {
		reqData.Method = r.Method
	}
	if reqData.RemoteIP == "" || reqData.Uri == "" {
		http.Error(w, "400 - "+headerClientIP+" and "+headerURI+" are required", http.StatusBadRequest)
		return reqData, nil, nil, false
	}
	// A connector always knows the address of its client; one that is not an IP address means
	// the connector is set up wrongly, and no check could be trusted to judge the request.
	if !reqData.Addr.IsValid() {
		http.Error(w, "400 - "+headerClientIP+" is not an IP address", http.StatusBadRequest)
		return reqData, nil, nil, false
	}

	snap := s.configs.Get()
	if snap == nil {
		http.Error(w, "Service Unavailable: Configuration not loaded", http.StatusServiceUnavailable)
		return reqData, nil, nil, false
	}

	// A site the connector names must exist: falling back to another site's rules would hide a
	// configuration mistake. A request without a name belongs to the default site, if there is one.
	site := r.Header.Get(headerSite)
	ruleSet := snap.Site(site)
	if ruleSet == nil {
		s.rt.Log().Error("request for an unknown site", "site", site, "host", reqData.Host, "default_site", snap.DefaultSite)
		http.Error(w, "500 - Unknown site", http.StatusInternalServerError)
		return reqData, nil, nil, false
	}
	reqData.Site = ruleSet.ID
	// Everything the checks need to know about the client is worked out here, before the first
	// check runs.
	reqData.Key = request.Key(reqData.Addr, reqData.RemoteIP, s.cfg.IPv6PrefixBits())
	if s.rt != nil {
		reqData.ResolveCountry(s.rt.CountryResolver)
	}
	reqData.ShareLookups()

	bits, unknown := applyFeatureOverrides(configFeatureBits(ruleSet), r.Header.Get(headerFeatures))
	reqData.ListOverrides, unknown = listOverrides(ruleSet.Lists, unknown)
	if len(unknown) > 0 {
		s.rt.Event(reqData, slog.LevelWarn, "unknown "+headerFeatures+" entries ignored", slog.String("entries", strings.Join(unknown, " ")))
	}
	reqData.FeatureControl = bits
	return reqData, ruleSet, snap.PagesFor(ruleSet.ID), true
}

// listOverrides picks, from the Torii-Features entries that name no check, the ones that name a
// list of the site: "+name" switches the action of the list on for the request and "-name"
// switches it off. It returns them with the entries that name nothing.
func listOverrides(lists *config.ListSet, entries []string) (map[string]bool, []string) {
	var overrides map[string]bool
	var unknown []string
	for _, entry := range entries {
		name := strings.ToLower(entry[1:])
		if (entry[0] != '+' && entry[0] != '-') || lists.ByName(name) == nil {
			unknown = append(unknown, entry)
			continue
		}
		if overrides == nil {
			overrides = make(map[string]bool)
		}
		overrides[name] = entry[0] == '+'
	}
	return overrides, unknown
}

// applyFeatureOverrides applies a Torii-Features header to the bits the site configuration turns
// on. The header lists checks by name, separated by commas or spaces: "+name" forces a check on
// and "-name" forces it off, for example "-captcha +http_flood". Entries it cannot apply are
// returned and otherwise ignored.
func applyFeatureOverrides(bits uint16, header string) (uint16, []string) {
	var unknown []string
	for _, entry := range strings.FieldsFunc(header, func(c rune) bool { return c == ',' || c == ' ' || c == '\t' }) {
		mask, ok := feature.ControlMaskByName(entry[1:])
		switch {
		case !ok:
			unknown = append(unknown, entry)
		case entry[0] == '+':
			bits |= mask
		case entry[0] == '-':
			bits &^= mask
		default:
			unknown = append(unknown, entry)
		}
	}
	return bits, unknown
}

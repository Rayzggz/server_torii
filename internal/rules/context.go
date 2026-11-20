package rules

import (
	"net/netip"
	"net/url"
	"path"
	"server_torii/internal/integrity"
	"server_torii/internal/request"
	"strings"
)

// BrowserEvidence reports whether an IP has recently behaved like a browser on a site.
type BrowserEvidence = request.BrowserEvidence

// Context holds one request plus lazily computed fields, so each field is parsed at most once
// no matter how many rules read it.
type Context struct {
	req      *request.UserRequest
	evidence BrowserEvidence

	ipDone bool
	ip     netip.Addr

	uriDone bool
	path    string
	query   string
	args    url.Values

	cookiesDone bool
	cookies     map[string]string

	evidenceDone bool
	hasEvidence  bool

	integrity *integrity.Request
}

// NewContext builds an evaluation context; evidence may be nil.
func NewContext(req *request.UserRequest, evidence BrowserEvidence) *Context {
	return &Context{req: req, evidence: evidence}
}

func (c *Context) header(name string) string {
	return c.req.Headers.Get(name)
}

func (c *Context) clientIP() netip.Addr {
	if !c.ipDone {
		c.ipDone = true
		c.ip = c.req.ClientAddr()
	}
	return c.ip
}

func (c *Context) parseURI() {
	if c.uriDone {
		return
	}
	c.uriDone = true
	uri := c.req.Uri
	if i := strings.IndexByte(uri, '#'); i >= 0 {
		uri = uri[:i]
	}
	c.path = uri
	if i := strings.IndexByte(uri, '?'); i >= 0 {
		c.path = uri[:i]
		c.query = uri[i+1:]
	}
	// ParseQuery keeps every pair it could parse, which is what a rule wants for malformed input.
	c.args, _ = url.ParseQuery(c.query)
}

func (c *Context) uriPath() string {
	c.parseURI()
	return c.path
}

func (c *Context) uriQuery() string {
	c.parseURI()
	return c.query
}

func (c *Context) uriArg(name string) string {
	c.parseURI()
	return c.args.Get(name)
}

func (c *Context) uriExtension() string {
	ext := path.Ext(c.uriPath())
	return strings.ToLower(strings.TrimPrefix(ext, "."))
}

func (c *Context) cookie(name string) string {
	if !c.cookiesDone {
		c.cookiesDone = true
		c.cookies = make(map[string]string)
		for _, line := range c.req.Headers.Values("Cookie") {
			for _, part := range strings.Split(line, ";") {
				key, value, _ := strings.Cut(strings.TrimSpace(part), "=")
				if key == "" {
					continue
				}
				if _, exists := c.cookies[key]; !exists {
					c.cookies[key] = value
				}
			}
		}
	}
	return c.cookies[name]
}

func (c *Context) countryCode() string {
	return c.req.Country
}

// breaksIntegrity reports whether the request breaks a rule of package integrity.
func (c *Context) breaksIntegrity(rule string) bool {
	if c.integrity == nil {
		c.integrity = integrity.New(c.req.UserAgent, c.req.Headers)
	}
	_, broken := c.integrity.Breaks(rule)
	return broken
}

func (c *Context) browserEvidence() bool {
	if !c.evidenceDone {
		c.evidenceDone = true
		c.hasEvidence = c.req.HasBrowserEvidence(c.evidence)
	}
	return c.hasEvidence
}

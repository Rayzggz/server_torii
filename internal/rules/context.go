package rules

import (
	"net/netip"
	"net/url"
	"path"
	"server_torii/internal/dataType"
	"strings"
)

// Context holds one request plus lazily computed fields, so each field is parsed at most once
// no matter how many rules read it.
type Context struct {
	req      *dataType.UserRequest
	resolver dataType.CountryResolver
	evidence dataType.BrowserEvidence

	ipDone bool
	ip     netip.Addr

	uriDone bool
	path    string
	query   string
	args    url.Values

	cookiesDone bool
	cookies     map[string]string

	countryDone bool
	country     string

	evidenceDone bool
	hasEvidence  bool
}

// NewContext builds an evaluation context; sharedMem may be nil.
func NewContext(req *dataType.UserRequest, sharedMem *dataType.SharedMemory) *Context {
	ctx := &Context{req: req}
	if sharedMem != nil {
		ctx.resolver = sharedMem.CountryResolver
		if ev, ok := dataType.BrowserEvidenceOf(sharedMem); ok {
			ctx.evidence = ev
		}
	}
	return ctx
}

func (c *Context) header(name string) string {
	return c.req.Headers.Get(name)
}

func (c *Context) clientIP() netip.Addr {
	if !c.ipDone {
		c.ipDone = true
		if addr, err := netip.ParseAddr(strings.TrimSpace(c.req.RemoteIP)); err == nil {
			c.ip = addr.Unmap()
		}
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
	if c.countryDone {
		return c.country
	}
	c.countryDone = true
	addr := c.clientIP()
	if !addr.IsValid() || !addr.IsGlobalUnicast() || addr.IsPrivate() || c.resolver == nil {
		return ""
	}
	if country, err := c.resolver.Country(addr); err == nil {
		c.country = strings.ToUpper(country)
	}
	return c.country
}

func (c *Context) browserEvidence() bool {
	if !c.evidenceDone {
		c.evidenceDone = true
		c.hasEvidence = c.evidence != nil && c.evidence.HasBrowserEvidence(c.req.RemoteIP)
	}
	return c.hasEvidence
}

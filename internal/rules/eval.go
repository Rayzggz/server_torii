package rules

import (
	"net/netip"
	"net/url"
	"strings"
)

type kind int

const (
	kindString kind = iota
	kindIP
	kindInt
	kindBool
)

func (k kind) String() string {
	switch k {
	case kindIP:
		return "IP"
	case kindInt:
		return "integer"
	case kindBool:
		return "boolean"
	default:
		return "string"
	}
}

type value struct {
	s  string
	ip netip.Addr
	n  int64
	b  bool
}

// valueNode produces a typed value: a field, a function call or a constant.
type valueNode interface {
	kind() kind
	value(ctx *Context) value
}

// boolNode is a condition.
type boolNode interface {
	test(ctx *Context) bool
}

type fieldNode struct {
	k   kind
	get func(ctx *Context) value
}

func (n fieldNode) kind() kind               { return n.k }
func (n fieldNode) value(ctx *Context) value { return n.get(ctx) }

func stringField(get func(ctx *Context) string) fieldNode {
	return fieldNode{k: kindString, get: func(ctx *Context) value { return value{s: get(ctx)} }}
}

var fields = map[string]fieldNode{
	"ip.src":                          {k: kindIP, get: func(ctx *Context) value { return value{ip: ctx.clientIP()} }},
	"ip.src.country":                  stringField((*Context).countryCode),
	"ip.geoip.country":                stringField((*Context).countryCode),
	"http.host":                       stringField(func(ctx *Context) string { return ctx.req.Host }),
	"http.request.uri":                stringField(func(ctx *Context) string { return ctx.req.Uri }),
	"http.request.uri.path":           stringField((*Context).uriPath),
	"http.request.uri.query":          stringField((*Context).uriQuery),
	"http.request.uri.path.extension": stringField((*Context).uriExtension),
	"http.request.method":             stringField(func(ctx *Context) string { return strings.ToUpper(ctx.req.Method) }),
	"http.user_agent":                 stringField(func(ctx *Context) string { return ctx.req.UserAgent }),
	"http.referer":                    stringField(func(ctx *Context) string { return ctx.header("Referer") }),
	"http.cookie":                     stringField(func(ctx *Context) string { return strings.Join(ctx.req.Headers.Values("Cookie"), "; ") }),
	"http.x_forwarded_for":            stringField(func(ctx *Context) string { return ctx.header("X-Forwarded-For") }),
	"torii.browser_evidence":          {k: kindBool, get: func(ctx *Context) value { return value{b: ctx.browserEvidence()} }},
}

// mapFields are indexed with a string key, e.g. http.request.headers["accept-language"].
var mapFields = map[string]func(ctx *Context, key string) string{
	"http.request.headers":  (*Context).header,
	"http.request.cookies":  (*Context).cookie,
	"http.request.uri.args": (*Context).uriArg,
}

type constNode struct {
	k kind
	v value
}

func (n constNode) kind() kind           { return n.k }
func (n constNode) value(*Context) value { return n.v }

// stringFunc is lower(), upper() or url_decode().
type stringFunc struct {
	arg valueNode
	fn  func(string) string
}

func (n stringFunc) kind() kind { return kindString }
func (n stringFunc) value(ctx *Context) value {
	return value{s: n.fn(n.arg.value(ctx).s)}
}

func urlDecode(s string) string {
	if decoded, err := url.QueryUnescape(s); err == nil {
		return decoded
	}
	return s
}

type lenFunc struct{ arg valueNode }

func (n lenFunc) kind() kind { return kindInt }
func (n lenFunc) value(ctx *Context) value {
	return value{n: int64(len(n.arg.value(ctx).s))}
}

// affixFunc is starts_with() or ends_with().
type affixFunc struct {
	arg   valueNode
	affix string
	fn    func(s, affix string) bool
}

func (n affixFunc) kind() kind { return kindBool }
func (n affixFunc) value(ctx *Context) value {
	return value{b: n.fn(n.arg.value(ctx).s, n.affix)}
}

// boolValue lets a boolean field or function stand alone as a condition.
type boolValue struct{ v valueNode }

func (n boolValue) test(ctx *Context) bool { return n.v.value(ctx).b }

// compareNode applies a predicate compiled from an operator and its literal.
type compareNode struct {
	lhs  valueNode
	pred func(value) bool
}

func (n compareNode) test(ctx *Context) bool { return n.pred(n.lhs.value(ctx)) }

type notNode struct{ x boolNode }

func (n notNode) test(ctx *Context) bool { return !n.x.test(ctx) }

type andNode struct{ l, r boolNode }

func (n andNode) test(ctx *Context) bool { return n.l.test(ctx) && n.r.test(ctx) }

type orNode struct{ l, r boolNode }

func (n orNode) test(ctx *Context) bool { return n.l.test(ctx) || n.r.test(ctx) }

type xorNode struct{ l, r boolNode }

func (n xorNode) test(ctx *Context) bool { return n.l.test(ctx) != n.r.test(ctx) }

// Program is a compiled rule expression. It is immutable and safe for concurrent use.
type Program struct {
	src  string
	root boolNode
}

// Eval reports whether the request in ctx matches the expression.
func (p *Program) Eval(ctx *Context) bool {
	return p.root.test(ctx)
}

func (p *Program) String() string {
	return p.src
}

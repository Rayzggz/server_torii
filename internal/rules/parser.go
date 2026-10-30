package rules

import (
	"fmt"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
)

// Compile parses a Cloudflare-style rule expression and type-checks it against the known fields.
func Compile(src string) (*Program, error) {
	if strings.TrimSpace(src) == "" {
		return nil, fmt.Errorf("expression is empty")
	}
	toks, err := lex(src)
	if err != nil {
		return nil, err
	}
	p := &parser{toks: toks}
	root, err := p.parseOr()
	if err != nil {
		return nil, err
	}
	if t := p.peek(); t.kind != tokEOF {
		return nil, p.errorf(t, "unexpected %s", t)
	}
	return &Program{src: src, root: root}, nil
}

type parser struct {
	toks []token
	i    int
}

func (p *parser) peek() token { return p.toks[p.i] }

func (p *parser) next() token {
	t := p.toks[p.i]
	if t.kind != tokEOF {
		p.i++
	}
	return t
}

func (p *parser) errorf(t token, format string, args ...any) error {
	return fmt.Errorf("col %d: %s", t.pos, fmt.Sprintf(format, args...))
}

func (p *parser) expect(k tokenKind, what string) (token, error) {
	t := p.next()
	if t.kind != k {
		return t, p.errorf(t, "expected %s, got %s", what, t)
	}
	return t, nil
}

// accept consumes the next token if it is one of the given keywords or symbolic operators.
func (p *parser) accept(words ...string) bool {
	t := p.peek()
	if t.kind != tokWord && t.kind != tokOp {
		return false
	}
	for _, w := range words {
		if t.text == w {
			p.i++
			return true
		}
	}
	return false
}

// Precedence follows Cloudflare: not > and > xor > or.
func (p *parser) parseOr() (boolNode, error) {
	left, err := p.parseXor()
	if err != nil {
		return nil, err
	}
	for p.accept("or", "||") {
		right, err := p.parseXor()
		if err != nil {
			return nil, err
		}
		left = orNode{left, right}
	}
	return left, nil
}

func (p *parser) parseXor() (boolNode, error) {
	left, err := p.parseAnd()
	if err != nil {
		return nil, err
	}
	for p.accept("xor", "^^") {
		right, err := p.parseAnd()
		if err != nil {
			return nil, err
		}
		left = xorNode{left, right}
	}
	return left, nil
}

func (p *parser) parseAnd() (boolNode, error) {
	left, err := p.parseUnary()
	if err != nil {
		return nil, err
	}
	for p.accept("and", "&&") {
		right, err := p.parseUnary()
		if err != nil {
			return nil, err
		}
		left = andNode{left, right}
	}
	return left, nil
}

func (p *parser) parseUnary() (boolNode, error) {
	if p.accept("not", "!") {
		x, err := p.parseUnary()
		if err != nil {
			return nil, err
		}
		return notNode{x}, nil
	}
	if p.peek().kind == tokLParen {
		p.next()
		x, err := p.parseOr()
		if err != nil {
			return nil, err
		}
		if _, err := p.expect(tokRParen, `")"`); err != nil {
			return nil, err
		}
		return x, nil
	}
	return p.parseComparison()
}

// operator names, with symbolic forms normalized to their word forms.
var operatorAliases = map[string]string{
	"eq": "eq", "==": "eq",
	"ne": "ne", "!=": "ne",
	"lt": "lt", "<": "lt",
	"le": "le", "<=": "le",
	"gt": "gt", ">": "gt",
	"ge": "ge", ">=": "ge",
	"contains": "contains",
	"wildcard": "wildcard",
	"matches":  "matches", "~": "matches",
	"in": "in",
}

var operatorsByKind = map[kind]map[string]bool{
	kindString: {"eq": true, "ne": true, "contains": true, "wildcard": true, "strict wildcard": true, "matches": true, "in": true},
	kindIP:     {"eq": true, "ne": true, "in": true},
	kindInt:    {"eq": true, "ne": true, "lt": true, "le": true, "gt": true, "ge": true, "in": true},
}

func (p *parser) parseOperator() (string, token, bool) {
	t := p.peek()
	if t.kind == tokWord && t.text == "strict" {
		if n := p.toks[p.i+1]; n.kind == tokWord && n.text == "wildcard" {
			p.i += 2
			return "strict wildcard", t, true
		}
	}
	if t.kind != tokWord && t.kind != tokOp {
		return "", t, false
	}
	op, ok := operatorAliases[t.text]
	if ok {
		p.i++
	}
	return op, t, ok
}

func (p *parser) parseComparison() (boolNode, error) {
	start := p.peek()
	lhs, err := p.parseValue()
	if err != nil {
		return nil, err
	}
	op, opTok, ok := p.parseOperator()
	if !ok {
		if lhs.kind() == kindBool {
			return boolValue{lhs}, nil
		}
		return nil, p.errorf(opTok, "expected a comparison operator after %s, got %s", start, opTok)
	}
	if !operatorsByKind[lhs.kind()][op] {
		return nil, p.errorf(opTok, "operator %q cannot be used with %s values", op, lhs.kind())
	}
	if op == "in" {
		pred, err := p.parseSet(lhs.kind())
		if err != nil {
			return nil, err
		}
		return compareNode{lhs: lhs, pred: pred}, nil
	}
	pred, err := p.parseLiteralPredicate(lhs.kind(), op)
	if err != nil {
		return nil, err
	}
	return compareNode{lhs: lhs, pred: pred}, nil
}

func (p *parser) parseLiteralPredicate(k kind, op string) (func(value) bool, error) {
	switch k {
	case kindIP:
		prefix, err := p.parseIPLiteral()
		if err != nil {
			return nil, err
		}
		if op == "ne" {
			return func(v value) bool { return !v.ip.IsValid() || !prefix.Contains(v.ip) }, nil
		}
		return func(v value) bool { return v.ip.IsValid() && prefix.Contains(v.ip) }, nil
	case kindInt:
		n, err := p.parseIntLiteral()
		if err != nil {
			return nil, err
		}
		return intPredicate(op, n), nil
	}

	t, err := p.expect(tokString, "a string literal")
	if err != nil {
		return nil, err
	}
	lit := t.text
	switch op {
	case "eq":
		return func(v value) bool { return v.s == lit }, nil
	case "ne":
		return func(v value) bool { return v.s != lit }, nil
	case "contains":
		return func(v value) bool { return strings.Contains(v.s, lit) }, nil
	case "wildcard", "strict wildcard":
		re, err := compileWildcard(lit, op == "strict wildcard")
		if err != nil {
			return nil, p.errorf(t, "invalid wildcard: %v", err)
		}
		return func(v value) bool { return re.MatchString(v.s) }, nil
	default: // matches
		re, err := regexp.Compile(lit)
		if err != nil {
			return nil, p.errorf(t, "invalid regular expression: %v", err)
		}
		return func(v value) bool { return re.MatchString(v.s) }, nil
	}
}

func intPredicate(op string, n int64) func(value) bool {
	switch op {
	case "ne":
		return func(v value) bool { return v.n != n }
	case "lt":
		return func(v value) bool { return v.n < n }
	case "le":
		return func(v value) bool { return v.n <= n }
	case "gt":
		return func(v value) bool { return v.n > n }
	case "ge":
		return func(v value) bool { return v.n >= n }
	default:
		return func(v value) bool { return v.n == n }
	}
}

// parseSet reads {a b c}; commas between items are optional.
func (p *parser) parseSet(k kind) (func(value) bool, error) {
	if _, err := p.expect(tokLBrace, `"{"`); err != nil {
		return nil, err
	}
	var (
		strs     = map[string]struct{}{}
		ints     = map[int64]struct{}{}
		prefixes []netip.Prefix
		count    int
	)
	for {
		t := p.peek()
		if t.kind == tokRBrace {
			p.next()
			break
		}
		if t.kind == tokComma && count > 0 {
			p.next()
			continue
		}
		switch k {
		case kindIP:
			prefix, err := p.parseIPLiteral()
			if err != nil {
				return nil, err
			}
			prefixes = append(prefixes, prefix)
		case kindInt:
			n, err := p.parseIntLiteral()
			if err != nil {
				return nil, err
			}
			ints[n] = struct{}{}
		default:
			s, err := p.expect(tokString, "a string literal or \"}\"")
			if err != nil {
				return nil, err
			}
			strs[s.text] = struct{}{}
		}
		count++
	}
	if count == 0 {
		return nil, fmt.Errorf("set must not be empty")
	}
	switch k {
	case kindIP:
		return func(v value) bool {
			if !v.ip.IsValid() {
				return false
			}
			for _, prefix := range prefixes {
				if prefix.Contains(v.ip) {
					return true
				}
			}
			return false
		}, nil
	case kindInt:
		return func(v value) bool { _, ok := ints[v.n]; return ok }, nil
	default:
		return func(v value) bool { _, ok := strs[v.s]; return ok }, nil
	}
}

// parseIPLiteral accepts a single address or a CIDR; an address becomes a host prefix.
func (p *parser) parseIPLiteral() (netip.Prefix, error) {
	t := p.next()
	if t.kind == tokWord {
		if strings.Contains(t.text, "/") {
			if prefix, err := netip.ParsePrefix(t.text); err == nil {
				return prefix.Masked(), nil
			}
		} else if addr, err := netip.ParseAddr(t.text); err == nil {
			addr = addr.Unmap()
			return netip.PrefixFrom(addr, addr.BitLen()), nil
		}
	}
	return netip.Prefix{}, p.errorf(t, "expected an IP address or CIDR, got %s", t)
}

func (p *parser) parseIntLiteral() (int64, error) {
	t := p.next()
	if t.kind == tokWord {
		if n, err := strconv.ParseInt(t.text, 10, 64); err == nil {
			return n, nil
		}
	}
	return 0, p.errorf(t, "expected an integer, got %s", t)
}

func isIdentifier(s string) bool {
	if s == "" || s[0] >= '0' && s[0] <= '9' {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '.') {
			return false
		}
	}
	return true
}

func (p *parser) parseValue() (valueNode, error) {
	t := p.next()
	if t.kind != tokWord || !isIdentifier(t.text) {
		return nil, p.errorf(t, "expected a field or function, got %s", t)
	}
	name := t.text
	if p.peek().kind == tokLParen {
		return p.parseCall(t)
	}
	if name == "true" || name == "false" {
		return constNode{k: kindBool, v: value{b: name == "true"}}, nil
	}
	if get, ok := mapFields[name]; ok {
		if _, err := p.expect(tokLBracket, `"["`); err != nil {
			return nil, err
		}
		key, err := p.expect(tokString, "a string key")
		if err != nil {
			return nil, err
		}
		if _, err := p.expect(tokRBracket, `"]"`); err != nil {
			return nil, err
		}
		k := key.text
		return fieldNode{k: kindString, get: func(ctx *Context) value { return value{s: get(ctx, k)} }}, nil
	}
	field, ok := fields[name]
	if !ok {
		return nil, p.errorf(t, "unknown field %q", name)
	}
	return field, nil
}

func (p *parser) parseCall(name token) (valueNode, error) {
	p.next() // "("
	arg, err := p.parseValue()
	if err != nil {
		return nil, err
	}
	if arg.kind() != kindString {
		return nil, p.errorf(name, "%s() expects a string argument, got %s", name.text, arg.kind())
	}
	var node valueNode
	switch name.text {
	case "lower":
		node = stringFunc{arg: arg, fn: strings.ToLower}
	case "upper":
		node = stringFunc{arg: arg, fn: strings.ToUpper}
	case "url_decode":
		node = stringFunc{arg: arg, fn: urlDecode}
	case "len":
		node = lenFunc{arg: arg}
	case "starts_with", "ends_with":
		if _, err := p.expect(tokComma, `","`); err != nil {
			return nil, err
		}
		affix, err := p.expect(tokString, "a string literal")
		if err != nil {
			return nil, err
		}
		fn := strings.HasPrefix
		if name.text == "ends_with" {
			fn = strings.HasSuffix
		}
		node = affixFunc{arg: arg, affix: affix.text, fn: fn}
	default:
		return nil, p.errorf(name, "unknown function %q", name.text)
	}
	if _, err := p.expect(tokRParen, `")"`); err != nil {
		return nil, err
	}
	return node, nil
}

// compileWildcard turns a Cloudflare wildcard into an anchored regexp: * matches any run of
// characters, \* and \\ are literals. The non-strict form is case-insensitive.
func compileWildcard(pattern string, caseSensitive bool) (*regexp.Regexp, error) {
	var sb, lit strings.Builder
	if !caseSensitive {
		sb.WriteString("(?i)")
	}
	sb.WriteString("(?s)^")
	for i := 0; i < len(pattern); i++ {
		c := pattern[i]
		if c == '\\' && i+1 < len(pattern) && (pattern[i+1] == '*' || pattern[i+1] == '\\') {
			lit.WriteByte(pattern[i+1])
			i++
			continue
		}
		if c == '*' {
			sb.WriteString(regexp.QuoteMeta(lit.String()))
			lit.Reset()
			sb.WriteString(".*")
			continue
		}
		lit.WriteByte(c)
	}
	sb.WriteString(regexp.QuoteMeta(lit.String()))
	sb.WriteString("$")
	return regexp.Compile(sb.String())
}

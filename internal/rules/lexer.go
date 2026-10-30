package rules

import (
	"fmt"
	"strings"
)

type tokenKind int

const (
	tokEOF  tokenKind = iota
	tokWord           // identifiers, keywords, numbers, IP and CIDR literals
	tokString
	tokLParen
	tokRParen
	tokLBrace
	tokRBrace
	tokLBracket
	tokRBracket
	tokComma
	tokOp // symbolic operators: == != && || ^^ ! ~ < <= > >=
)

type token struct {
	kind tokenKind
	text string
	pos  int // 1-based column
}

func (t token) String() string {
	if t.kind == tokEOF {
		return "end of expression"
	}
	return fmt.Sprintf("%q", t.text)
}

// isWordChar covers identifiers with dots plus IPv4/IPv6/CIDR literals.
func isWordChar(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' ||
		c == '_' || c == '.' || c == ':' || c == '/'
}

func lex(src string) ([]token, error) {
	var tokens []token
	i := 0
	for i < len(src) {
		c := src[i]
		start := i
		switch {
		case c == ' ' || c == '\t' || c == '\n' || c == '\r':
			i++
		case c == '"':
			var sb strings.Builder
			i++
			closed := false
			for i < len(src) {
				ch := src[i]
				if ch == '\\' {
					if i+1 >= len(src) {
						break
					}
					next := src[i+1]
					if next != '"' && next != '\\' {
						return nil, fmt.Errorf("col %d: invalid escape \\%c (only \\\" and \\\\ are allowed)", i+1, next)
					}
					sb.WriteByte(next)
					i += 2
					continue
				}
				if ch == '"' {
					closed = true
					i++
					break
				}
				sb.WriteByte(ch)
				i++
			}
			if !closed {
				return nil, fmt.Errorf("col %d: unterminated string", start+1)
			}
			tokens = append(tokens, token{kind: tokString, text: sb.String(), pos: start + 1})
		case c == '(':
			tokens = append(tokens, token{kind: tokLParen, text: "(", pos: start + 1})
			i++
		case c == ')':
			tokens = append(tokens, token{kind: tokRParen, text: ")", pos: start + 1})
			i++
		case c == '{':
			tokens = append(tokens, token{kind: tokLBrace, text: "{", pos: start + 1})
			i++
		case c == '}':
			tokens = append(tokens, token{kind: tokRBrace, text: "}", pos: start + 1})
			i++
		case c == '[':
			tokens = append(tokens, token{kind: tokLBracket, text: "[", pos: start + 1})
			i++
		case c == ']':
			tokens = append(tokens, token{kind: tokRBracket, text: "]", pos: start + 1})
			i++
		case c == ',':
			tokens = append(tokens, token{kind: tokComma, text: ",", pos: start + 1})
			i++
		case isWordChar(c):
			for i < len(src) && isWordChar(src[i]) {
				i++
			}
			tokens = append(tokens, token{kind: tokWord, text: src[start:i], pos: start + 1})
		default:
			op := ""
			for _, candidate := range []string{"==", "!=", "&&", "||", "^^", "<=", ">=", "!", "~", "<", ">"} {
				if strings.HasPrefix(src[i:], candidate) {
					op = candidate
					break
				}
			}
			if op == "" {
				return nil, fmt.Errorf("col %d: unexpected character %q", start+1, c)
			}
			tokens = append(tokens, token{kind: tokOp, text: op, pos: start + 1})
			i += len(op)
		}
	}
	tokens = append(tokens, token{kind: tokEOF, pos: len(src) + 1})
	return tokens, nil
}

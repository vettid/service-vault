package servicevault

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sort"
	"strconv"
	"unicode/utf16"
	"unicode/utf8"
)

// The action hash of an admin approval (README "Admin approvals"):
//
//	action_hash = hex(SHA-256(JCS({"action": action, "payload": payload, "summary": summary})))
//
// where JCS is the JSON Canonicalization Scheme of RFC 8785: no
// whitespace; object members sorted by their names' UTF-16 code units;
// strings with only '"', '\' and U+0000..U+001F escaped (\b \t \n \f \r
// short, the rest as lowercase \u00xx) and everything else as UTF-8;
// numbers as IEEE-754 doubles printed the way ECMAScript prints them
// (so integers beyond 2^53 lose precision: carry them as strings).
// Duplicate member names, invalid UTF-8 and lone surrogates are errors.
// Any RFC 8785 implementation computes the same bytes.

// MaxCanonicalDepth bounds the nesting of a canonicalized value.
const MaxCanonicalDepth = 64

// ErrCanonical is returned for input that has no canonical form.
var ErrCanonical = errors.New("servicevault: JSON has no canonical form")

// CanonicalJSON returns the RFC 8785 canonical form of one JSON value.
func CanonicalJSON(in []byte) ([]byte, error) {
	if !utf8.Valid(in) {
		return nil, ErrCanonical
	}
	p := &jcsParser{in: in}
	var out bytes.Buffer
	p.ws()
	if err := p.value(&out, 0); err != nil {
		return nil, err
	}
	p.ws()
	if p.i != len(p.in) {
		return nil, ErrCanonical
	}
	return out.Bytes(), nil
}

// CanonicalAction returns the canonical bytes that ActionHash hashes.
// payload must be a JSON object.
func CanonicalAction(action, summary string, payload json.RawMessage) ([]byte, error) {
	cp, err := CanonicalJSON(payload)
	if err != nil {
		return nil, err
	}
	if len(cp) == 0 || cp[0] != '{' {
		return nil, ErrCanonical
	}
	if !utf8.ValidString(action) || !utf8.ValidString(summary) {
		return nil, ErrCanonical
	}
	var b bytes.Buffer
	b.WriteString(`{"action":`)
	writeJCSString(&b, action)
	b.WriteString(`,"payload":`)
	b.Write(cp)
	b.WriteString(`,"summary":`)
	writeJCSString(&b, summary)
	b.WriteByte('}')
	return b.Bytes(), nil
}

// ActionHash is the hex SHA-256 of CanonicalAction: the hash the service
// vault returns for an approval and puts (its first 8 hex digits) in the
// admins' challenge, so the application can check that the approval is
// for exactly the action it submitted.
func ActionHash(action, summary string, payload json.RawMessage) (string, error) {
	c, err := CanonicalAction(action, summary, payload)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(c)
	return hex.EncodeToString(sum[:]), nil
}

type jcsParser struct {
	in []byte
	i  int
}

func (p *jcsParser) ws() {
	for p.i < len(p.in) {
		switch p.in[p.i] {
		case ' ', '\t', '\n', '\r':
			p.i++
		default:
			return
		}
	}
}

func (p *jcsParser) lit(s string) bool {
	if bytes.HasPrefix(p.in[p.i:], []byte(s)) {
		p.i += len(s)
		return true
	}
	return false
}

func (p *jcsParser) value(out *bytes.Buffer, depth int) error {
	if depth > MaxCanonicalDepth || p.i >= len(p.in) {
		return ErrCanonical
	}
	switch c := p.in[p.i]; {
	case c == '{':
		return p.object(out, depth)
	case c == '[':
		return p.array(out, depth)
	case c == '"':
		s, err := p.str()
		if err != nil {
			return err
		}
		writeJCSString(out, s)
		return nil
	case c == '-' || c >= '0' && c <= '9':
		return p.number(out)
	case p.lit("true"):
		out.WriteString("true")
	case p.lit("false"):
		out.WriteString("false")
	case p.lit("null"):
		out.WriteString("null")
	default:
		return ErrCanonical
	}
	return nil
}

type jcsMember struct {
	name  string
	key   []uint16
	value []byte
}

func (p *jcsParser) object(out *bytes.Buffer, depth int) error {
	p.i++ // '{'
	var ms []jcsMember
	seen := map[string]bool{}
	p.ws()
	if p.i < len(p.in) && p.in[p.i] == '}' {
		p.i++
		out.WriteString("{}")
		return nil
	}
	for {
		p.ws()
		if p.i >= len(p.in) || p.in[p.i] != '"' {
			return ErrCanonical
		}
		name, err := p.str()
		if err != nil {
			return err
		}
		if seen[name] {
			return ErrCanonical
		}
		seen[name] = true
		p.ws()
		if p.i >= len(p.in) || p.in[p.i] != ':' {
			return ErrCanonical
		}
		p.i++
		p.ws()
		var v bytes.Buffer
		if err := p.value(&v, depth+1); err != nil {
			return err
		}
		ms = append(ms, jcsMember{name: name, key: utf16.Encode([]rune(name)), value: v.Bytes()})
		p.ws()
		if p.i >= len(p.in) {
			return ErrCanonical
		}
		if p.in[p.i] == ',' {
			p.i++
			continue
		}
		if p.in[p.i] != '}' {
			return ErrCanonical
		}
		p.i++
		break
	}
	sort.Slice(ms, func(a, b int) bool { return lessUTF16(ms[a].key, ms[b].key) })
	out.WriteByte('{')
	for i, m := range ms {
		if i > 0 {
			out.WriteByte(',')
		}
		writeJCSString(out, m.name)
		out.WriteByte(':')
		out.Write(m.value)
	}
	out.WriteByte('}')
	return nil
}

func lessUTF16(a, b []uint16) bool {
	for i := 0; i < len(a) && i < len(b); i++ {
		if a[i] != b[i] {
			return a[i] < b[i]
		}
	}
	return len(a) < len(b)
}

func (p *jcsParser) array(out *bytes.Buffer, depth int) error {
	p.i++ // '['
	out.WriteByte('[')
	p.ws()
	if p.i < len(p.in) && p.in[p.i] == ']' {
		p.i++
		out.WriteByte(']')
		return nil
	}
	for n := 0; ; n++ {
		if n > 0 {
			out.WriteByte(',')
		}
		p.ws()
		if err := p.value(out, depth+1); err != nil {
			return err
		}
		p.ws()
		if p.i >= len(p.in) {
			return ErrCanonical
		}
		if p.in[p.i] == ',' {
			p.i++
			continue
		}
		if p.in[p.i] != ']' {
			return ErrCanonical
		}
		p.i++
		out.WriteByte(']')
		return nil
	}
}

// str parses a JSON string (RFC 8259 §7) at p.i, rejecting lone
// surrogates.
func (p *jcsParser) str() (string, error) {
	p.i++ // '"'
	var b []rune
	for {
		if p.i >= len(p.in) {
			return "", ErrCanonical
		}
		c := p.in[p.i]
		switch {
		case c == '"':
			p.i++
			return string(b), nil
		case c < 0x20:
			return "", ErrCanonical
		case c == '\\':
			if p.i+1 >= len(p.in) {
				return "", ErrCanonical
			}
			e := p.in[p.i+1]
			p.i += 2
			switch e {
			case '"', '\\', '/':
				b = append(b, rune(e))
			case 'b':
				b = append(b, '\b')
			case 'f':
				b = append(b, '\f')
			case 'n':
				b = append(b, '\n')
			case 'r':
				b = append(b, '\r')
			case 't':
				b = append(b, '\t')
			case 'u':
				r, ok := p.hex4()
				if !ok {
					return "", ErrCanonical
				}
				switch {
				case utf16.IsSurrogate(r) && r < 0xDC00:
					if !p.lit(`\u`) {
						return "", ErrCanonical
					}
					lo, ok := p.hex4()
					if !ok || lo < 0xDC00 || lo > 0xDFFF {
						return "", ErrCanonical
					}
					r = utf16.DecodeRune(r, lo)
				case utf16.IsSurrogate(r):
					return "", ErrCanonical
				}
				b = append(b, r)
			default:
				return "", ErrCanonical
			}
		default:
			r, n := utf8.DecodeRune(p.in[p.i:])
			if r == utf8.RuneError && n <= 1 {
				return "", ErrCanonical
			}
			b = append(b, r)
			p.i += n
		}
	}
}

func (p *jcsParser) hex4() (rune, bool) {
	if p.i+4 > len(p.in) {
		return 0, false
	}
	v, err := strconv.ParseUint(string(p.in[p.i:p.i+4]), 16, 32)
	if err != nil {
		return 0, false
	}
	p.i += 4
	return rune(v), true
}

// number parses a JSON number (RFC 8259 §6) and writes it as ECMAScript
// prints the nearest double (RFC 8785 §3.2.2.3).
func (p *jcsParser) number(out *bytes.Buffer) error {
	start := p.i
	if p.in[p.i] == '-' {
		p.i++
	}
	digits := func() int {
		n := 0
		for p.i < len(p.in) && p.in[p.i] >= '0' && p.in[p.i] <= '9' {
			p.i++
			n++
		}
		return n
	}
	if p.i < len(p.in) && p.in[p.i] == '0' {
		p.i++
	} else if digits() == 0 {
		return ErrCanonical
	}
	if p.i < len(p.in) && p.in[p.i] == '.' {
		p.i++
		if digits() == 0 {
			return ErrCanonical
		}
	}
	if p.i < len(p.in) && (p.in[p.i] == 'e' || p.in[p.i] == 'E') {
		p.i++
		if p.i < len(p.in) && (p.in[p.i] == '+' || p.in[p.i] == '-') {
			p.i++
		}
		if digits() == 0 {
			return ErrCanonical
		}
	}
	f, err := strconv.ParseFloat(string(p.in[start:p.i]), 64)
	if err != nil {
		return ErrCanonical // out of the double range
	}
	out.Write(formatES(f))
	return nil
}

// formatES prints f as ECMAScript's Number.prototype.toString does: the
// shortest digits that round-trip, plain notation for 1e-6 <= |f| < 1e21
// and exponent notation ("1e+21", "1.5e-7") otherwise; -0 is "0".
func formatES(f float64) []byte {
	if f == 0 {
		return []byte("0")
	}
	abs := f
	if abs < 0 {
		abs = -abs
	}
	format := byte('f')
	if abs < 1e-6 || abs >= 1e21 {
		format = 'e'
	}
	b := strconv.AppendFloat(nil, f, format, -1, 64)
	if format == 'e' {
		// "1e-07" -> "1e-7", "1e+07" cannot occur here.
		n := len(b)
		if n >= 4 && b[n-4] == 'e' && b[n-2] == '0' {
			b[n-2] = b[n-1]
			b = b[:n-1]
		}
	}
	return b
}

const hexDigits = "0123456789abcdef"

// writeJCSString writes s as RFC 8785 §3.2.2.2 does.
func writeJCSString(b *bytes.Buffer, s string) {
	b.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"':
			b.WriteString(`\"`)
		case '\\':
			b.WriteString(`\\`)
		case '\b':
			b.WriteString(`\b`)
		case '\t':
			b.WriteString(`\t`)
		case '\n':
			b.WriteString(`\n`)
		case '\f':
			b.WriteString(`\f`)
		case '\r':
			b.WriteString(`\r`)
		default:
			if r < 0x20 {
				b.WriteString(`\u00`)
				b.WriteByte(hexDigits[r>>4])
				b.WriteByte(hexDigits[r&0xF])
			} else {
				b.WriteRune(r)
			}
		}
	}
	b.WriteByte('"')
}

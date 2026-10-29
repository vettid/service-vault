package ballot

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
	"unicode/utf16"
	"unicode/utf8"
)

// JCS (RFC 8785) for the documents (BALLOT-PROTOCOL §2). The documents
// hold only objects, arrays, strings, integers, booleans and null, so the
// number rule reduces to plain integers of at most 2^53 − 1 in magnitude.

var errJCS = errors.New("ballot: not a canonical document")

const maxSafeInt = 1<<53 - 1

// parseStrict parses data as one JSON value with no duplicate member
// names at any depth, no fractions or exponents, and nothing after it.
// Objects come back as map[string]any, arrays as []any, integers as
// int64.
func parseStrict(data []byte) (any, error) {
	if !utf8.Valid(data) {
		return nil, errJCS
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	v, err := parseValue(dec)
	if err != nil {
		return nil, err
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, errJCS
	}
	return v, nil
}

func parseValue(dec *json.Decoder) (any, error) {
	tok, err := dec.Token()
	if err != nil {
		return nil, errJCS
	}
	switch t := tok.(type) {
	case json.Delim:
		switch t {
		case '{':
			m := map[string]any{}
			for dec.More() {
				kt, err := dec.Token()
				if err != nil {
					return nil, errJCS
				}
				k, ok := kt.(string)
				if !ok {
					return nil, errJCS
				}
				if _, dup := m[k]; dup {
					return nil, fmt.Errorf("%w: duplicate member %q", errJCS, k)
				}
				v, err := parseValue(dec)
				if err != nil {
					return nil, err
				}
				m[k] = v
			}
			if _, err := dec.Token(); err != nil {
				return nil, errJCS
			}
			return m, nil
		case '[':
			a := []any{}
			for dec.More() {
				v, err := parseValue(dec)
				if err != nil {
					return nil, err
				}
				a = append(a, v)
			}
			if _, err := dec.Token(); err != nil {
				return nil, errJCS
			}
			return a, nil
		}
		return nil, errJCS
	case json.Number:
		s := string(t)
		if strings.ContainsAny(s, ".eE") || s == "-0" {
			return nil, errJCS
		}
		n, err := strconv.ParseInt(s, 10, 64)
		if err != nil || n > maxSafeInt || n < -maxSafeInt {
			return nil, errJCS
		}
		return n, nil
	case string, bool, nil:
		return t, nil
	}
	return nil, errJCS
}

// canonical writes v in JCS form.
func canonical(buf *bytes.Buffer, v any) error {
	switch x := v.(type) {
	case nil:
		buf.WriteString("null")
	case bool:
		buf.WriteString(strconv.FormatBool(x))
	case int64:
		buf.WriteString(strconv.FormatInt(x, 10))
	case string:
		writeString(buf, x)
	case []any:
		buf.WriteByte('[')
		for i, e := range x {
			if i > 0 {
				buf.WriteByte(',')
			}
			if err := canonical(buf, e); err != nil {
				return err
			}
		}
		buf.WriteByte(']')
	case map[string]any:
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		// RFC 8785 §3.2.3: sort by UTF-16 code units.
		sort.Slice(keys, func(i, j int) bool { return lessUTF16(keys[i], keys[j]) })
		buf.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				buf.WriteByte(',')
			}
			writeString(buf, k)
			buf.WriteByte(':')
			if err := canonical(buf, x[k]); err != nil {
				return err
			}
		}
		buf.WriteByte('}')
	default:
		return errJCS
	}
	return nil
}

func lessUTF16(a, b string) bool {
	ua, ub := utf16.Encode([]rune(a)), utf16.Encode([]rune(b))
	for i := 0; i < len(ua) && i < len(ub); i++ {
		if ua[i] != ub[i] {
			return ua[i] < ub[i]
		}
	}
	return len(ua) < len(ub)
}

// writeString escapes as RFC 8785 §3.2.2.2 (ECMAScript JSON.stringify):
// the two-character escapes, \u00xx (lower-case hex) for other control
// characters, and everything else as itself.
func writeString(buf *bytes.Buffer, s string) {
	buf.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"':
			buf.WriteString(`\"`)
		case '\\':
			buf.WriteString(`\\`)
		case '\b':
			buf.WriteString(`\b`)
		case '\f':
			buf.WriteString(`\f`)
		case '\n':
			buf.WriteString(`\n`)
		case '\r':
			buf.WriteString(`\r`)
		case '\t':
			buf.WriteString(`\t`)
		default:
			if r < 0x20 {
				fmt.Fprintf(buf, `\u%04x`, r)
			} else {
				buf.WriteRune(r)
			}
		}
	}
	buf.WriteByte('"')
}

// Canonicalize parses data strictly and returns its JCS form.
func Canonicalize(data []byte) ([]byte, error) {
	v, err := parseStrict(data)
	if err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	if err := canonical(&buf, v); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// checkCanonical refuses data unless it is exactly its own JCS form
// (BALLOT-PROTOCOL §2), and returns the parsed tree.
func checkCanonical(data []byte) (map[string]any, error) {
	v, err := parseStrict(data)
	if err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	if err := canonical(&buf, v); err != nil {
		return nil, err
	}
	if !bytes.Equal(buf.Bytes(), data) {
		return nil, fmt.Errorf("%w: not in canonical form", errJCS)
	}
	m, ok := v.(map[string]any)
	if !ok {
		return nil, errJCS
	}
	return m, nil
}

// encodeCanonical marshals v (a document struct) and returns its JCS
// form.
func encodeCanonical(v any) ([]byte, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	return Canonicalize(b)
}

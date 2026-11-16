package servicevault

import (
	"bytes"
	"encoding/json"
	"io"
	"strconv"
	"strings"
)

// An approval challenge that carries its document, CanonicalAction's
// bytes, is dropped by a member's vault that would not accept the
// document (VAULT-MESSAGING §10.4 "Approval documents", the receiver's
// checks): silently, so the approval would gather no answers. The
// challenger must check a document as the receiver will before it sends
// one (§10.4, §15 item 53). The service vault refuses every approval
// whose document fails ApprovalDocument, and an application can make the
// same checks before it submits one.
const (
	// MaxDocumentBytes bounds a document.
	MaxDocumentBytes = 65536
	// MaxDocumentDepth bounds a document's nesting: the document object
	// is level 1 and each object or array inside it one more, so a
	// payload nests at most 15 levels, itself included.
	MaxDocumentDepth = 16
	// MaxDocumentSummary bounds a document's summary, in bytes.
	MaxDocumentSummary = 1024
	// MaxSafeInteger is the largest number a document may hold
	// (VAULT-MESSAGING §5.3): every number is an integer with no sign,
	// fraction or exponent, from 0 to 2^53 - 1. Carry a signed or
	// fractional value, or a larger one, as a string.
	MaxSafeInteger = 1<<53 - 1
)

// Reasons of a DocumentError.
const (
	DocumentSize   = "size"   // over MaxDocumentBytes
	DocumentDepth  = "depth"  // nested deeper than MaxDocumentDepth
	DocumentNumber = "number" // a number other than an integer from 0 to MaxSafeInteger
	DocumentShape  = "shape"  // an action outside [a-z0-9_.]{1,64}, or a summary over MaxDocumentSummary bytes
)

// DocumentError is a document a member's vault would drop.
type DocumentError struct {
	Reason string // DocumentSize, DocumentDepth, DocumentNumber or DocumentShape
	// Field is where in the document, as an RFC 6901 JSON pointer (for
	// example "/payload/change/amount"): the number, the object or array
	// one level too deep, or "/action" or "/summary". It is empty for
	// DocumentSize.
	Field string
}

func (e *DocumentError) Error() string {
	switch e.Reason {
	case DocumentSize:
		return "servicevault: approval document over 65536 bytes"
	case DocumentDepth:
		return "servicevault: approval document nested over 16 levels at " + strconv.Quote(e.Field)
	case DocumentShape:
		return "servicevault: approval document " + strconv.Quote(e.Field) + " out of bounds"
	}
	return "servicevault: approval document number at " + strconv.Quote(e.Field) + " is not an integer from 0 to 2^53-1"
}

// ApprovalDocument returns CanonicalAction's bytes if a member's vault
// would accept them as an approval document; otherwise its error is a
// *DocumentError, or ErrCanonical for input with no canonical form.
// Beyond CheckDocument, the action is 1 to 64 bytes of [a-z0-9_.] and
// the summary at most MaxDocumentSummary bytes (DocumentShape).
func ApprovalDocument(action, summary string, payload json.RawMessage) ([]byte, error) {
	if !documentAction(action) {
		return nil, &DocumentError{Reason: DocumentShape, Field: "/action"}
	}
	if len(summary) > MaxDocumentSummary {
		return nil, &DocumentError{Reason: DocumentShape, Field: "/summary"}
	}
	doc, err := CanonicalAction(action, summary, payload)
	if err != nil {
		return nil, err
	}
	if err := CheckDocument(doc); err != nil {
		return nil, err
	}
	return doc, nil
}

func documentAction(a string) bool {
	if a == "" || len(a) > 64 {
		return false
	}
	for i := 0; i < len(a); i++ {
		if c := a[i]; !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '_' || c == '.') {
			return false
		}
	}
	return true
}

// CheckDocument checks doc's size, nesting and numbers as a member's
// vault does (a *DocumentError), and that doc is one canonical JSON
// value (ErrCanonical). The numbers are judged in the canonical bytes,
// so an input 1.0, 1e3 or -0 passes: it is 1, 1000 or 0 there. In the
// vault's order: the size, then the nesting of the whole document, then
// the numbers, then whether the bytes are canonical, so bytes that are
// not canonical can fail as DocumentNumber first (1.0 as sent). It does
// not check the members of the document, which CanonicalAction builds.
func CheckDocument(doc []byte) error {
	if len(doc) > MaxDocumentBytes {
		return &DocumentError{Reason: DocumentSize}
	}
	for _, numbers := range []bool{false, true} {
		dec := json.NewDecoder(bytes.NewReader(doc))
		dec.UseNumber()
		if err := checkDocValue(dec, "", 1, numbers); err != nil {
			return err
		}
		if _, err := dec.Token(); err != io.EOF {
			return ErrCanonical
		}
	}
	c, err := CanonicalJSON(doc)
	if err != nil {
		return err
	}
	if !bytes.Equal(c, doc) {
		return ErrCanonical
	}
	return nil
}

// checkDocValue checks the value at path, which is at nesting level
// level if it is an object or an array: the nesting, and the numbers if
// numbers is set.
func checkDocValue(dec *json.Decoder, path string, level int, numbers bool) error {
	tok, err := dec.Token()
	if err != nil {
		return ErrCanonical
	}
	switch t := tok.(type) {
	case json.Delim:
		if level > MaxDocumentDepth {
			return &DocumentError{Reason: DocumentDepth, Field: path}
		}
		switch t {
		case '{':
			for dec.More() {
				kt, err := dec.Token()
				if err != nil {
					return ErrCanonical
				}
				k, ok := kt.(string)
				if !ok {
					return ErrCanonical
				}
				if err := checkDocValue(dec, path+"/"+pointerToken(k), level+1, numbers); err != nil {
					return err
				}
			}
		case '[':
			for i := 0; dec.More(); i++ {
				if err := checkDocValue(dec, path+"/"+strconv.Itoa(i), level+1, numbers); err != nil {
					return err
				}
			}
		default:
			return ErrCanonical
		}
		if _, err := dec.Token(); err != nil {
			return ErrCanonical
		}
	case json.Number:
		if numbers && !safeInteger(string(t)) {
			return &DocumentError{Reason: DocumentNumber, Field: path}
		}
	}
	return nil
}

// safeInteger reports whether the JSON number s is a plain integer from
// 0 to MaxSafeInteger. ParseUint in base 10 takes digits only: no sign,
// point or exponent.
func safeInteger(s string) bool {
	n, err := strconv.ParseUint(s, 10, 64)
	return err == nil && n <= MaxSafeInteger
}

// pointerToken escapes a member name for a JSON pointer (RFC 6901 §3).
func pointerToken(s string) string {
	return strings.ReplaceAll(strings.ReplaceAll(s, "~", "~0"), "/", "~1")
}

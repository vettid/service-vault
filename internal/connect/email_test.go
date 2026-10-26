package connect

import (
	"bytes"
	"strings"
	"testing"
)

func TestNormalizeEmail(t *testing.T) {
	good := map[string]string{
		"member@example.org":             "member@example.org",
		"  Member@Example.ORG ":          "member@example.org",
		"first.last+tag@sub.example.org": "first.last+tag@sub.example.org",
		"member@example.org\n":           "member@example.org",
	}
	for in, want := range good {
		got, err := NormalizeEmail(in)
		if err != nil || got != want {
			t.Errorf("NormalizeEmail(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	bad := []string{
		"", "   ", "member", "member@", "@example.org", "member@localhost",
		"Member <member@example.org>", "<member@example.org>", "member@example.org (work)",
		"a b@example.org", "mem\nber@example.org", "\"quoted\"@example.org",
		strings.Repeat("a", 250) + "@example.org", "m\xffember@example.org",
	}
	for _, in := range bad {
		if got, err := NormalizeEmail(in); err != ErrEmail {
			t.Errorf("NormalizeEmail(%q) = %q, %v; want ErrEmail", in, got, err)
		}
	}
}

func TestEmailIndexKey(t *testing.T) {
	if _, err := NewEmailIndex(make([]byte, 31)); err != ErrPepper {
		t.Fatalf("short pepper: %v", err)
	}
	x, err := NewEmailIndex(bytes.Repeat([]byte{1}, 32))
	if err != nil {
		t.Fatal(err)
	}
	y, _ := NewEmailIndex(bytes.Repeat([]byte{2}, 32))

	k1, err := x.Key("Member@Example.org")
	if err != nil {
		t.Fatal(err)
	}
	k2, _ := x.Key(" member@example.org")
	if k1 != k2 {
		t.Fatal("same address, different keys")
	}
	if len(k1) != 64 || strings.Contains(k1, "member") {
		t.Fatalf("key %q", k1)
	}
	if k3, _ := x.Key("other@example.org"); k3 == k1 {
		t.Fatal("different addresses, same key")
	}
	if k4, _ := y.Key("member@example.org"); k4 == k1 {
		t.Fatal("different peppers, same key")
	}
	if _, err := x.Key("not an address"); err != ErrEmail {
		t.Fatalf("bad address: %v", err)
	}
}

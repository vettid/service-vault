package webhook

import (
	"bytes"
	"strings"
	"testing"
	"time"
)

var (
	secret = bytes.Repeat([]byte{0x5a}, 32)
	now    = time.Unix(1_800_000_000, 0)
	body   = []byte(`{"type":"signin.approved","connection_id":"c1"}`)
	id     = "01JBT9Z5X8M3K0Q4R7V2W6Y1A9"
)

func TestSignVerify(t *testing.T) {
	h, err := Sign(secret, now, id, body)
	if err != nil {
		t.Fatal(err)
	}
	if err := Verify(secret, h, id, body, now.Add(time.Minute), DefaultTolerance); err != nil {
		t.Fatalf("Verify: %v", err)
	}
}

func TestVerifyRejects(t *testing.T) {
	h, _ := Sign(secret, now, id, body)
	other := bytes.Repeat([]byte{0x6b}, 32)
	cases := []struct {
		name   string
		secret []byte
		header string
		id     string
		body   []byte
		at     time.Time
		want   error
	}{
		{"tampered body", secret, h, id, []byte(`{"type":"signin.approved","connection_id":"c2"}`), now, ErrMismatch},
		{"other event id", secret, h, "01JBT9Z5X8M3K0Q4R7V2W6Y1B0", body, now, ErrMismatch},
		{"other secret", other, h, id, body, now, ErrMismatch},
		{"too old", secret, h, id, body, now.Add(DefaultTolerance + time.Second), ErrStale},
		{"from the future", secret, h, id, body, now.Add(-DefaultTolerance - time.Second), ErrStale},
		{"short secret", secret[:31], h, id, body, now, ErrSecret},
		{"no timestamp", secret, h[strings.Index(h, ",")+1:], id, body, now, ErrMalformed},
		{"no v1", secret, h[:strings.Index(h, ",")], id, body, now, ErrMalformed},
		{"bad hex", secret, "t=1800000000,v1=zz", id, body, now, ErrMalformed},
		{"two timestamps", secret, "t=1,t=2," + h[strings.Index(h, ",")+1:], id, body, now, ErrMalformed},
		{"no event id", secret, h, "", body, now, ErrMalformed},
	}
	for _, c := range cases {
		if err := Verify(c.secret, c.header, c.id, c.body, c.at, DefaultTolerance); err != c.want {
			t.Errorf("%s: err %v, want %v", c.name, err, c.want)
		}
	}
}

func TestVerifyDuringRotation(t *testing.T) {
	old := bytes.Repeat([]byte{0x6b}, 32)
	h1, _ := Sign(old, now, id, body)
	h2, _ := Sign(secret, now, id, body)
	both := h1 + "," + h2[strings.Index(h2, ",")+1:]
	for _, s := range [][]byte{old, secret} {
		if err := Verify(s, both, id, body, now, DefaultTolerance); err != nil {
			t.Fatalf("Verify with either secret: %v", err)
		}
	}
}

func TestSignShortSecret(t *testing.T) {
	if _, err := Sign(secret[:16], now, id, body); err != ErrSecret {
		t.Fatalf("err %v", err)
	}
}

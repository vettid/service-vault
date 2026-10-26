package signin

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestMatchCode(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 5000; i++ {
		c, err := MatchCode()
		if err != nil {
			t.Fatal(err)
		}
		if len(c) != 2 || c < "10" || c > "99" {
			t.Fatalf("code %q", c)
		}
		seen[c] = true
	}
	if len(seen) != 90 {
		t.Fatalf("%d distinct codes in 5000 draws, want 90", len(seen))
	}
}

func TestContext(t *testing.T) {
	s, err := Context("VettID Member Service", "42")
	if err != nil || s != "Sign in to VettID Member Service — match code 42" {
		t.Fatalf("%q %v", s, err)
	}
	if _, err := Context(strings.Repeat("x", 250), "42"); err == nil {
		t.Fatal("over-long context accepted")
	}
}

func TestUniform(t *testing.T) {
	floor := 50 * time.Millisecond
	for _, work := range []time.Duration{0, 20 * time.Millisecond} {
		start := time.Now()
		over := Uniform(context.Background(), floor, func(context.Context) { time.Sleep(work) })
		if d := time.Since(start); over || d < floor || d > floor+40*time.Millisecond {
			t.Fatalf("work %v: took %v, overran %v", work, d, over)
		}
	}
	if !Uniform(context.Background(), time.Millisecond, func(context.Context) { time.Sleep(5 * time.Millisecond) }) {
		t.Fatal("overrun not reported")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	start := time.Now()
	Uniform(ctx, time.Second, func(context.Context) {})
	if time.Since(start) > 100*time.Millisecond {
		t.Fatal("cancelled context did not end the wait")
	}
}

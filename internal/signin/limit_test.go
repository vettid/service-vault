package signin

import (
	"context"
	"sync"
	"testing"
	"time"
)

func TestParseLimits(t *testing.T) {
	l, err := ParseLimits("", DefaultEmailLimits)
	if err != nil || len(l) != 2 || l[0].String() != "5/15m" || l[1].String() != "20/24h" {
		t.Fatalf("%v %v", l, err)
	}
	if l, err := ParseLimits(" 3/90s, 10/1h ", nil); err != nil || len(l) != 2 || l[0] != (Limit{3, 90 * time.Second}) || l[1].String() != "10/1h" {
		t.Fatalf("%v %v", l, err)
	}
	if l, err := ParseLimits("none", DefaultSourceLimits); err != nil || l != nil {
		t.Fatalf("%v %v", l, err)
	}
	for _, bad := range []string{"5", "0/1m", "-1/1m", "x/1m", "5/0s", "5/1500ms", "5/200h", "5/1m,"} {
		if _, err := ParseLimits(bad, nil); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestWindowStart(t *testing.T) {
	now := time.Date(2026, 10, 27, 12, 14, 59, 0, time.UTC)
	if got := WindowStart(now, 15*time.Minute); !got.Equal(time.Date(2026, 10, 27, 12, 0, 0, 0, time.UTC)) {
		t.Fatal(got)
	}
	if got := WindowStart(now.Add(time.Second), 15*time.Minute); !got.Equal(time.Date(2026, 10, 27, 12, 15, 0, 0, time.UTC)) {
		t.Fatal(got)
	}
	if got := WindowStart(now, 24*time.Hour); !got.Equal(time.Date(2026, 10, 27, 0, 0, 0, 0, time.UTC)) {
		t.Fatal(got)
	}
}

func TestLimiter(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 10, 27, 12, 0, 0, 0, time.UTC)
	l := &Limiter{Counters: &MemCounters{}, Email: DefaultEmailLimits, Source: DefaultSourceLimits}
	for i := 0; i < 5; i++ {
		if over, err := l.Count(ctx, "e", "s", now); over != "" || err != nil {
			t.Fatalf("%d: %q %v", i, over, err)
		}
	}
	if over, _ := l.Count(ctx, "e", "s", now); over != "email 5/15m" {
		t.Fatalf("over %q", over)
	}
	// Per-day: windows of 15 minutes pass; 20 a day.
	n := 6
	for w := 1; n < 20; w++ {
		for i := 0; i < 5 && n < 20; i++ {
			if over, _ := l.Count(ctx, "e", "", now.Add(time.Duration(w)*15*time.Minute)); over != "" {
				t.Fatalf("count %d: %q", n, over)
			}
			n++
		}
	}
	if over, _ := l.Count(ctx, "e", "", now.Add(2*time.Hour)); over != "email 20/24h" {
		t.Fatalf("day %q", over)
	}
	if over, _ := l.Count(ctx, "e", "", now.Add(24*time.Hour)); over != "" {
		t.Fatalf("next day %q", over)
	}
	// Per source, across emails; no source, no source limit.
	for i := 0; i < 20; i++ {
		if over, _ := l.Count(ctx, string(rune('a'+i)), "src", now); over != "" {
			t.Fatalf("source %d: %q", i, over)
		}
	}
	if over, _ := l.Count(ctx, "z", "src", now); over != "source 20/15m" {
		t.Fatalf("source over %q", over)
	}
	if over, _ := l.Count(ctx, "y", "", now); over != "" {
		t.Fatalf("no source %q", over)
	}
	var nilL *Limiter
	if over, err := nilL.Count(ctx, "e", "s", now); over != "" || err != nil {
		t.Fatal("nil limiter limits")
	}
}

// Concurrent counts: each caller gets a distinct value, and exactly Max
// pass.
func TestLimiterConcurrent(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 10, 27, 12, 0, 0, 0, time.UTC)
	l := &Limiter{Counters: &MemCounters{}, Email: []Limit{{Max: 10, Window: time.Minute}}}
	var wg sync.WaitGroup
	var mu sync.Mutex
	passed := 0
	for i := 0; i < 64; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			over, err := l.Count(ctx, "e", "", now)
			if err != nil {
				t.Error(err)
			}
			if over == "" {
				mu.Lock()
				passed++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if passed != 10 {
		t.Fatalf("%d passed", passed)
	}
}

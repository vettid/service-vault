package signin

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Rate limits on starting sign-ins (MEMBER-SERVICE-PLAN §4.2 "per-email
// and per-source rate limits"). Every start is counted against each limit
// of its email key and, when the application passed one, of its source
// key, in fixed windows. A start over any limit is answered as any other
// but sends no challenge (the service decides that, not this package).

// Limit allows at most Max sign-ins in each Window.
type Limit struct {
	Max    int64
	Window time.Duration
}

// String is the limit as ParseLimits reads it ("5/15m").
func (l Limit) String() string { return strconv.FormatInt(l.Max, 10) + "/" + shortDuration(l.Window) }

func shortDuration(d time.Duration) string {
	switch {
	case d%time.Hour == 0:
		return strconv.FormatInt(int64(d/time.Hour), 10) + "h"
	case d%time.Minute == 0:
		return strconv.FormatInt(int64(d/time.Minute), 10) + "m"
	}
	return d.String()
}

// Default limits (chosen; not in the spec): per email key 5 per 15
// minutes and 20 per 24 hours; per source 20 per 15 minutes.
var (
	DefaultEmailLimits  = []Limit{{Max: 5, Window: 15 * time.Minute}, {Max: 20, Window: 24 * time.Hour}}
	DefaultSourceLimits = []Limit{{Max: 20, Window: 15 * time.Minute}}
)

// ParseLimits reads comma-separated "N/duration" limits ("5/15m,20/24h");
// "none" is no limit and "" the given defaults. N is at least 1 and the
// window at least a second and at most 7 days, in whole seconds.
func ParseLimits(s string, def []Limit) ([]Limit, error) {
	s = strings.TrimSpace(s)
	switch s {
	case "":
		return append([]Limit(nil), def...), nil
	case "none":
		return nil, nil
	}
	var out []Limit
	for _, part := range strings.Split(s, ",") {
		n, w, ok := strings.Cut(strings.TrimSpace(part), "/")
		if !ok {
			return nil, fmt.Errorf("signin: limit %q is not N/duration", part)
		}
		limit, err := strconv.ParseInt(n, 10, 64)
		if err != nil || limit < 1 {
			return nil, fmt.Errorf("signin: limit %q: count must be a positive integer", part)
		}
		d, err := time.ParseDuration(w)
		if err != nil || d < time.Second || d > 7*24*time.Hour || d%time.Second != 0 {
			return nil, fmt.Errorf("signin: limit %q: window must be whole seconds from 1s to 168h", part)
		}
		out = append(out, Limit{Max: limit, Window: d})
	}
	return out, nil
}

// Counters keeps the rate-limit counters. Incr adds one to the counter
// named key in the window of the given length that contains now, and
// returns its new value; it must be atomic across concurrent callers, and
// a counter may be forgotten once its window has passed.
type Counters interface {
	Incr(ctx context.Context, key string, window time.Duration, now time.Time) (int64, error)
}

// WindowStart is the start of the fixed window of length w containing
// now (windows are aligned on the Unix epoch).
func WindowStart(now time.Time, w time.Duration) time.Time {
	sec := int64(w / time.Second)
	if sec <= 0 {
		sec = 1
	}
	u := now.Unix()
	return time.Unix(u-((u%sec)+sec)%sec, 0).UTC()
}

// Limiter applies the email and source limits.
type Limiter struct {
	Counters Counters
	Email    []Limit // per email index key
	Source   []Limit // per source key; not applied when no source is given
}

// Count counts one sign-in for emailKey and sourceKey (empty: none) and
// returns the name of a limit it exceeds ("email 5/15m"), or "" when it
// is within every limit. Every limit is counted, exceeded or not. The
// name carries neither the email nor the source.
func (l *Limiter) Count(ctx context.Context, emailKey, sourceKey string, now time.Time) (string, error) {
	if l == nil || l.Counters == nil {
		return "", nil
	}
	if emailKey == "" {
		return "", errors.New("signin: no email key")
	}
	over := ""
	count := func(scope, key string, limits []Limit) error {
		for _, lim := range limits {
			n, err := l.Counters.Incr(ctx, scope+"#"+strconv.FormatInt(int64(lim.Window/time.Second), 10)+"#"+key, lim.Window, now)
			if err != nil {
				return err
			}
			if n > lim.Max && over == "" {
				over = scope + " " + lim.String()
			}
		}
		return nil
	}
	if err := count("email", emailKey, l.Email); err != nil {
		return "", err
	}
	if sourceKey != "" {
		if err := count("source", sourceKey, l.Source); err != nil {
			return "", err
		}
	}
	return over, nil
}

// MemCounters is an in-memory Counters, for tests and local runs.
type MemCounters struct {
	mu sync.Mutex
	m  map[string]memCounter
}

type memCounter struct {
	n   int64
	end time.Time
}

// Incr implements Counters.
func (c *MemCounters) Incr(_ context.Context, key string, window time.Duration, now time.Time) (int64, error) {
	start := WindowStart(now, window)
	k := key + "#" + strconv.FormatInt(start.Unix(), 10)
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.m == nil {
		c.m = map[string]memCounter{}
	}
	for k2, v := range c.m {
		if !now.Before(v.end) {
			delete(c.m, k2)
		}
	}
	v := c.m[k]
	v.n++
	v.end = start.Add(window)
	c.m[k] = v
	return v.n, nil
}

//go:build integration

package integration

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"

	"github.com/vettid/service-vault/internal/peer"
	"github.com/vettid/service-vault/internal/service"
	"github.com/vettid/service-vault/internal/signin"
	"github.com/vettid/service-vault/internal/webhook"
)

// Rate-limit counters on DynamoDB: atomic under concurrency, one item per
// window with a TTL, and kept across a restart (a new Counters on the
// same table).
func TestCountersOnDynamoDB(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	tbl := newTable(t, ctx)
	c := tbl.Counters()
	now := time.Date(2026, 10, 27, 12, 3, 0, 0, time.UTC)

	const n = 40
	var wg sync.WaitGroup
	var mu sync.Mutex
	seen := map[int64]bool{}
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			v, err := c.Incr(ctx, "email#900#k", 15*time.Minute, now)
			if err != nil {
				t.Error(err)
				return
			}
			mu.Lock()
			seen[v] = true
			mu.Unlock()
		}()
	}
	wg.Wait()
	if len(seen) != n || !seen[1] || !seen[n] {
		t.Fatalf("counts not distinct 1..%d: %d distinct", n, len(seen))
	}
	// A restart: the count goes on.
	if v, err := tbl.Counters().Incr(ctx, "email#900#k", 15*time.Minute, now.Add(time.Minute)); err != nil || v != n+1 {
		t.Fatalf("after restart %d %v", v, err)
	}
	// The next window starts again; another key is separate.
	if v, _ := c.Incr(ctx, "email#900#k", 15*time.Minute, now.Add(12*time.Minute)); v != 1 {
		t.Fatalf("next window %d", v)
	}
	if v, _ := c.Incr(ctx, "email#900#other", 15*time.Minute, now); v != 1 {
		t.Fatalf("other key %d", v)
	}
	// The item carries a TTL past its window.
	start := signin.WindowStart(now, 15*time.Minute)
	out, err := tbl.Client.GetItem(ctx, &dynamodb.GetItemInput{TableName: aws.String(tbl.Name), Key: map[string]types.AttributeValue{
		"pk": &types.AttributeValueMemberS{Value: "rl#email#900#k"},
		"sk": &types.AttributeValueMemberS{Value: strconv.FormatInt(start.Unix(), 10)},
	}})
	if err != nil {
		t.Fatal(err)
	}
	ttl, ok := out.Item["ttl"].(*types.AttributeValueMemberN)
	if !ok {
		t.Fatalf("no ttl: %v", out.Item)
	}
	if v, _ := strconv.ParseInt(ttl.Value, 10, 64); v <= start.Add(15*time.Minute).Unix() {
		t.Fatalf("ttl %d inside the window", v)
	}

	// The limiter on DynamoDB: the sixth start in a window is over.
	l := &signin.Limiter{Counters: c, Email: signin.DefaultEmailLimits, Source: signin.DefaultSourceLimits}
	for i := 0; i < 5; i++ {
		if over, err := l.Count(ctx, "e2", "s2", now); over != "" || err != nil {
			t.Fatalf("%d: %q %v", i, over, err)
		}
	}
	if over, _ := l.Count(ctx, "e2", "s2", now); over != "email 5/15m" {
		t.Fatalf("over %q", over)
	}
}

// hookList is the webhook endpoint; all delivers what the outboxes hold
// first.
type hookList struct {
	mu   sync.Mutex
	evs  []*webhook.Event
	outs []*webhook.Outbox
}

func (h *hookList) outbox(st peer.Store, kind string) *webhook.Outbox {
	o := &webhook.Outbox{Store: st, Kind: kind, Sender: h}
	h.outs = append(h.outs, o)
	return o
}

func (h *hookList) Deliver(_ context.Context, e *webhook.Event) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.evs = append(h.evs, e)
	return nil
}

// The email binding's conditional write on DynamoDB: of connections
// added at once with one email exactly one binds; removing it frees the
// binding for the next.
func TestEmailBindingOnDynamoDB(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	tbl := newTable(t, ctx)
	hk := &hookList{}
	svc := &service.Service{Store: tbl.Peer(), Hooks: hk.outbox(tbl.Peer(), service.HookKind)}
	const n = 12
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			if err := svc.Deliver(ctx, &peer.Event{ID: fmt.Sprint("e", i), Type: peer.EventConnectionAdded,
				ConnectionID: fmt.Sprint("c", i), Tag: "email-key", At: time.Now()}); err != nil {
				t.Error(err)
			}
		}(i)
	}
	wg.Wait()
	bound := ""
	for _, e := range hk.all() {
		var d map[string]any
		_ = json.Unmarshal(e.Data, &d)
		if d["email_bound"] == true {
			if bound != "" {
				t.Fatalf("both %s and %s bound", bound, e.ConnectionID)
			}
			bound = e.ConnectionID
		}
	}
	if bound == "" {
		t.Fatal("none bound")
	}
	if b, _, _ := tbl.Peer().Get(ctx, "email", "email-key"); string(b) != bound {
		t.Fatalf("stored %q, bound %q", b, bound)
	}
	if err := svc.Deliver(ctx, &peer.Event{ID: "r", Type: peer.EventConnectionRemoved, ConnectionID: bound, Tag: "email-key",
		Direction: "in", At: time.Now()}); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := tbl.Peer().Get(ctx, "email", "email-key"); ok {
		t.Fatal("binding not freed")
	}
	if err := svc.Deliver(ctx, &peer.Event{ID: "x", Type: peer.EventConnectionAdded, ConnectionID: "next", Tag: "email-key",
		At: time.Now()}); err != nil {
		t.Fatal(err)
	}
	if b, _, _ := tbl.Peer().Get(ctx, "email", "email-key"); string(b) != "next" {
		t.Fatalf("next not bound: %q", b)
	}
}

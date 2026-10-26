package service

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/vettid/service-vault/internal/api"
	"github.com/vettid/service-vault/internal/peer"
	"github.com/vettid/service-vault/internal/signin"
	"github.com/vettid/vettid-vault/vms/peerwire"
)

// The first active connection with an email keeps the binding; a later
// one with the same email is not bound; removing the bound one frees it
// for the next connection made with that email.
func TestEmailBindingFirstKeeps(t *testing.T) {
	f := newFixture(t)
	a, da := f.connect(f.m, "email-key")
	if da["email_bound"] != true {
		t.Fatalf("first: %v", da)
	}
	mb := f.member(20)
	b, db := f.connect(mb, "email-key")
	if db["email_bound"] != false || db["invite_id"] == nil || db["name"] == nil {
		t.Fatalf("second: %v", db)
	}
	// Sign-in goes to the first.
	f.start("email-key", "", "42")
	f.pump()
	if len(f.m.Challenges) != 1 || len(mb.Challenges) != 0 {
		t.Fatalf("challenges %d %d", len(f.m.Challenges), len(mb.Challenges))
	}

	// The unbound one is removed: nothing changes.
	mb.Send(peerwire.TypeConnectionRemoved, peerwire.ConnectionRemovedBody())
	f.pump()
	if got, _, _ := f.svc.Store.Get(context.Background(), kindEmail, "email-key"); string(got) != a {
		t.Fatalf("binding %q, want %q (b %q)", got, a, b)
	}

	// The bound one is removed: the binding is freed, and the next
	// connection with the email binds.
	f.m.Send(peerwire.TypeConnectionRemoved, peerwire.ConnectionRemovedBody())
	f.pump()
	if _, ok, _ := f.svc.Store.Get(context.Background(), kindEmail, "email-key"); ok {
		t.Fatal("binding not freed")
	}
	mc := f.member(30)
	c, dc := f.connect(mc, "email-key")
	if dc["email_bound"] != true {
		t.Fatalf("third: %v", dc)
	}
	f.start("email-key", "", "43")
	f.pump()
	if len(mc.Challenges) != 1 {
		t.Fatal("no challenge to the newly bound connection")
	}
	// A redelivered connection.added reports the same.
	ev := &peer.Event{ID: "e1", Type: peer.EventConnectionAdded, ConnectionID: c, Tag: "email-key", At: f.clk.Now()}
	if err := f.svc.Deliver(context.Background(), ev); err != nil {
		t.Fatal(err)
	}
	added := f.hk.of(peer.EventConnectionAdded)
	if !strings.Contains(string(added[len(added)-1].Data), `"email_bound":true`) {
		t.Fatalf("redelivered %s", added[len(added)-1].Data)
	}
}

// Connections added at once with the same email: exactly one binds.
func TestEmailBindingConcurrent(t *testing.T) {
	f := newFixture(t)
	const n = 32
	var wg sync.WaitGroup
	errs := make(chan error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			errs <- f.svc.Deliver(context.Background(), &peer.Event{ID: fmt.Sprint("e", i), Type: peer.EventConnectionAdded,
				ConnectionID: fmt.Sprint("c", i), Tag: "email-key", At: f.clk.Now()})
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	bound := 0
	for _, e := range f.hk.of(peer.EventConnectionAdded) {
		var d map[string]any
		_ = json.Unmarshal(e.Data, &d)
		if d["email_bound"] == true {
			bound++
			if got, _, _ := f.svc.Store.Get(context.Background(), kindEmail, "email-key"); string(got) != e.ConnectionID {
				t.Fatalf("bound %q, stored %q", e.ConnectionID, got)
			}
		}
	}
	if bound != 1 {
		t.Fatalf("%d connections bound", bound)
	}
}

// One pending sign-in per email: a new one supersedes the pending one,
// whose challenge is cancelled; approving it afterwards does nothing.
func TestSignInSupersedes(t *testing.T) {
	f := newFixture(t)
	f.connect(f.m, "email-key")
	id1 := f.start("email-key", "", "11")
	f.pump()
	id2 := f.start("email-key", "", "22")
	f.pump()
	if s := f.status(id1); s.Status != "expired" {
		t.Fatalf("superseded %+v", s)
	}
	if s := f.status(id2); s.Status != "pending" {
		t.Fatalf("current %+v", s)
	}
	f.sign(f.m, f.m.Challenges[0], f.m.Cred) // the superseded challenge
	if s := f.status(id1); s.Status != "expired" || len(f.hk.of(peer.EventSignInApproved)) != 0 {
		t.Fatalf("superseded approved: %+v", s)
	}
	f.sign(f.m, f.m.Challenges[1], f.m.Cred)
	if s := f.status(id2); s.Status != "approved" {
		t.Fatalf("current %+v", s)
	}
	if ap := f.hk.of(peer.EventSignInApproved); len(ap) != 1 || !strings.Contains(string(ap[0].Data), id2) {
		t.Fatalf("webhooks %+v", ap)
	}
	// An approved sign-in is not superseded.
	f.start("email-key", "", "33")
	if s := f.status(id2); s.Status != "approved" {
		t.Fatalf("approved superseded: %+v", s)
	}

	// The same for an unknown email: superseding reveals nothing.
	u1 := f.start("unknown-key", "", "44")
	f.start("unknown-key", "", "55")
	if s := f.status(u1); s.Status != "expired" {
		t.Fatalf("unknown superseded %+v", s)
	}
}

// An outcome emitted before the sign-in was superseded is dropped.
func TestSupersededOutcomeDropped(t *testing.T) {
	f := newFixture(t)
	f.connect(f.m, "email-key")
	id1 := f.start("email-key", "", "11")
	f.pump()
	b, _, _ := f.svc.Store.Get(context.Background(), kindSignIn, id1)
	var rec signInRecord
	_ = json.Unmarshal(b, &rec)
	f.start("email-key", "", "22")
	ev := &peer.Event{ID: "late", Type: peer.EventSignInApproved, ConnectionID: rec.ConnID, RequestID: rec.RequestID, At: f.clk.Now()}
	if err := f.svc.Deliver(context.Background(), ev); err != nil {
		t.Fatal(err)
	}
	if s := f.status(id1); s.Status != "expired" || len(f.hk.of(peer.EventSignInApproved)) != 0 {
		t.Fatalf("late outcome applied: %+v", s)
	}
}

// Concurrent starts for one email leave exactly one pending.
func TestSignInSupersedeConcurrent(t *testing.T) {
	f := newFixture(t)
	f.connect(f.m, "email-key")
	const n = 6
	ids := make([]string, n)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			id, err := f.svc.StartSignIn(context.Background(), api.SignInRequest{EmailKey: "email-key", MatchCode: "12"})
			if err != nil {
				t.Error(err)
			}
			ids[i] = id
		}(i)
	}
	wg.Wait()
	pending := 0
	for _, id := range ids {
		if f.status(id).Status == "pending" {
			pending++
		}
	}
	if pending != 1 {
		t.Fatalf("%d pending", pending)
	}
}

func TestKeyChanged(t *testing.T) {
	f := newFixture(t)
	f.connect(f.m, "email-key")
	id1 := f.start("email-key", "", "11")
	f.pump()
	f.sign(f.m, f.m.Challenges[0], f.m.Cred)
	id2 := f.start("email-key", "", "22")
	f.pump()
	f.sign(f.m, f.m.Challenges[1], ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))) // not the pinned key
	if s := f.status(id1); s.KeyChanged == nil || *s.KeyChanged {
		t.Fatalf("first %+v", s)
	}
	if s := f.status(id2); s.Status != "approved" || s.KeyChanged == nil || !*s.KeyChanged {
		t.Fatalf("changed %+v", s)
	}
	ap := f.hk.of(peer.EventSignInApproved)
	if len(ap) != 2 || !strings.Contains(string(ap[1].Data), `"key_changed":true`) {
		t.Fatalf("webhooks %+v", ap)
	}
}

func limiter(c signin.Counters) *signin.Limiter {
	return &signin.Limiter{Counters: c, Email: signin.DefaultEmailLimits, Source: signin.DefaultSourceLimits}
}

// Over the per-email limit: the same answer, a fresh id, no challenge;
// the sign-in expires; the next window allows again. Logs carry neither
// the email key nor the source.
func TestSignInEmailLimit(t *testing.T) {
	f := newFixture(t)
	f.svc.Limiter = limiter(&signin.MemCounters{})
	f.connect(f.m, "email-key")
	f.clk.Advance(15 * time.Minute) // a fresh window
	var ids []string
	for i := 0; i < 6; i++ {
		ids = append(ids, f.start("email-key", "source-key", "12"))
		f.pump()
	}
	if len(f.m.Challenges) != 5 {
		t.Fatalf("%d challenges", len(f.m.Challenges))
	}
	if s := f.status(ids[5]); s.Status != "pending" || len(ids[5]) != len(ids[0]) {
		t.Fatalf("limited %+v", s)
	}
	f.clk.Advance(signin.ChallengeTTL)
	if s := f.status(ids[5]); s.Status != "expired" {
		t.Fatalf("limited %+v", s)
	}
	if f.svc.LimitedSignIns() != 1 {
		t.Fatalf("counter %d", f.svc.LimitedSignIns())
	}
	logs := f.logs.String()
	if !strings.Contains(logs, "signin rate limited") || !strings.Contains(logs, "email 5/15m") ||
		strings.Contains(logs, "email-key") || strings.Contains(logs, "source-key") {
		t.Fatalf("logs:\n%s", logs)
	}
	// Another email is not affected.
	f.start("other-key", "", "12")

	// The next 15-minute window allows again, up to 20 a day.
	sent := len(f.m.Challenges)
	for w := 0; w < 4; w++ {
		f.clk.Advance(15 * time.Minute)
		for i := 0; i < 5; i++ {
			f.start("email-key", "", "12")
			f.pump()
		}
	}
	if got := len(f.m.Challenges) - sent; got != 14 { // 20 a day, the limited start counted too
		t.Fatalf("%d challenges after the first window, want 14", got)
	}
}

func TestSignInSourceLimit(t *testing.T) {
	f := newFixture(t)
	f.svc.Limiter = limiter(&signin.MemCounters{})
	f.connect(f.m, "email-key")
	f.clk.Advance(15 * time.Minute)
	for i := 0; i < 20; i++ {
		f.start(fmt.Sprint("k", i), "source-key", "12")
	}
	f.start("email-key", "source-key", "12") // 21st from the source
	f.pump()
	if len(f.m.Challenges) != 0 {
		t.Fatal("challenge over the source limit")
	}
	f.start("email-key", "other-source", "12")
	f.start("email-key", "", "12")
	f.pump()
	if len(f.m.Challenges) != 2 {
		t.Fatalf("%d challenges", len(f.m.Challenges))
	}
	if !strings.Contains(f.logs.String(), "source 20/15m") {
		t.Fatal("no log")
	}
}

type failCounters struct{}

func (failCounters) Incr(context.Context, string, time.Duration, time.Time) (int64, error) {
	return 0, fmt.Errorf("down")
}

func TestSignInCountersDown(t *testing.T) {
	f := newFixture(t)
	f.svc.Limiter = limiter(failCounters{})
	if _, err := f.svc.StartSignIn(context.Background(), api.SignInRequest{EmailKey: "k", MatchCode: "12"}); err == nil {
		t.Fatal("started without counters")
	}
}

// A start over a limit makes its own sign-in, which reads pending and
// then expired, and leaves the email's pending sign-in alone: it is
// still answerable. Starts within the limits still supersede.
func TestOverLimitDoesNotSupersede(t *testing.T) {
	f := newFixture(t)
	f.svc.Limiter = limiter(&signin.MemCounters{})
	f.connect(f.m, "email-key")
	f.clk.Advance(15 * time.Minute) // a fresh window
	var ids []string
	for i := 0; i < 5; i++ {
		ids = append(ids, f.start("email-key", "", "12"))
		f.pump()
	}
	for _, id := range ids[:4] { // within the limits: superseded
		if s := f.status(id); s.Status != "expired" {
			t.Fatalf("within limits, not superseded: %+v", s)
		}
	}
	cur := ids[4]
	over1 := f.start("email-key", "", "13") // over the per-email limit
	over2 := f.start("email-key", "source-key", "14")
	f.pump()
	if len(f.m.Challenges) != 5 {
		t.Fatalf("%d challenges", len(f.m.Challenges))
	}
	for _, id := range []string{cur, over1, over2} {
		if s := f.status(id); s.Status != "pending" || len(id) != len(cur) {
			t.Fatalf("%s: %+v", id, s)
		}
	}
	// The member approves the pending one.
	f.sign(f.m, f.m.Challenges[4], f.m.Cred)
	if s := f.status(cur); s.Status != "approved" {
		t.Fatalf("pending sign-in after over-limit starts: %+v", s)
	}
	if ap := f.hk.of(peer.EventSignInApproved); len(ap) != 1 || !strings.Contains(string(ap[0].Data), cur) {
		t.Fatalf("webhooks %+v", ap)
	}
	f.clk.Advance(signin.ChallengeTTL)
	for _, id := range []string{over1, over2} {
		if s := f.status(id); s.Status != "expired" {
			t.Fatalf("over-limit %+v", s)
		}
	}
}

// Over the per-source limit: the email's pending sign-in is not
// superseded either.
func TestOverSourceLimitDoesNotSupersede(t *testing.T) {
	f := newFixture(t)
	f.svc.Limiter = limiter(&signin.MemCounters{})
	f.connect(f.m, "email-key")
	f.clk.Advance(15 * time.Minute)
	cur := f.start("email-key", "", "12")
	f.pump()
	for i := 0; i < 20; i++ {
		f.start(fmt.Sprint("k", i), "source-key", "12")
	}
	over := f.start("email-key", "source-key", "13") // 21st from the source
	f.pump()
	if s := f.status(cur); s.Status != "pending" {
		t.Fatalf("superseded by an over-limit start: %+v", s)
	}
	f.sign(f.m, f.m.Challenges[0], f.m.Cred)
	if s := f.status(cur); s.Status != "approved" {
		t.Fatalf("%+v", s)
	}
	f.clk.Advance(signin.ChallengeTTL)
	if s := f.status(over); s.Status != "expired" {
		t.Fatalf("over-limit %+v", s)
	}
	// Within the limits again (another source): it supersedes.
	next := f.start("email-key", "other-source", "15")
	f.pump()
	again := f.start("email-key", "other-source", "16")
	f.pump()
	if s := f.status(next); s.Status != "expired" {
		t.Fatalf("within limits, not superseded: %+v", s)
	}
	if s := f.status(again); s.Status != "pending" {
		t.Fatalf("%+v", s)
	}
}

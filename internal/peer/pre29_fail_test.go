package peer

import (
	"context"
	"errors"
	"log/slog"
	"testing"

	"github.com/vettid/service-vault/internal/peer/peertest"
)

// failNth splits every Apply into transactions of 3 changes, as the
// DynamoDB store splits them into transactions of 100, and fails the at-th
// transaction (counting from 1): the ones before it stay written.
type failNth struct {
	*MemStore
	n, at int
}

func (s *failNth) Apply(ctx context.Context, ch []Change) error {
	for len(ch) > 0 {
		k := min(3, len(ch))
		s.n++
		if s.n == s.at {
			return errors.New("injected: a transaction failed")
		}
		if err := s.MemStore.Apply(ctx, ch[:k]); err != nil {
			return err
		}
		ch = ch[k:]
	}
	return nil
}

// A start that fails partway through ending connections never leaves a
// connection record deleted with its tokens still valid: each connection
// is ended in two writes, the record's deletion last, so the next start
// ends what is left, and in the end every token issued for the ended
// connections is denied.
func TestPre29EndSurvivesAFailedWrite(t *testing.T) {
	for _, endAll := range []bool{false, true} {
		for at := 1; at <= 12; at++ {
			testEndSurvives(t, endAll, at)
		}
	}
}

// testEndSurvives: the pre29 sweep, or with endAll the one-shot setting
// (whose run is recorded only once every connection is ended).
func testEndSurvives(t *testing.T, endAll bool, at int) {
	{
		f := newFixture(t)
		a := f.connect(f.member(10), "")
		b := f.connect(f.member(20), "")
		date := ""
		if endAll {
			date = "2026-11-13"
			f.endAll = date
		} else {
			f.storedRelease(a, 0)
			f.storedRelease(b, 0)
		}
		fs := &failNth{MemStore: f.store, at: at}
		p, err := New(Config{Log: slog.New(slog.NewTextHandler(&f.logs, nil)), Keys: f.keys, Relay: testRelay{f.sv, f},
			RelayURL: peertest.RelayURL, Store: fs, Events: f.ev, Now: f.clk.Now, EndAllConnections: date,
			Profile: Profile{FirstName: "VettID", LastName: "Member Service"}})
		if err != nil {
			t.Fatal(err)
		}
		if err := p.Start(context.Background()); err == nil && fs.n < at {
			return // fewer transactions than at: nothing failed
		}
		// Every connection record still stored has its tokens: none was
		// deleted ahead of its tokens' denial.
		for _, id := range []string{a, b} {
			if _, ok, _ := f.store.Get(context.Background(), kindConn, id); ok {
				continue
			}
			for _, tok := range p.issued {
				if tok.ConnID == id && !tok.Denied && tok.Kind != tokOpen {
					if _, stored, _ := f.store.Get(context.Background(), kindToken, tok.JTI); stored {
						b, _, _ := f.store.Get(context.Background(), kindToken, tok.JTI)
						t.Fatalf("at %d: connection %s deleted, token %s not denied in the store: %s", at, id, tok.JTI, b)
					}
				}
			}
		}
		f.start() // a clean start ends the rest
		for _, id := range []string{a, b} {
			if _, ok := f.p.conns[id]; ok {
				t.Fatalf("at %d: connection %s not ended", at, id)
			}
		}
		for _, tok := range f.p.issued {
			if (tok.ConnID == a || tok.ConnID == b) && tok.Kind != tokOpen && !tok.Denied {
				t.Fatalf("at %d: token %s of an ended connection not denied", at, tok.JTI)
			}
		}
	}
}

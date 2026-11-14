package ballot

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/vettid/service-vault/internal/peer"
)

// countingSender is a fakeSender that counts each send's messages as the
// peer does: a message to a connection in queue waits in the outbox, one
// in drop ended there undelivered, any other was deposited.
type countingSender struct {
	*fakeSender
	mu    sync.Mutex
	refs  map[string][]string // ref -> the connections sent to
	queue map[string]bool
	drop  map[string]bool
}

func (s *countingSender) SendMessageRef(ctx context.Context, conn, typ string, body json.RawMessage, notAfter time.Time, ref string) (string, error) {
	id, err := s.SendMessage(ctx, conn, typ, body, notAfter)
	if err == nil {
		s.mu.Lock()
		s.refs[ref] = append(s.refs[ref], conn)
		s.mu.Unlock()
	}
	return id, err
}

func (s *countingSender) SendCounts(prefix string) []peer.SendCounts {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []peer.SendCounts
	for ref, conns := range s.refs {
		if !strings.HasPrefix(ref, prefix) {
			continue
		}
		c := peer.SendCounts{Ref: ref}
		for _, conn := range conns {
			switch {
			case s.queue[conn]:
				c.Queued++
			case s.drop[conn]:
				c.Dropped++
			default:
				c.Sent++
			}
		}
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Ref < out[j].Ref })
	return out
}

// A send's log line and the proposal's status split its messages into
// deposited, queued and dropped: accepted is not sent.
func TestSendCountsSplit(t *testing.T) {
	ctx := context.Background()
	m, s, _ := newManager(t)
	cs := &countingSender{fakeSender: s, refs: map[string][]string{}, queue: map[string]bool{"c1": true}, drop: map[string]bool{"c2": true}}
	m.Sender = cs
	logs := &bytes.Buffer{}
	m.Log = slog.New(slog.NewTextHandler(logs, nil))
	c, err := m.Create(ctx, "apv", input())
	if err != nil {
		t.Fatal(err)
	}
	m.Wait()
	if c.Sending != 3 {
		t.Fatalf("sending %d", c.Sending)
	}
	line := ""
	for _, l := range strings.Split(logs.String(), "\n") {
		if strings.Contains(l, TypeProposal+" send ended") {
			line = l
		}
	}
	for _, want := range []string{"accepted=3", "deposited=1", "queued=1", "dropped=1"} {
		if !strings.Contains(line, want) {
			t.Fatalf("log line %q lacks %s", line, want)
		}
	}
	st, err := m.Status(ctx, c.ProposalID)
	if err != nil {
		t.Fatal(err)
	}
	if got := fmt.Sprint(st.Sends); got != "[{proposal 1 1 1}]" {
		t.Fatalf("sends %s", got)
	}
	// Named from the ref: an extension's number is kept, the id dropped.
	cs.refs[sendRef(c.ProposalID, "extended/"+c.ProposalID+"/2")] = []string{"c0"}
	cs.refs[sendRef(c.ProposalID, "closed/"+c.ProposalID)] = []string{"c0", "c1"}
	cs.refs[sendRef("other", "closed/other")] = []string{"c0"}
	if got := fmt.Sprint(m.sendStatus(c.ProposalID)); got != "[{closed 1 1 0} {extended/2 1 0 0} {proposal 1 1 1}]" {
		t.Fatalf("sends %s", got)
	}
	// A Sender that doesn't count: no sends in the status.
	m.Sender = s
	if st, err := m.Status(ctx, c.ProposalID); err != nil || st.Sends != nil {
		t.Fatalf("%+v %v", st, err)
	}
}

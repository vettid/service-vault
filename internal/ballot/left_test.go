package ballot

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"

	"github.com/vettid/service-vault/internal/peer"
	"github.com/vettid/service-vault/vote"
)

// leftRoster reports fixed leaves.
type leftRoster struct {
	fakeRoster
	left map[string]peer.Leave
}

func (r leftRoster) Left(ids []string) map[string]peer.Leave {
	out := map[string]peer.Leave{}
	for _, id := range ids {
		if l, ok := r.left[id]; ok {
			out[id] = l
		}
	}
	return out
}

// counts.removed counts the members who left in [record_at, closes_at in
// force), by their recorded times, and a member with no record of its
// leave, with an alarm (BALLOT-PROTOCOL 0.14.2 §7).
func TestRemovedFromLeaveTimes(t *testing.T) {
	const recordAt, closesAt = 1793500000, 1793520000 + 3*86400
	ms := func(s int64) uint64 { return uint64(s) * 1000 }
	known := func(at uint64) peer.Leave { return peer.Leave{AtMS: at, Kind: peer.LeftRemovedOut, Known: true} }
	r := leftRoster{left: map[string]peer.Leave{
		"before":   known(ms(recordAt) - 5000), // counts as at record_at
		"during":   known(ms(recordAt) + 1),
		"lastms":   known(ms(closesAt) - 1),
		"at-close": known(ms(closesAt)), // not before the close in force
		"after":    known(ms(closesAt) + 60000),
		"unknown":  {},
		"susp":     {AtMS: ms(recordAt) + 10, Kind: peer.LeftSuspended, Known: true},
	}}
	var logs bytes.Buffer
	m := &Manager{Roster: r, Log: slog.New(slog.NewTextHandler(&logs, nil))}
	o := &OpenProposal{ClosesAt: closesAt, Members: map[string]Member{}}
	for _, id := range []string{"before", "during", "lastms", "at-close", "after", "unknown", "susp", "active", "stale"} {
		o.Members[id] = Member{}
	}
	p := &vote.Proposal{ProposalID: "01JBQZ0000000000000000000A", RecordAt: recordAt}
	// before, during, lastms, unknown, susp.
	if n := m.removed(o, p); n != 5 {
		t.Fatalf("removed %d, want 5", n)
	}
	if !strings.Contains(logs.String(), "alarm=removed_unknown") || !strings.Contains(logs.String(), "members=1") {
		t.Fatalf("no alarm for the unknown leave: %s", logs.String())
	}
	// An extension moves the close in force.
	o.ClosesAt = closesAt + 3600
	if n := m.removed(o, p); n != 7 { // at-close and after are now inside
		t.Fatalf("removed %d after an extension, want 7", n)
	}
}

package ballot

import (
	"context"
	"encoding/json"
	"sort"
	"sync"
	"time"
)

// Member sends (BALLOT-PROTOCOL §4.1): vote.proposal, vote.extended and
// vote.closed go to every eligible member in the background, so that a
// request that makes, extends or closes a vote answers at once. At 15,000
// members, sending in series takes longer than a request may (#6946).
//
// A proposal's sends run one message at a time, in the order they were
// started (so no member is sent vote.extended before vote.proposal), each
// to its members in connection order; different proposals' sends run side
// by side. The peer serialises sends anyway, so sending one message to
// several members at once would buy nothing. A member a send misses
// still learns of it: of a proposal, from the site's index, asking with
// vote.status (§10.1, §4.2); of an extension, from the index (§10.2); of
// the close, at its fixed time (§8.3).

// SendTimeout bounds one member's send once the peer takes it (the wait
// for the peer's lock is not bounded by it).
const SendTimeout = 30 * time.Second

// sendJob is one message to send to a proposal's members.
type sendJob struct {
	key, typ string
	conns    []string
	body     func(conn string) (json.RawMessage, error)
}

// sends tracks the background senders: each proposal's queue, while its
// sender runs, and the keys queued or running.
type sends struct {
	mu     sync.Mutex
	queues map[string][]*sendJob
	keys   map[string]bool
	wg     sync.WaitGroup
}

// sortedConns is the connections of a proposal's members, in order.
func sortedConns(members map[string]Member) []string {
	conns := make([]string, 0, len(members))
	for c := range members {
		conns = append(conns, c)
	}
	sort.Strings(conns)
	return conns
}

// sendInBackground queues typ to each of conns, with the body body gives
// for it, behind the proposal's earlier sends, under the Manager's
// Background context. A send already queued or running under key isn't
// queued again: it returns false. Each body is built as it is sent, so
// the bodies aren't all held at once.
func (m *Manager) sendInBackground(proposalID, key, typ string, conns []string, body func(conn string) (json.RawMessage, error)) bool {
	m.sends.mu.Lock()
	defer m.sends.mu.Unlock()
	if m.sends.queues == nil {
		m.sends.queues, m.sends.keys = map[string][]*sendJob{}, map[string]bool{}
	}
	if m.sends.keys[key] {
		m.log().Info(typ+" already being sent", "send", key)
		return false
	}
	m.sends.keys[key] = true
	q, running := m.sends.queues[proposalID]
	m.sends.queues[proposalID] = append(q, &sendJob{key: key, typ: typ, conns: conns, body: body})
	if !running {
		m.sends.wg.Add(1)
		go m.runSends(proposalID)
	}
	return true
}

// runSends sends a proposal's queued jobs, in order, until none is left.
func (m *Manager) runSends(proposalID string) {
	defer m.sends.wg.Done()
	for {
		m.sends.mu.Lock()
		q := m.sends.queues[proposalID]
		if len(q) == 0 {
			delete(m.sends.queues, proposalID)
			m.sends.mu.Unlock()
			return
		}
		job := q[0]
		m.sends.queues[proposalID] = q[1:]
		m.sends.mu.Unlock()
		m.runJob(job)
		m.sends.mu.Lock()
		delete(m.sends.keys, job.key)
		m.sends.mu.Unlock()
	}
}

func (m *Manager) runJob(job *sendJob) {
	ctx := m.Background
	if ctx == nil {
		ctx = context.Background()
	}
	sent, failed, bodyErrs := 0, 0, 0
	for _, c := range job.conns {
		// Checked before each send: the peer queues a message before it
		// looks at the context.
		if ctx.Err() != nil {
			break
		}
		b, err := job.body(c)
		if err != nil {
			if bodyErrs == 0 {
				m.log().Error(job.typ+" not sent: its body", "send", job.key, "connection_id", c, "err", err.Error())
			}
			bodyErrs++
			continue
		}
		sctx, cancel := context.WithTimeout(ctx, SendTimeout)
		_, err = m.Sender.SendMessage(sctx, c, job.typ, b)
		cancel()
		if err != nil {
			// A send that timed out may still be in the peer's outbox, and go
			// out later.
			m.log().Warn(job.typ+" not sent", "send", job.key, "connection_id", c, "err", err.Error())
			failed++
			continue
		}
		sent++
	}
	m.log().Info(job.typ+" sent", "send", job.key, "sent", sent, "failed", failed, "body_errors", bodyErrs,
		"of", len(job.conns), "stopped", ctx.Err() != nil)
}

// Wait waits for every background send to end (tests, and the daemon's
// shutdown).
func (m *Manager) Wait() { m.sends.wg.Wait() }

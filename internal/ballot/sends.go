package ballot

import (
	"context"
	"encoding/json"
	"errors"
	"sort"
	"sync"
	"time"

	"github.com/vettid/service-vault/internal/peer"
	"github.com/vettid/service-vault/vote"
)

// Member sends (BALLOT-PROTOCOL §4.1): vote.proposal, vote.extended and
// vote.closed go to every eligible member in the background, so that a
// request that makes, extends or closes a vote answers at once. At 15,000
// members, sending in series takes longer than a request may (#6946).
//
// A proposal's sends run one message at a time, in the order they were
// started, each to its members in connection order; different proposals'
// sends run side by side. The order is the order sent, not delivered: no
// member is sent vote.extended before vote.proposal, but a vote.proposal
// that failed and is sent again later (a /publish) can reach a member
// after the vote.extended sent meanwhile. The peer serialises sends anyway, so sending one message to
// several members at once would buy nothing. A member a send misses
// still learns of it: of a proposal, from the site's index, asking with
// vote.status (§10.1, §4.2); of an extension, from the index (§10.2); of
// the close, at its fixed time (§8.3).

// SendTimeout bounds one member's send once the peer takes it. The wait
// for the peer's lock is not bounded by it: a relay that hangs holds the
// lock for up to SendTimeout a send, so a request that needs the peer
// meanwhile (a close collecting) can run past the API's 30 s and answer
// retry.
const SendTimeout = 30 * time.Second

// A queued vote.proposal or vote.extended is worth delivering until the
// close in force plus the most the extensions may add (BALLOT-PROTOCOL
// §10.2: 24 h in all); a vote.closed for ClosedSendLife. The peer drops a
// deposit not made by then, so it no longer counts toward its bound.
const (
	extensionsMax  = vote.MaxExtension * time.Second
	ClosedSendLife = 7 * 24 * time.Hour
)

func voteSendUntil(closesAt int64) time.Time {
	return time.Unix(closesAt, 0).Add(extensionsMax)
}

// MaxFailuresInARow stops a job after that many sends in a row have
// failed for a reason that isn't the member's own: the relay hanging (the
// drain runs out SendTimeout) or the store failing, while the job holds
// the peer, its proposal's later sends and its key (a retry). A relay that
// refuses at once doesn't fail a send: the message is queued and saved,
// and goes out later, until the outbox is full (peer.ErrOutboxFull, which
// counts). A connection gone (peer.ErrNotFound), a member's outbox full,
// or a member whose deposits wait for its next token (both peer.ErrBusy)
// is about that member only: it fails that send without counting. The
// members not sent learn of it as above.
const MaxFailuresInARow = 20

// memberOnly reports whether err is about one member, not the relay.
func memberOnly(err error) bool {
	return errors.Is(err, peer.ErrNotFound) || errors.Is(err, peer.ErrBusy)
}

// sendJob is one message to send to a proposal's members.
type sendJob struct {
	key, typ string
	ref      string // its messages' count at the peer (sendRef)
	conns    []string
	notAfter time.Time
	body     func(conn string) (json.RawMessage, error)
}

// sends tracks the background senders: each proposal's queue, while its
// sender runs, and the keys queued or running.
type sends struct {
	mu     sync.Mutex
	queues map[string][]*sendJob
	keys   map[string]bool
	closed bool // StopSends: nothing more is queued
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
// queued again, nor is anything once StopSends was called: it returns
// false, and the caller answers that nothing is being sent. Each body is
// built as it is sent, so the bodies aren't all held at once.
func (m *Manager) sendInBackground(proposalID, key, typ string, conns []string, notAfter time.Time, body func(conn string) (json.RawMessage, error)) bool {
	m.sends.mu.Lock()
	defer m.sends.mu.Unlock()
	if m.sends.queues == nil {
		m.sends.queues, m.sends.keys = map[string][]*sendJob{}, map[string]bool{}
	}
	if m.sends.closed {
		m.log().Warn(typ+" not queued: the service is stopping", "send", key)
		return false
	}
	if m.sends.keys[key] {
		m.log().Info(typ+" already being sent", "send", key)
		return false
	}
	m.sends.keys[key] = true
	q, running := m.sends.queues[proposalID]
	m.sends.queues[proposalID] = append(q, &sendJob{key: key, typ: typ, ref: sendRef(proposalID, key), conns: conns, notAfter: notAfter, body: body})
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
	accepted, failed, bodyErrs, inARow := 0, 0, 0, 0
	gaveUp := false
	sc, counted := m.Sender.(SendCounter)
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
		if counted {
			_, err = sc.SendMessageRef(sctx, c, job.typ, b, job.notAfter, job.ref)
		} else {
			_, err = m.Sender.SendMessage(sctx, c, job.typ, b, job.notAfter)
		}
		cancel()
		if err != nil {
			// A send that timed out may still be in the peer's outbox, and go
			// out later. The first failure is logged; the rest are counted.
			if failed == 0 {
				m.log().Warn(job.typ+" not sent", "send", job.key, "connection_id", c, "err", err.Error())
			}
			failed++
			if memberOnly(err) {
				continue
			}
			if inARow++; inARow >= MaxFailuresInARow {
				gaveUp = true
				m.log().Warn(job.typ+" stopped: sends failed in a row; members not sent learn of it as BALLOT-PROTOCOL §4.2, §8.3 and §10 say",
					"send", job.key, "in_a_row", inARow)
				break
			}
			continue
		}
		inARow = 0
		accepted++
	}
	// Accepted is not sent: the split says how many members it has reached
	// so far (deposited), how many wait in the outbox (queued: their
	// connection is mid-reconnect, say) and how many ended there
	// undelivered. They count this send's messages so far, earlier runs of
	// the same send included; the proposal's status follows them later.
	args := []any{"send", job.key, "accepted", accepted, "failed", failed, "body_errors", bodyErrs,
		"of", len(job.conns), "stopped", ctx.Err() != nil, "gave_up", gaveUp}
	if counted {
		var n peer.SendCounts
		for _, c := range sc.SendCounts(job.ref) {
			if c.Ref == job.ref { // not extended/<id>/10 for extended/<id>/1
				n = c
			}
		}
		args = append(args, "deposited", n.Sent, "queued", n.Queued, "dropped", n.Dropped)
	}
	m.log().Info(job.typ+" send ended", args...)
}

// Wait waits for every background send to end (tests, and the daemon's
// shutdown, after StopSends).
func (m *Manager) Wait() { m.sends.wg.Wait() }

// StopSends queues nothing more (a send asked for after it is logged and
// dropped), so that Wait can't race a new sender at shutdown.
func (m *Manager) StopSends() {
	m.sends.mu.Lock()
	m.sends.closed = true
	m.sends.mu.Unlock()
}

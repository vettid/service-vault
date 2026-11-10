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
// One sender runs per message at a time, in connection order; the peer
// serialises sends anyway, so running them in parallel would buy nothing.
// A member a send misses asks with vote.status (§4.2), or checks at its
// fixed time (§8.3), as before.

// SendTimeout bounds one member's send.
const SendTimeout = 30 * time.Second

// sends tracks the background senders running.
type sends struct {
	mu      sync.Mutex
	running map[string]bool
	wg      sync.WaitGroup
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

// sendInBackground sends typ to each of conns, with the body body gives
// for it, in the background, under the Manager's Background context. A
// sender already running for key isn't started again: it returns false.
// Each body is built as it is sent, so the bodies aren't all held at once.
func (m *Manager) sendInBackground(key, typ string, conns []string, body func(conn string) (json.RawMessage, error)) bool {
	m.sends.mu.Lock()
	if m.sends.running == nil {
		m.sends.running = map[string]bool{}
	}
	if m.sends.running[key] {
		m.sends.mu.Unlock()
		return false
	}
	m.sends.running[key] = true
	m.sends.wg.Add(1)
	m.sends.mu.Unlock()
	ctx := m.Background
	if ctx == nil {
		ctx = context.Background()
	}
	go func() {
		defer func() {
			m.sends.mu.Lock()
			delete(m.sends.running, key)
			m.sends.mu.Unlock()
			m.sends.wg.Done()
		}()
		sent := 0
		for _, c := range conns {
			if ctx.Err() != nil {
				break
			}
			b, err := body(c)
			if err != nil {
				m.log().Error(typ+" not sent: its body", "send", key, "connection_id", c, "err", err.Error())
				continue
			}
			sctx, cancel := context.WithTimeout(ctx, SendTimeout)
			_, err = m.Sender.SendMessage(sctx, c, typ, b)
			cancel()
			if err != nil {
				m.log().Warn(typ+" not sent", "send", key, "connection_id", c, "err", err.Error())
				continue
			}
			sent++
		}
		m.log().Info(typ+" sent", "send", key, "sent", sent, "of", len(conns), "stopped", ctx.Err() != nil)
	}()
	return true
}

// Wait waits for every background send to end (tests, and a shutdown
// that wants them done).
func (m *Manager) Wait() { m.sends.wg.Wait() }

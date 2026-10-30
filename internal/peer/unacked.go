package peer

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// The messages left unacked, and those the peer stopped waiting for, are
// stored (kind "unacked", by msg_id), so that a restart or another
// process neither starts a message's wait again nor forgets it in
// counts.unhandled (BALLOT-PROTOCOL §7). A record holds times only: the
// message's relay time, when it was first left, and whether the count
// went ahead without it. It is written the first time a message is left
// (the first writer's time stands), deleted in the same write as the
// message's handling, and expires when gaveUpUntil passes.

// unackedRec is the stored form.
type unackedRec struct {
	MS     uint64 `json:"ms"`
	First  int64  `json:"first"` // Unix ms
	GaveUp bool   `json:"gave_up,omitempty"`
}

// loadUnacked replaces the in-memory sets with the stored ones, keeping
// what this process left and hasn't stored yet.
func (p *Peer) loadUnacked(ctx context.Context) error {
	recs, err := p.cfg.Store.Load(ctx, kindUnacked)
	if err != nil {
		return err
	}
	unacked, gaveUp := map[string]unacked{}, map[string]unacked{}
	for _, r := range recs {
		var rec unackedRec
		if err := json.Unmarshal(r.Data, &rec); err != nil {
			return fmt.Errorf("peer: unacked record: %w", err)
		}
		u := p.unackedEntry(rec.MS, time.UnixMilli(rec.First))
		u.version = r.Version
		if rec.GaveUp {
			u.exp = gaveUpUntil(u)
			gaveUp[r.ID] = u
		} else {
			unacked[r.ID] = u
		}
	}
	for id := range p.unackedNew {
		_, storedA := unacked[id]
		_, storedG := gaveUp[id]
		switch {
		case storedG:
			delete(p.unackedNew, id)
		case storedA:
			// Stored by another process first: its time stands.
		default:
			if u, ok := p.unacked[id]; ok {
				unacked[id] = u
			} else if u, ok := p.gaveUp[id]; ok {
				gaveUp[id] = u // given up on before it was stored
			}
		}
	}
	p.unacked, p.gaveUp = unacked, gaveUp
	return nil
}

// writeUnacked stores the messages this process left unacked since the
// last call, given up on already if the count went ahead without one
// before it was stored. One another process stored first keeps that
// one's time. A failed write is retried at the next call; until then a
// restart would start that message's wait again.
func (p *Peer) writeUnacked(ctx context.Context) {
	for id := range p.unackedNew {
		u, ok := p.unacked[id]
		g, gave := p.gaveUp[id]
		if gave {
			u, ok = g, true
		}
		if !ok {
			delete(p.unackedNew, id) // handled
			continue
		}
		data, _ := json.Marshal(unackedRec{MS: u.ms, First: u.first.UnixMilli(), GaveUp: gave})
		err := p.cfg.Store.Apply(ctx, []Change{{Kind: kindUnacked, ID: id, Data: data, Expires: gaveUpUntil(u), IfAbsent: true}})
		if err != nil && !errors.Is(err, ErrConflict) {
			p.log().Warn("a message left unacked not stored", "msg_id", id, "err", err.Error())
			continue
		}
		delete(p.unackedNew, id)
	}
}

// storeGaveUp records that the count no longer waits for a message. A
// record gone or changed meanwhile (handled, or another process gave up
// first) is left as it is.
func (p *Peer) storeGaveUp(ctx context.Context, id string, u unacked) error {
	if u.version == 0 {
		return nil // not stored yet: writeUnacked stores it given up on
	}
	data, _ := json.Marshal(unackedRec{MS: u.ms, First: u.first.UnixMilli(), GaveUp: true})
	err := p.cfg.Store.Apply(ctx, []Change{{Kind: kindUnacked, ID: id, Data: data, Expires: gaveUpUntil(u), IfVersion: u.version}})
	if errors.Is(err, ErrConflict) {
		return nil
	}
	return err
}

// handledUnacked deletes a message's record in the write of its
// handling, if this process knows of one.
func (p *Peer) handledUnacked(id string) {
	_, a := p.unacked[id]
	_, g := p.gaveUp[id]
	if !a && !g {
		return
	}
	for _, c := range p.extra {
		if c.Kind == kindUnacked && c.ID == id {
			return // a redelivery before a flush: one change per item
		}
	}
	p.extra = append(p.extra, Change{Kind: kindUnacked, ID: id})
}

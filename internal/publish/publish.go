// Package publish puts a vote's documents on votes.vettid.org
// (BALLOT-PROTOCOL §3.3; vettid/votes docs/VOTES-SITE.md §4): each is
// anchored in Rekor under the service's anchor key, then uploaded with its
// signature and bundle. It is the ballot manager's Publisher.
package publish

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/vettid/service-vault/anchor"
	"github.com/vettid/service-vault/internal/ballot"
	"github.com/vettid/service-vault/internal/peer"
)

// KindBundle is a document's Sigstore bundle in the record store, by the
// document's SHA-256 (hex).
const KindBundle = "vote_bundle"

// KindStampWait is what an early results timestamp taught, by the
// results' SHA-256 (hex): the timestamp authority's time and this
// service's at that stamp, and the anchor signatures dropped.
const KindStampWait = "vote_stamp_wait"

// Kinds are the record kinds the publisher keeps (sealed and resealed
// with the rest, cmd/service-vault recordKinds).
func Kinds() []string { return []string{KindBundle, KindStampWait} }

// maxDroppedSigs is how many dropped anchor signatures are remembered.
const maxDroppedSigs = 16

// Anchorer anchors a document and returns its Sigstore bundle.
type Anchorer interface {
	Anchor(ctx context.Context, doc []byte) (json.RawMessage, error)
}

// Publisher uploads to one site.
type Publisher struct {
	// URL is the site's base, https://votes.vettid.org.
	URL    string
	Anchor Anchorer
	Client *http.Client
	// Records keeps each bundle before its upload. The site takes a
	// document once, with its bundle (§4 "Write-once"), so a retry after
	// a restart must send the same bundle, not a new anchor. Nil: kept in
	// memory only (tests).
	Records peer.Store

	// Timestamp returns the verified RFC 3161 time (Unix seconds) of a
	// bundle anchored for doc (anchor.TimestampTime). Results are uploaded
	// only once it is at or after their close (BALLOT-PROTOCOL §8.3 step
	// 2); nil publishes no results (fail closed).
	Timestamp func(bundle json.RawMessage, doc []byte) (int64, error)

	// Log is where the publisher logs; nil is slog's default.
	Log *slog.Logger
	// Now is the clock; nil is time.Now.
	Now func() time.Time
	// AuthorityTime asks the timestamp authority for the time, verified
	// (anchor.AuthorityTime): after an early results stamp it decides when
	// to anchor again (no log entry). Nil: an estimate from the early stamp.
	AuthorityTime func(ctx context.Context) (int64, error)

	mu      sync.Mutex
	bundles map[[32]byte]json.RawMessage // anchored this run, by document
	waits   map[[32]byte]*stampWait      // without Records (tests)
}

var (
	_ ballot.Publisher          = (*Publisher)(nil)
	_ ballot.ExtensionPublisher = (*Publisher)(nil)
	_ ballot.ResultsPublisher   = (*Publisher)(nil)
	_ ballot.BundleSource       = (*Publisher)(nil)
	_ Anchorer                  = (*anchor.Anchorer)(nil)
)

// ErrRefused is the site refusing a document: a code it gave, which no
// retry changes.
type ErrRefused = ballot.ErrPublishRefused

// PublishProposal implements ballot.Publisher.
func (p *Publisher) PublishProposal(ctx context.Context, id string, doc, sig []byte) (json.RawMessage, error) {
	rc, err := p.publish(ctx, id, "proposal", doc, sig, nil, 0)
	return rc.Bundle, err
}

// PublishExtension implements ballot.ExtensionPublisher.
func (p *Publisher) PublishExtension(ctx context.Context, id string, n int64, doc, sig []byte) (ballot.Receipt, error) {
	return p.publish(ctx, id, "extension-"+strconv.FormatInt(n, 10), doc, sig, nil, 0)
}

// PublishResults implements ballot.ResultsPublisher. Results are always
// checked: notBefore must be the close in force.
func (p *Publisher) PublishResults(ctx context.Context, id string, results, sig, rows []byte, notBefore int64) (ballot.Receipt, error) {
	if notBefore <= 0 {
		return ballot.Receipt{}, errors.New("publish: results without the close they must be stamped at or after")
	}
	return p.publish(ctx, id, "results", results, sig, rows, notBefore)
}

// RepublishResults implements ballot.ResultsPublisher: the identical
// upload again of results the site holds (its index stale), with the
// bundle uploaded first. It is checked again; one that is early or
// doesn't verify is kept, never dropped (the site holds it), with its
// alarm, and not uploaded.
func (p *Publisher) RepublishResults(ctx context.Context, id string, results, sig, rows []byte, bundle json.RawMessage, notBefore int64) (ballot.Receipt, error) {
	if notBefore <= 0 || p.Timestamp == nil {
		return ballot.Receipt{}, errors.New("publish: results again without their timestamp check")
	}
	t, err := p.Timestamp(bundle, results)
	if err != nil {
		p.log().Error("the published results' bundle doesn't verify", "alarm", "results_bundle_unverified", "proposal_id", id, "err", err.Error())
		return ballot.Receipt{}, fmt.Errorf("publish: the results' timestamp: %w", err)
	}
	if t < notBefore {
		p.log().Error("the published results were timestamped before the close", "alarm", "results_stamped_early", "proposal_id", id, "timestamp", t, "closes_at", notBefore)
		return ballot.Receipt{}, ballot.ErrStampedEarly
	}
	return p.upload(ctx, id, "results", results, sig, rows, bundle)
}

func (p *Publisher) now() time.Time {
	if p.Now != nil {
		return p.Now()
	}
	return time.Now()
}

func (p *Publisher) log() *slog.Logger {
	if p.Log != nil {
		return p.Log
	}
	return slog.Default()
}

// StoredBundle implements ballot.BundleSource: the bundle kept for doc,
// in memory or in Records, or nil. It never anchors.
func (p *Publisher) StoredBundle(ctx context.Context, doc []byte) (json.RawMessage, error) {
	key := sha256.Sum256(doc)
	p.mu.Lock()
	b := p.bundles[key]
	p.mu.Unlock()
	if b != nil || p.Records == nil {
		return b, nil
	}
	data, ok, err := p.Records.Get(ctx, KindBundle, hex.EncodeToString(key[:]))
	if err != nil || !ok {
		return nil, err
	}
	return data, nil
}

// bundle returns doc's bundle: the one kept, or a new anchor, kept
// before it is returned.
func (p *Publisher) bundle(ctx context.Context, doc []byte) (json.RawMessage, error) {
	b, _, err := p.bundleNew(ctx, doc)
	return b, err
}

// bundleNew is bundle, and reports whether the bundle was anchored by
// this call (not one kept before).
func (p *Publisher) bundleNew(ctx context.Context, doc []byte) (json.RawMessage, bool, error) {
	key := sha256.Sum256(doc)
	p.mu.Lock()
	b := p.bundles[key]
	p.mu.Unlock()
	if b != nil {
		return b, false, nil
	}
	id := hex.EncodeToString(key[:])
	if p.Records != nil {
		data, ok, err := p.Records.Get(ctx, KindBundle, id)
		if err != nil {
			return nil, false, err
		}
		if ok {
			b = data
		}
	}
	anchored := false
	if b == nil {
		var err error
		if b, err = p.Anchor.Anchor(ctx, doc); err != nil {
			return nil, false, err
		}
		anchored = true
		if p.Records != nil {
			err := p.Records.Apply(ctx, []peer.Change{{Kind: KindBundle, ID: id, Data: b, IfAbsent: true}})
			if errors.Is(err, peer.ErrConflict) {
				// Kept meanwhile: that one. (Should it vanish before the
				// re-read, this anchors again; the caller still checks the
				// dropped signatures and the timestamp of whatever it gets.)
				return p.bundleNew(ctx, doc)
			}
			if err != nil {
				return nil, false, err
			}
		}
	}
	p.mu.Lock()
	if p.bundles == nil {
		p.bundles = map[[32]byte]json.RawMessage{}
	}
	p.bundles[key] = b
	p.mu.Unlock()
	return b, anchored, nil
}

// forget drops doc's kept bundle b, in memory and in Records, so that
// the next bundle call anchors doc again. Only b is dropped: a bundle
// another process kept meanwhile stays.
func (p *Publisher) forget(ctx context.Context, doc []byte, b json.RawMessage) error {
	key := sha256.Sum256(doc)
	p.mu.Lock()
	if bytes.Equal(p.bundles[key], b) {
		delete(p.bundles, key)
	}
	p.mu.Unlock()
	if p.Records == nil {
		return nil
	}
	id := hex.EncodeToString(key[:])
	rg, ok := p.Records.(peer.RecordGetter)
	if !ok {
		return errors.New("publish: the record store can't drop a bundle conditionally")
	}
	r, ok, err := rg.GetRecord(ctx, KindBundle, id)
	if err != nil || !ok || !bytes.Equal(r.Data, b) {
		return err
	}
	err = p.Records.Apply(ctx, []peer.Change{{Kind: KindBundle, ID: id, IfVersion: r.Version}})
	if errors.Is(err, peer.ErrConflict) {
		return nil // replaced meanwhile: not ours to drop
	}
	return err
}

// stampWait is a KindStampWait record.
type stampWait struct {
	TSA     int64    `json:"tsa"`  // the early stamp's time
	Seen    int64    `json:"seen"` // this service's clock then
	Dropped [][]byte `json:"dropped,omitempty"`
}

func (p *Publisher) loadWait(ctx context.Context, doc []byte) (*stampWait, error) {
	if p.Records == nil {
		p.mu.Lock()
		defer p.mu.Unlock()
		if w := p.waits[sha256.Sum256(doc)]; w != nil {
			c := *w
			return &c, nil
		}
		return nil, nil
	}
	key := sha256.Sum256(doc)
	data, ok, err := p.Records.Get(ctx, KindStampWait, hex.EncodeToString(key[:]))
	if err != nil || !ok {
		return nil, err
	}
	var w stampWait
	if err := json.Unmarshal(data, &w); err != nil {
		return nil, fmt.Errorf("publish: the kept stamp wait: %w", err)
	}
	return &w, nil
}

func (p *Publisher) saveWait(ctx context.Context, doc []byte, w *stampWait) error {
	key := sha256.Sum256(doc)
	if p.Records == nil {
		p.mu.Lock()
		defer p.mu.Unlock()
		if p.waits == nil {
			p.waits = map[[32]byte]*stampWait{}
		}
		c := *w
		p.waits[key] = &c
		return nil
	}
	data, err := json.Marshal(w)
	if err != nil {
		return err
	}
	return p.Records.Apply(ctx, []peer.Change{{Kind: KindStampWait, ID: hex.EncodeToString(key[:]), Data: data}})
}

// stampedBundle returns doc's bundle once its timestamp is at or after
// notBefore (BALLOT-PROTOCOL §8.3 step 2). An earlier bundle means this
// service's clock is ahead of the timestamp authority's by more than
// CollectMargin: it is never uploaded, and it is dropped, so that doc is
// anchored again, under a new anchor signature (the same signature would
// only fetch the transparency log's existing entry).
//
// Each anchor is a permanent public log entry, so they are rationed: a
// call anchors at most once, and after an early stamp none is made until
// the authority's time, judged from that stamp and this service's clock
// since, has reached notBefore (the call answers ballot.ErrStampedEarly
// meanwhile). The early stamp and the dropped anchor signatures are kept
// (KindStampWait), so these hold across calls and restarts.
func (p *Publisher) stampedBundle(ctx context.Context, id string, doc []byte, notBefore int64) (json.RawMessage, error) {
	if p.Timestamp == nil {
		return nil, errors.New("publish: no timestamp check for the results")
	}
	w, err := p.loadWait(ctx, doc)
	if err != nil {
		return nil, err
	}
	for kept := true; ; kept = false {
		// A kept bundle is checked as it is; a new anchor waits until the
		// authority's time can have reached notBefore.
		bundle, err := p.StoredBundle(ctx, doc)
		if err != nil {
			return nil, err
		}
		anchored := false
		if bundle == nil {
			if early, err := p.tooSoon(ctx, id, doc, w, notBefore); err != nil || early {
				if err == nil {
					err = ballot.ErrStampedEarly // too soon to anchor again
				}
				return nil, err
			}
			if bundle, anchored, err = p.bundleNew(ctx, doc); err != nil {
				return nil, err
			}
		}
		if w != nil && containsSig(w.Dropped, anchorSig(bundle)) {
			// Not kept either: a later call must not take it as a kept one.
			if err := p.forget(ctx, doc, bundle); err != nil {
				return nil, err
			}
			if !anchored && kept {
				continue // left by a crash between the wait's save and the drop: judged as dropped
			}
			return nil, errors.New("publish: anchoring the results again gave an anchor signature dropped before")
		}
		t, err := p.Timestamp(bundle, doc)
		if err != nil {
			// Never uploaded unchecked. One kept from before stays kept, as
			// it may be what the site holds (README "results_bundle_unverified");
			// one anchored by this call was never uploaded, so it is dropped
			// and the next call anchors again.
			p.log().Error("the results' bundle doesn't verify", "alarm", "results_bundle_unverified", "proposal_id", id, "anchored", anchored, "err", err.Error())
			if anchored {
				if ferr := p.forget(ctx, doc, bundle); ferr != nil {
					return nil, ferr
				}
			}
			return nil, fmt.Errorf("publish: the results' timestamp: %w", err)
		}
		if t >= notBefore {
			if w != nil { // done waiting: the wait goes (best effort)
				if err := p.dropWait(ctx, doc); err != nil {
					p.log().Warn("publish: the stamp wait not dropped", "proposal_id", id, "err", err.Error())
				}
			}
			return bundle, nil
		}
		now := p.now().Unix()
		p.log().Error("results timestamped before the close: this service's clock is ahead of the timestamp authority's", "alarm", "results_stamped_early",
			"proposal_id", id, "timestamp", t, "closes_at", notBefore, "skew_seconds", now-t, "anchored", anchored)
		if w == nil {
			w = &stampWait{}
		}
		w.TSA, w.Seen = t, now
		if sig := anchorSig(bundle); len(sig) > 0 {
			w.Dropped = append(w.Dropped, sig)
			if len(w.Dropped) > maxDroppedSigs {
				w.Dropped = w.Dropped[len(w.Dropped)-maxDroppedSigs:]
			}
		}
		// Kept before the bundle is dropped: a crash between them leaves
		// the wait, never an early bundle without it.
		if err := p.saveWait(ctx, doc, w); err != nil {
			return nil, err
		}
		if err := p.forget(ctx, doc, bundle); err != nil {
			return nil, err
		}
		if anchored || !kept {
			return nil, ballot.ErrStampedEarly
		}
	}
}

// tooSoon reports whether, after an early stamp (w), a new anchor would
// still be early. With AuthorityTime, a fresh probe decides (no log
// entry); its answer updates w. Without, the estimate from w and this
// clock since does, void if this clock went back and never longer than
// ballot.ProbeMaxWait, so a corrected clock never starves the results.
func (p *Publisher) tooSoon(ctx context.Context, id string, doc []byte, w *stampWait, notBefore int64) (bool, error) {
	if w == nil {
		return false, nil
	}
	now := p.now().Unix()
	if p.AuthorityTime != nil {
		t, err := p.AuthorityTime(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return false, ctx.Err()
			}
			p.log().Error("the timestamp authority's time is unavailable: the results are not anchored again", "alarm", "tsa_unavailable", "proposal_id", id, "err", err.Error())
			return false, fmt.Errorf("%w: %v", ballot.ErrAuthorityTime, err)
		}
		if t >= notBefore {
			return false, nil
		}
		w.TSA, w.Seen = t, p.now().Unix()
		if err := p.saveWait(ctx, doc, w); err != nil {
			return false, err
		}
		p.log().Info("the timestamp authority isn't past the close yet: the results are not anchored again", "proposal_id", id, "authority_time", t, "closes_at", notBefore)
		return true, nil
	}
	since := now - w.Seen
	if since < 0 || since >= int64(ballot.ProbeMaxWait/time.Second) {
		return false, nil
	}
	if w.TSA+since < notBefore {
		p.log().Info("the timestamp authority can't be past the close yet: the results are not anchored again", "proposal_id", id, "closes_at", notBefore)
		return true, nil
	}
	return false, nil
}

// dropWait deletes doc's stamp wait.
func (p *Publisher) dropWait(ctx context.Context, doc []byte) error {
	key := sha256.Sum256(doc)
	if p.Records == nil {
		p.mu.Lock()
		delete(p.waits, key)
		p.mu.Unlock()
		return nil
	}
	return p.Records.Apply(ctx, []peer.Change{{Kind: KindStampWait, ID: hex.EncodeToString(key[:])}})
}

func containsSig(list [][]byte, sig []byte) bool {
	if len(sig) == 0 {
		return false
	}
	for _, x := range list {
		if bytes.Equal(x, sig) {
			return true
		}
	}
	return false
}

// anchorSig is a bundle's message signature (the anchor signature), or
// nil if it has none.
func anchorSig(bundle json.RawMessage) []byte {
	var b struct {
		MessageSignature struct {
			Signature []byte `json:"signature"`
		} `json:"messageSignature"`
	}
	if json.Unmarshal(bundle, &b) != nil {
		return nil
	}
	return b.MessageSignature.Signature
}

// publish anchors doc (once: a retry, even after a restart, sends the
// same bundle, which the site wants, §4 "Write-once") and uploads it.
// With notBefore, only a bundle timestamped at or after it is uploaded
// (stampedBundle).
func (p *Publisher) publish(ctx context.Context, id, name string, doc, sig, rows []byte, notBefore int64) (ballot.Receipt, error) {
	var bundle json.RawMessage
	var err error
	if notBefore > 0 {
		bundle, err = p.stampedBundle(ctx, id, doc, notBefore)
	} else {
		bundle, err = p.bundle(ctx, doc)
	}
	if err != nil {
		return ballot.Receipt{}, err
	}
	return p.upload(ctx, id, name, doc, sig, rows, bundle)
}

// upload posts doc with its signature, bundle and rows to the site.
func (p *Publisher) upload(ctx context.Context, id, name string, doc, sig, rows []byte, bundle json.RawMessage) (ballot.Receipt, error) {
	body, err := json.Marshal(struct {
		Doc    []byte          `json:"doc"`
		Sig    []byte          `json:"sig"`
		Bundle json.RawMessage `json:"bundle"`
		Rows   []byte          `json:"rows,omitempty"`
	}{doc, sig, bundle, rows})
	if err != nil {
		return ballot.Receipt{}, err
	}
	url := strings.TrimRight(p.URL, "/") + "/api/v1/p/" + id + "/" + name
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return ballot.Receipt{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := p.Client.Do(req)
	if err != nil {
		return ballot.Receipt{}, err
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	switch resp.StatusCode {
	case http.StatusCreated, http.StatusOK:
		// The document is written. "index_updated": false says the index
		// update failed: published all the same, and the identical upload
		// again (reconcile does it for an extension) finishes the index.
		// A site that sends no such field is not saying it failed.
		var a struct {
			IndexUpdated *bool `json:"index_updated"`
		}
		stale := json.Unmarshal(out, &a) == nil && a.IndexUpdated != nil && !*a.IndexUpdated
		if stale {
			p.log().Warn("publish: the site's index is not updated", "proposal_id", id, "name", name)
		}
		return ballot.Receipt{Bundle: bundle, IndexStale: stale}, nil
	}
	var e struct {
		Error string `json:"error"`
	}
	_ = json.Unmarshal(out, &e)
	if resp.StatusCode >= 500 || resp.StatusCode == http.StatusTooManyRequests {
		return ballot.Receipt{}, fmt.Errorf("publish: votes.vettid.org answered %d %s", resp.StatusCode, e.Error)
	}
	return ballot.Receipt{}, &ErrRefused{Status: resp.StatusCode, Code: e.Error}
}

// errNoURL is a publisher with no site.
var errNoURL = errors.New("publish: no site URL")

// Check reports whether the publisher is configured.
func (p *Publisher) Check() error {
	if !strings.HasPrefix(p.URL, "https://") {
		return errNoURL
	}
	return nil
}

var _ ballot.SiteReader = (*Publisher)(nil)

// get fetches a path of the site's read side (/v1/...), or nil on 404.
func (p *Publisher) get(ctx context.Context, path string, max int64) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(p.URL, "/")+"/v1/"+path, nil)
	if err != nil {
		return nil, err
	}
	resp, err := p.Client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusOK:
		b, err := io.ReadAll(io.LimitReader(resp.Body, max+1))
		if err != nil {
			return nil, err
		}
		if int64(len(b)) > max {
			return nil, fmt.Errorf("publish: %s is over %d bytes", path, max)
		}
		return b, nil
	case http.StatusNotFound:
		return nil, nil
	}
	return nil, fmt.Errorf("publish: votes.vettid.org answered %d for %s", resp.StatusCode, path)
}

// Extension implements ballot.SiteReader. The site writes the document
// last, so a document without its signature or bundle is an error, not
// a missing extension.
func (p *Publisher) Extension(ctx context.Context, id string, n int64) (*ballot.SiteExtension, error) {
	base := "p/" + id + "/extension-" + strconv.FormatInt(n, 10)
	doc, err := p.get(ctx, base+".json", 4096)
	if err != nil || doc == nil {
		return nil, err
	}
	sig, err := p.get(ctx, base+".json.sig", 256)
	if err != nil {
		return nil, err
	}
	bundle, err := p.get(ctx, base+".json.sigstore.json", 64<<10)
	if err != nil {
		return nil, err
	}
	if sig == nil || bundle == nil {
		return nil, fmt.Errorf("publish: extension %d of %s has no signature or bundle on the site", n, id)
	}
	return &ballot.SiteExtension{Doc: doc, Sig: sig, Bundle: bundle}, nil
}

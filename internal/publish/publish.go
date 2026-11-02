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

	"github.com/vettid/service-vault/internal/anchor"
	"github.com/vettid/service-vault/internal/ballot"
	"github.com/vettid/service-vault/internal/peer"
)

// KindBundle is a document's Sigstore bundle in the record store, by the
// document's SHA-256 (hex).
const KindBundle = "vote_bundle"

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

	// Log is where the publisher logs; nil is slog's default.
	Log *slog.Logger

	mu      sync.Mutex
	bundles map[[32]byte]json.RawMessage // anchored this run, by document
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
	rc, err := p.publish(ctx, id, "proposal", doc, sig, nil)
	return rc.Bundle, err
}

// PublishExtension implements ballot.ExtensionPublisher.
func (p *Publisher) PublishExtension(ctx context.Context, id string, n int64, doc, sig []byte) (ballot.Receipt, error) {
	return p.publish(ctx, id, "extension-"+strconv.FormatInt(n, 10), doc, sig, nil)
}

// PublishResults implements ballot.ResultsPublisher.
func (p *Publisher) PublishResults(ctx context.Context, id string, results, sig, rows []byte) (ballot.Receipt, error) {
	return p.publish(ctx, id, "results", results, sig, rows)
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
	key := sha256.Sum256(doc)
	p.mu.Lock()
	b := p.bundles[key]
	p.mu.Unlock()
	if b != nil {
		return b, nil
	}
	id := hex.EncodeToString(key[:])
	if p.Records != nil {
		data, ok, err := p.Records.Get(ctx, KindBundle, id)
		if err != nil {
			return nil, err
		}
		if ok {
			b = data
		}
	}
	if b == nil {
		var err error
		if b, err = p.Anchor.Anchor(ctx, doc); err != nil {
			return nil, err
		}
		if p.Records != nil {
			err := p.Records.Apply(ctx, []peer.Change{{Kind: KindBundle, ID: id, Data: b, IfAbsent: true}})
			if errors.Is(err, peer.ErrConflict) {
				return p.bundle(ctx, doc) // kept meanwhile: that one
			}
			if err != nil {
				return nil, err
			}
		}
	}
	p.mu.Lock()
	if p.bundles == nil {
		p.bundles = map[[32]byte]json.RawMessage{}
	}
	p.bundles[key] = b
	p.mu.Unlock()
	return b, nil
}

// publish anchors doc (once: a retry, even after a restart, sends the
// same bundle, which the site wants, §4 "Write-once") and uploads it.
func (p *Publisher) publish(ctx context.Context, id, name string, doc, sig, rows []byte) (ballot.Receipt, error) {
	bundle, err := p.bundle(ctx, doc)
	if err != nil {
		return ballot.Receipt{}, err
	}
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

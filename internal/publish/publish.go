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

	mu      sync.Mutex
	bundles map[[32]byte]json.RawMessage // anchored this run, by document
}

var (
	_ ballot.Publisher          = (*Publisher)(nil)
	_ ballot.ExtensionPublisher = (*Publisher)(nil)
	_ ballot.ResultsPublisher   = (*Publisher)(nil)
	_ Anchorer                  = (*anchor.Anchorer)(nil)
)

// ErrRefused is the site refusing a document: a code it gave, which no
// retry changes.
type ErrRefused struct {
	Status int
	Code   string
}

func (e *ErrRefused) Error() string {
	return fmt.Sprintf("publish: votes.vettid.org refused it: %d %s", e.Status, e.Code)
}

// PublishProposal implements ballot.Publisher.
func (p *Publisher) PublishProposal(ctx context.Context, id string, doc, sig []byte) (json.RawMessage, error) {
	return p.publish(ctx, id, "proposal", doc, sig, nil)
}

// PublishExtension implements ballot.ExtensionPublisher.
func (p *Publisher) PublishExtension(ctx context.Context, id string, n int64, doc, sig []byte) (json.RawMessage, error) {
	return p.publish(ctx, id, "extension-"+strconv.FormatInt(n, 10), doc, sig, nil)
}

// PublishResults implements ballot.ResultsPublisher.
func (p *Publisher) PublishResults(ctx context.Context, id string, results, sig, rows []byte) (json.RawMessage, error) {
	return p.publish(ctx, id, "results", results, sig, rows)
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
func (p *Publisher) publish(ctx context.Context, id, name string, doc, sig, rows []byte) (json.RawMessage, error) {
	bundle, err := p.bundle(ctx, doc)
	if err != nil {
		return nil, err
	}
	body, err := json.Marshal(struct {
		Doc    []byte          `json:"doc"`
		Sig    []byte          `json:"sig"`
		Bundle json.RawMessage `json:"bundle"`
		Rows   []byte          `json:"rows,omitempty"`
	}{doc, sig, bundle, rows})
	if err != nil {
		return nil, err
	}
	url := strings.TrimRight(p.URL, "/") + "/api/v1/p/" + id + "/" + name
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := p.Client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	switch resp.StatusCode {
	case http.StatusCreated, http.StatusOK:
		return bundle, nil
	}
	var e struct {
		Error string `json:"error"`
	}
	_ = json.Unmarshal(out, &e)
	if resp.StatusCode >= 500 || resp.StatusCode == http.StatusTooManyRequests {
		return nil, fmt.Errorf("publish: votes.vettid.org answered %d %s", resp.StatusCode, e.Error)
	}
	return nil, &ErrRefused{Status: resp.StatusCode, Code: e.Error}
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

package servicevault_test

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"io"
	"log"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/vettid/service-vault/internal/api"
	"github.com/vettid/service-vault/internal/approval"
	"github.com/vettid/service-vault/internal/connect"
	"github.com/vettid/service-vault/internal/peer"
	"github.com/vettid/service-vault/internal/service"
	"github.com/vettid/service-vault/internal/tlsid"
	"github.com/vettid/service-vault/sdk/go/servicevault"
)

// randomHex returns n random bytes in hex: test keys and secrets are made
// at run time, never written down.
func randomHex(t testing.TB, n int) string {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(b)
}

const knownEmail = "member@example.org"

var inviteExp = time.Unix(1_800_000_600, 0).UTC()

// fakePeer stands in for the relay side: one invitation, inv1, whose
// handshake reached the SAS for connection c1; c1 is active, and every
// challenge is sent, numbered req1, req2, ...
type fakePeer struct{ n atomic.Int32 }

func (*fakePeer) CreateInvite(_ context.Context, tag string) (*peer.InviteRecord, error) {
	return &peer.InviteRecord{ID: "inv1", URL: "https://relay.vettid.test/connect#x", Exp: inviteExp, Tag: tag,
		Status: peer.InviteWaiting}, nil
}

func (*fakePeer) Invite(id string) (peer.InviteRecord, bool) {
	return peer.InviteRecord{ID: id, Status: peer.InviteSAS, SAS: "123456", ConnID: "c1"}, id == "inv1"
}

func (*fakePeer) Connection(id string) (peer.ConnectionInfo, bool) {
	return peer.ConnectionInfo{ID: id, State: peer.StateActive}, id == "c1"
}

func (p *fakePeer) Authenticate(context.Context, string, string, time.Duration) (string, error) {
	return "req" + strconv.Itoa(int(p.n.Add(1))), nil
}

func (*fakePeer) CancelChallenge(context.Context, string) (bool, error) { return true, nil }

// fixture is the service (internal/service on a fake peer) behind the
// private API (internal/api) over TLS 1.3 with a tlsid key.
type fixture struct {
	svc      *service.Service
	apv      *approval.Manager // bootstrap email: knownEmail
	emailKey string            // the index key of knownEmail
	url, pin string
	key      string // the API key
}

func newFixture(t *testing.T, hooks service.Webhooks) *fixture {
	t.Helper()
	idx, err := connect.NewEmailIndex([]byte(randomHex(t, 32)))
	if err != nil {
		t.Fatal(err)
	}
	ek, err := idx.Key(knownEmail)
	if err != nil {
		t.Fatal(err)
	}
	quiet := slog.New(slog.NewTextHandler(io.Discard, nil))
	fp, st := &fakePeer{}, peer.NewMemStore()
	svc := &service.Service{Peer: fp, Store: st, ServiceName: "VettID Member Service", Webhooks: hooks, Log: quiet}
	svc.Approvals = &approval.Manager{Peer: fp, Store: st, Pager: st, Webhooks: hooks, ServiceName: svc.ServiceName,
		Threshold: 1, BootstrapKey: ek, BoundConnection: svc.BoundConnection, Log: quiet}
	f := &fixture{svc: svc, apv: svc.Approvals, emailKey: ek, key: randomHex(t, 24)}
	s := &api.Server{Keys: [][32]byte{api.HashKey(f.key)}, Email: idx, Invites: svc.Invites(), SignIns: svc.SignIns(),
		Approvals: svc.Approvals, LookupFloor: 10 * time.Millisecond, Log: quiet}
	var srv *httptest.Server
	srv, f.pin = tlsServer(t, s.Handler())
	f.url = srv.URL
	return f
}

func (f *fixture) client(t *testing.T) *servicevault.Client {
	t.Helper()
	c, err := servicevault.New(servicevault.Config{BaseURL: f.url + "/", APIKey: f.key, Pin: f.pin})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// deliver hands the service a peer event, as the peer does.
func (f *fixture) deliver(t *testing.T, e peer.Event) {
	t.Helper()
	if e.At.IsZero() {
		e.At = time.Now()
	}
	if err := f.svc.Deliver(context.Background(), &e); err != nil {
		t.Fatalf("%s: %v", e.Type, err)
	}
}

func tlsServer(t *testing.T, h http.Handler) (*httptest.Server, string) {
	t.Helper()
	der, err := tlsid.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	cert, pin, err := tlsid.Certificate(der, []string{"service-vault.test"}, time.Now(), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewUnstartedServer(h)
	srv.TLS = tlsid.ServerConfig(cert)
	srv.Config.ErrorLog = log.New(io.Discard, "", 0) // the pin test's refused handshakes
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv, pin
}

//go:build integration

package integration

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"

	"github.com/vettid/service-vault/internal/peer"
	"github.com/vettid/service-vault/internal/peer/peertest"
	"github.com/vettid/service-vault/internal/service"
	"github.com/vettid/service-vault/internal/store"
	"github.com/vettid/vettid-vault/vms/peerwire"
)

func newTable(t *testing.T, ctx context.Context) *store.Table {
	t.Helper()
	cfg, ep := awsConfig(t)
	tbl := &store.Table{
		Client: dynamodb.NewFromConfig(cfg, func(o *dynamodb.Options) { o.BaseEndpoint = aws.String(ep) }),
		Name:   fmt.Sprintf("sv-it-peer-%d", time.Now().UnixNano()),
	}
	if err := tbl.CreateTable(ctx); err != nil {
		t.Fatalf("CreateTable: %v", err)
	}
	t.Cleanup(func() {
		tbl.Client.DeleteTable(context.Background(), &dynamodb.DeleteTableInput{TableName: aws.String(tbl.Name)})
	})
	return tbl
}

func TestPeerStoreConditions(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	s := newTable(t, ctx).Peer()

	// IfAbsent: once only.
	if err := s.Apply(ctx, []peer.Change{{Kind: "k", ID: "a", Data: []byte("1"), IfAbsent: true}}); err != nil {
		t.Fatal(err)
	}
	if err := s.Apply(ctx, []peer.Change{{Kind: "k", ID: "a", Data: []byte("2"), IfAbsent: true}}); err != peer.ErrConflict {
		t.Fatalf("second IfAbsent: %v", err)
	}
	// IfVersion: the version read.
	recs, err := s.Load(ctx, "k")
	if err != nil || len(recs) != 1 || recs[0].Version != 1 || string(recs[0].Data) != "1" {
		t.Fatalf("load %+v %v", recs, err)
	}
	if err := s.Apply(ctx, []peer.Change{{Kind: "k", ID: "a", Data: []byte("2"), IfVersion: 1}}); err != nil {
		t.Fatal(err)
	}
	if err := s.Apply(ctx, []peer.Change{{Kind: "k", ID: "a", Data: []byte("3"), IfVersion: 1}}); err != peer.ErrConflict {
		t.Fatalf("stale version: %v", err)
	}
	// All or nothing: a failing condition writes nothing.
	err = s.Apply(ctx, []peer.Change{{Kind: "k", ID: "b", Data: []byte("x"), IfAbsent: true},
		{Kind: "k", ID: "a", Data: []byte("4"), IfVersion: 1}})
	if err != peer.ErrConflict {
		t.Fatalf("mixed: %v", err)
	}
	if _, ok, _ := s.Get(ctx, "k", "b"); ok {
		t.Fatal("partial write")
	}
	// Expired records are absent: not loaded, not got, re-creatable, and
	// deleting one holds.
	past := time.Now().Add(-time.Minute)
	if err := s.Apply(ctx, []peer.Change{{Kind: "k", ID: "e", Data: []byte("x"), Expires: past, IfAbsent: true}}); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := s.Get(ctx, "k", "e"); ok {
		t.Fatal("expired record read")
	}
	if recs, _ := s.Load(ctx, "k"); len(recs) != 1 {
		t.Fatalf("load with expired: %d", len(recs))
	}
	if err := s.Apply(ctx, []peer.Change{{Kind: "k", ID: "e", IfVersion: 1}}); err != nil {
		t.Fatalf("delete expired: %v", err)
	}
	if err := s.Apply(ctx, []peer.Change{{Kind: "k", ID: "e", Data: []byte("y"), IfAbsent: true}}); err != nil {
		t.Fatalf("re-create: %v", err)
	}
	// Delete on the version read.
	if err := s.Apply(ctx, []peer.Change{{Kind: "k", ID: "a", IfVersion: 1}}); err != peer.ErrConflict {
		t.Fatalf("stale delete: %v", err)
	}
	if err := s.Apply(ctx, []peer.Change{{Kind: "k", ID: "a", IfVersion: 2}}); err != nil {
		t.Fatal(err)
	}
	// More changes than one transaction holds, and pages of Load.
	var many []peer.Change
	for i := 0; i < 250; i++ {
		many = append(many, peer.Change{Kind: "m", ID: fmt.Sprintf("%04d", i), Data: bytes.Repeat([]byte{'z'}, 2000), IfAbsent: true})
	}
	if err := s.Apply(ctx, many); err != nil {
		t.Fatal(err)
	}
	if recs, err := s.Load(ctx, "m"); err != nil || len(recs) != 250 {
		t.Fatalf("load many: %d %v", len(recs), err)
	}
}

// A connection and a sign-in end to end on DynamoDB, with a restart in
// the middle (MEMBER-SERVICE-PLAN §10 1.2: in-flight state survives).
func TestPeerOnDynamoDB(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	tbl := newTable(t, ctx)
	clk := peertest.NewClock(time.Now().UTC().Truncate(time.Millisecond))
	w := peertest.NewWorld(clk)
	keys, err := peer.KeysFromSeeds(peer.Seeds{IK: bytes.Repeat([]byte{1}, 32), KEM: bytes.Repeat([]byte{2}, 32),
		Relay: bytes.Repeat([]byte{3}, 32)})
	if err != nil {
		t.Fatal(err)
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	var p *peer.Peer
	var svc *service.Service
	start := func() {
		svc = &service.Service{Store: tbl.Peer(), ServiceName: "VettID Member Service", Now: clk.Now, Log: log}
		p, err = peer.New(peer.Config{Keys: keys, Relay: w.View(keys.Relay), RelayURL: peertest.RelayURL, Store: tbl.Peer(),
			Events: svc, Now: clk.Now, Log: log, Profile: peer.Profile{FirstName: "VettID", LastName: "Member Service"}})
		if err != nil {
			t.Fatal(err)
		}
		if err := p.Start(ctx); err != nil {
			t.Fatal(err)
		}
		svc.Peer = p
	}
	m := peertest.NewMember(t, w, 10)
	pump := func() {
		for i := 0; i < 50; i++ {
			n, err := p.Step(ctx, 0)
			if err != nil {
				t.Fatal(err)
			}
			n += m.Step()
			p.DeliverEvents(ctx)
			if n == 0 {
				return
			}
		}
	}
	start()
	inv, err := svc.Invites().Create(ctx, "email-key")
	if err != nil {
		t.Fatal(err)
	}
	m.Accept(inv.URL[strings.IndexByte(inv.URL, '#')+1:], "")
	pump()
	st, err := svc.Invites().Status(ctx, inv.ID)
	if err != nil || st.SAS != m.SAS || m.SAS == "" {
		t.Fatalf("status %+v %v", st, err)
	}
	start() // restart before the member approves
	m.Approve()
	pump()
	if st, _ := svc.Invites().Status(ctx, inv.ID); st.Status != "connected" {
		t.Fatalf("status %+v", st)
	}
	id, err := svc.SignIns().Start(ctx, "email-key", "42")
	if err != nil {
		t.Fatal(err)
	}
	pump()
	if len(m.Challenges) != 1 {
		t.Fatal("no challenge")
	}
	start() // restart with the sign-in in flight
	r, _ := peerwire.SignConnAuth(m.Cred, keys.IKPublic(), m.IK.Public().(ed25519.PublicKey), m.Challenges[0], clk.Now(), nil)
	m.Send(peerwire.TypeConnAuthResponse, r.Marshal())
	pump()
	if s, cid, err := svc.SignIns().Status(ctx, id); err != nil || s != "approved" || cid != st.ConnectionID {
		t.Fatalf("sign-in %q %q %v", s, cid, err)
	}
	// The member rekeys a day later; the epoch moves on DynamoDB too.
	clk.Advance(24 * time.Hour)
	m.StartRekey()
	pump()
	m.Send(peerwire.TypeConnectionRemoved, peerwire.ConnectionRemovedBody())
	pump()
	if _, ok := p.Connection(st.ConnectionID); ok {
		t.Fatal("connection kept after removal")
	}
}

//go:build devstack

// Package devstack runs the service vault against a real member vault:
// vettid-vault's dev stack (README "Local dev stack" there) at the commit
// pinned in go.mod, with a member played by its vaultctl. Not in CI:
//
//	make devstack-up     # in another terminal: the stack (about 8 GB of memory)
//	make devstack-test
//
// The service vault runs in this process: its peer on the stack's relay
// (https://relay.vettid.test, dialled at ready.json's relay_tls and
// trusting the stack's TEST TLS root), its private API on a loopback
// listener and its webhooks into memory.
package devstack

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/vettid/vettid-relay/relayclient"

	"github.com/vettid/service-vault/internal/api"
	"github.com/vettid/service-vault/internal/approval"
	"github.com/vettid/service-vault/internal/connect"
	"github.com/vettid/service-vault/internal/peer"
	"github.com/vettid/service-vault/internal/service"
	"github.com/vettid/service-vault/internal/webhook"
	"github.com/vettid/service-vault/sdk/go/servicevault"
)

const relayOrigin = "https://relay.vettid.test"

// The dev stack's TEST-ONLY app PIN and credential (vettid-vault README).
const (
	devPIN        = "13572468"
	devCredential = "development password"
)

// stack is the running dev stack, as its ready.json describes it.
type stack struct {
	data     string
	Ctl      string `json:"ctl"`
	API      string `json:"api"`
	RelayTLS string `json:"relay_tls"`
}

func openStack(t *testing.T) *stack {
	t.Helper()
	data := os.Getenv("SV_DEVSTACK_DATA")
	if data == "" {
		cache, err := os.UserCacheDir()
		if err != nil {
			t.Fatal(err)
		}
		data = filepath.Join(cache, "vettid-devstack")
	}
	b, err := os.ReadFile(filepath.Join(data, "run", "ready.json"))
	if err != nil {
		t.Fatalf("no dev stack for %s (make devstack-up, or set SV_DEVSTACK_DATA): %v", data, err)
	}
	s := &stack{data: data}
	if err := json.Unmarshal(b, s); err != nil || s.Ctl == "" || s.API == "" || s.RelayTLS == "" {
		t.Fatalf("ready.json: %v", err)
	}
	return s
}

// relayClient dials relay_tls for relay.vettid.test and trusts only the
// stack's TEST TLS root (GET /dev/trust).
func (s *stack) relayClient(t *testing.T) *http.Client {
	t.Helper()
	resp, err := http.Get(strings.TrimRight(s.Ctl, "/") + "/dev/trust")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var tr struct {
		TLSRootPEM string `json:"tls_root_pem"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&tr); err != nil || tr.TLSRootPEM == "" {
		t.Fatalf("/dev/trust: %v", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM([]byte(tr.TLSRootPEM)) {
		t.Fatal("/dev/trust: no TLS root")
	}
	addr := strings.TrimPrefix(strings.TrimPrefix(s.RelayTLS, "https://"), "http://")
	d := &net.Dialer{Timeout: 10 * time.Second}
	tp := &http.Transport{
		Proxy: nil,
		DialContext: func(ctx context.Context, network, a string) (net.Conn, error) {
			if a != "relay.vettid.test:443" {
				return nil, fmt.Errorf("dev stack: no route to %s", a)
			}
			return d.DialContext(ctx, network, addr)
		},
		TLSClientConfig:     &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12},
		ForceAttemptHTTP2:   true,
		TLSHandshakeTimeout: 10 * time.Second,
	}
	return &http.Client{Transport: tp, Timeout: 60 * time.Second}
}

// vaultctl plays the member's phone.
type vaultctl struct {
	t     *testing.T
	bin   string
	state string
	env   []string
}

func (s *stack) member(t *testing.T) *vaultctl {
	return &vaultctl{t: t, bin: filepath.Join(s.data, "bin", "vaultctl"), state: filepath.Join(t.TempDir(), "member.json"),
		env: append(os.Environ(), "VAULTCTL_DEV_RESOLVE=relay.vettid.test="+strings.TrimPrefix(s.RelayTLS, "https://"),
			"VAULTCTL_PIN="+devPIN, "VAULTCTL_PASSWORD="+devCredential)}
}

// run runs vaultctl and returns the JSON objects it printed.
func (v *vaultctl) run(args ...string) []map[string]any {
	v.t.Helper()
	full := append([]string{"-state", v.state, "-timeout", "150s"}, args...)
	cmd := exec.Command(v.bin, full...)
	cmd.Env = v.env
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	if err := cmd.Run(); err != nil {
		v.t.Fatalf("vaultctl %s: %v\n%s\n%s", args[0], err, out.String(), errb.String())
	}
	var objs []map[string]any
	dec := json.NewDecoder(bytes.NewReader(out.Bytes()))
	for {
		var o map[string]any
		if err := dec.Decode(&o); err != nil {
			break
		}
		objs = append(objs, o)
	}
	return objs
}

// request sends a request and returns its response body; the events
// printed with it are returned too.
func (v *vaultctl) request(typ, body string) (map[string]any, []map[string]any) {
	v.t.Helper()
	objs := v.run("request", typ, body)
	if len(objs) == 0 {
		v.t.Fatalf("%s: no output", typ)
	}
	r := objs[0]
	if r["status"] != "ok" {
		v.t.Fatalf("%s: %v", typ, r)
	}
	b, _ := r["body"].(map[string]any)
	return b, objs[1:]
}

// waitEvent collects events until one of type typ matches.
func (v *vaultctl) waitEvent(typ string, match func(map[string]any) bool, seen *[]map[string]any) map[string]any {
	v.t.Helper()
	check := func() map[string]any {
		for _, e := range *seen {
			if e["type"] == typ {
				if b, _ := e["body"].(map[string]any); match == nil || match(b) {
					return b
				}
			}
		}
		return nil
	}
	deadline := time.Now().Add(3 * time.Minute)
	for time.Now().Before(deadline) {
		if b := check(); b != nil {
			return b
		}
		*seen = append(*seen, v.run("events", "-wait", "5s")...)
	}
	v.t.Fatalf("no %s event", typ)
	return nil
}

type hooks struct {
	mu  sync.Mutex
	evs []*webhook.Event
}

func (h *hooks) Deliver(_ context.Context, e *webhook.Event) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.evs = append(h.evs, e)
	return nil
}

func (h *hooks) wait(t *testing.T, typ string) *webhook.Event {
	t.Helper()
	deadline := time.Now().Add(2 * time.Minute)
	for time.Now().Before(deadline) {
		h.mu.Lock()
		for _, e := range h.evs {
			if e.Type == typ {
				h.mu.Unlock()
				return e
			}
		}
		h.mu.Unlock()
		time.Sleep(200 * time.Millisecond)
	}
	t.Fatalf("no %s webhook", typ)
	return nil
}

const apiKey = "devstack-test-api-key-not-a-secret"

func call(t *testing.T, srv *httptest.Server, method, path, body string) map[string]any {
	t.Helper()
	req, _ := http.NewRequest(method, srv.URL+path, strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+apiKey)
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil || resp.StatusCode >= 300 {
		t.Fatalf("%s %s: %d %s", method, path, resp.StatusCode, b)
	}
	return m
}

func TestConnectAndSignInAgainstDevStack(t *testing.T) {
	s := openStack(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))

	// The service vault, in process.
	keys, err := peer.GenerateKeys()
	if err != nil {
		t.Fatal(err)
	}
	rc := relayclient.New(relayOrigin, keys.Relay)
	rc.HTTP = s.relayClient(t)
	st := peer.NewMemStore()
	hk := &hooks{}
	svc := &service.Service{Store: st, ServiceName: "VettID Member Service", Webhooks: hk, Log: log}
	p, err := peer.New(peer.Config{Keys: keys, Relay: rc, RelayURL: relayOrigin, Store: st, Events: svc, Log: log,
		Profile: peer.Profile{FirstName: "VettID", LastName: "Member Service"}, PollWait: 2 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	svc.Peer = p
	email, err := connect.NewEmailIndex(bytes.Repeat([]byte{7}, 32)) // TEST-ONLY pepper
	if err != nil {
		t.Fatal(err)
	}
	bootKey, _ := email.Key("member@example.org")
	approvals := &approval.Manager{Peer: p, Store: st, Pager: st, Webhooks: hk, ServiceName: svc.ServiceName, Threshold: 1,
		BootstrapKey: bootKey, BoundConnection: svc.BoundConnection, Log: log}
	svc.Approvals = approvals
	go approvals.Run(ctx)
	runDone := make(chan error, 1)
	go func() { runDone <- p.Run(ctx) }()
	defer func() {
		cancel()
		<-runDone
	}()
	srv := httptest.NewTLSServer((&api.Server{Keys: [][32]byte{api.HashKey(apiKey)}, Email: email, Invites: svc.Invites(),
		SignIns: svc.SignIns(), Approvals: approvals, LookupFloor: 50 * time.Millisecond, Log: log}).Handler())
	defer srv.Close()

	// The member: a fresh test vault with an app, its credential unlocked.
	m := s.member(t)
	m.run("init", "-role", "app", "-name", "member-phone", "-relay", relayOrigin)
	m.run("api-enroll", "-api", s.API, "-guid", fmt.Sprintf("sv-devstack-%d", time.Now().UnixNano()), "-pin", devPIN)
	m.run("credential", "unlock")
	var seen []map[string]any

	// 1. Connect from the service's invitation link.
	inv := call(t, srv, "POST", "/v1/invites", `{"email":"member@example.org"}`)
	invID, _ := inv["invite_id"].(string)
	url, _ := inv["url"].(string)
	link := url[strings.IndexByte(url, '#')+1:]
	accepted, evs := m.request("connection.invite.accept", fmt.Sprintf(`{"link":%q}`, link))
	seen = append(seen, evs...)
	connID, _ := accepted["connection_id"].(string)
	out := m.waitEvent("connection.request.outgoing", func(b map[string]any) bool { return b["connection_id"] == connID }, &seen)
	memberSAS, _ := out["sas"].(string)
	var status map[string]any
	for i := 0; i < 100; i++ {
		status = call(t, srv, "GET", "/v1/invites/"+invID, "")
		if status["status"] == "sas" {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}
	if status["status"] != "sas" || status["sas"] != memberSAS || memberSAS == "" {
		t.Fatalf("SAS: service %v, member %q", status, memberSAS)
	}
	t.Logf("SAS equal on both sides: %s", memberSAS)
	if hk.wait(t, peer.EventConnectionPending) == nil {
		t.Fatal("no pending webhook")
	}

	// 2. The member approves after comparing; the service approved its side.
	_, evs = m.request("connection.approve", fmt.Sprintf(`{"connection_id":%q}`, connID))
	seen = append(seen, evs...)
	m.waitEvent("connection.event", func(b map[string]any) bool { return b["connection_id"] == connID && b["event"] == "added" }, &seen)
	added := hk.wait(t, peer.EventConnectionAdded)
	svcConn := added.ConnectionID
	if st := call(t, srv, "GET", "/v1/invites/"+invID, ""); st["status"] != "connected" || st["connection_id"] != svcConn {
		t.Fatalf("invite %v", st)
	}
	t.Logf("connection active: member %s, service %s", connID, svcConn)

	// 3. The member's vault shows the service by its profile's names.
	var title string
	for i := 0; i < 50 && title == ""; i++ {
		got, evs := m.request("connection.get", fmt.Sprintf(`{"connection_id":%q}`, connID))
		seen = append(seen, evs...)
		if pr, ok := got["profile"].(map[string]any); ok {
			title = fmt.Sprintf("%v %v", pr["first_name"], pr["last_name"])
		}
		if title == "" {
			time.Sleep(time.Second)
		}
	}
	if title != "VettID Member Service" {
		t.Fatalf("connection title %q", title)
	}
	t.Logf("member's vault shows the connection as %q", title)

	// 4. Sign in: the challenge carries the match code; the member approves.
	si := call(t, srv, "POST", "/v1/signins", `{"email":"member@example.org"}`)
	siID, _ := si["signin_id"].(string)
	code, _ := si["match_code"].(string)
	pend := m.waitEvent("connection.authenticate.pending", func(b map[string]any) bool { return b["connection_id"] == connID }, &seen)
	ctxt, _ := pend["context"].(string)
	if !regexp.MustCompile(`match code ` + code + `$`).MatchString(ctxt) {
		t.Fatalf("challenge context %q, code %s", ctxt, code)
	}
	t.Logf("challenge context: %q", ctxt)
	_, evs = m.request("connection.authenticate.approve", fmt.Sprintf(`{"request_id":%q}`, pend["request_id"]))
	seen = append(seen, evs...)
	hk.wait(t, peer.EventSignInApproved)
	if r := call(t, srv, "GET", "/v1/signins/"+siID, ""); r["status"] != "approved" || r["connection_id"] != svcConn {
		t.Fatalf("sign-in %v", r)
	}
	t.Log("sign-in approved and verified")

	// 5. The member is the bootstrap admin; a governance action reaches
	// their phone with its hash, and their approval approves it.
	if ad := call(t, srv, "GET", "/v1/admins", ""); fmt.Sprint(ad["admins"]) != "["+svcConn+"]" {
		t.Fatalf("admins %v", ad)
	}
	ap := call(t, srv, "POST", "/v1/approvals", `{"action":"vote.open","summary":"Open the vote on proposal 7","payload":{"proposal":7}}`)
	apID, _ := ap["approval_id"].(string)
	hash, _ := ap["action_hash"].(string)
	if want, _ := servicevault.ActionHash("vote.open", "Open the vote on proposal 7", json.RawMessage(`{"proposal":7}`)); hash != want {
		t.Fatalf("action hash %q, want %q", hash, want)
	}
	pend = m.waitEvent("connection.authenticate.pending", func(b map[string]any) bool {
		c, _ := b["context"].(string)
		return b["connection_id"] == connID && strings.Contains(c, "ref "+hash[:8])
	}, &seen)
	t.Logf("approval challenge context: %q", pend["context"])
	_, evs = m.request("connection.authenticate.approve", fmt.Sprintf(`{"request_id":%q}`, pend["request_id"]))
	seen = append(seen, evs...)
	hk.wait(t, approval.EventApproved)
	if r := call(t, srv, "GET", "/v1/approvals/"+apID, ""); r["status"] != "approved" {
		t.Fatalf("approval %v", r)
	}
	audit := call(t, srv, "GET", "/v1/audit", "")
	entries, _ := audit["entries"].([]any)
	signed := false
	for _, e := range entries {
		if e, _ := e.(map[string]any); e["type"] == "approval.response" && e["answer"] == "approved" && e["signature"] != nil {
			signed = true
		}
	}
	if !signed {
		t.Fatalf("audit %v", audit)
	}
	t.Log("approval approved on the phone; signature in the audit log")

	// 6. The member removes the connection; the service learns it.
	m.request("connection.remove", fmt.Sprintf(`{"connection_id":%q}`, connID))
	rm := hk.wait(t, peer.EventConnectionRemoved)
	if rm.ConnectionID != svcConn {
		t.Fatalf("removed %+v", rm)
	}
	if _, ok := p.Connection(svcConn); ok {
		t.Fatal("connection kept after removal")
	}
	t.Log("removal reached the service")
}

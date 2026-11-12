// Command service-vault is the VettID service vault: the component an
// application runs to connect with VettID members. It is a VMS v2 peer on
// the relay (VAULT-MESSAGING §6.4, §10.4) and serves the application a
// private HTTPS API and signed webhooks (MEMBER-SERVICE-PLAN §3, §7.2),
// including admin approvals of governance actions (§4.5).
//
//	service-vault serve        run (configuration from SV_* variables, README "Deployment")
//	service-vault healthcheck  probe GET /health on the local API; exit 0 or 1
//	service-vault admin bootstrap -email E
//	                           arm a new one-shot admin bootstrap (the same environment as serve)
//	service-vault admin bootstrap -connection ID [-fingerprint 16HEX]
//	                           show the connection waiting to become the first admin, or confirm it
//	service-vault table restore -from RESTORED -to TABLE [-other-keys] [-newer-point]
//	                           copy a restored backup back into the stack's table (README "Restoring the table")
//	service-vault version
package main

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	ssmtypes "github.com/aws/aws-sdk-go-v2/service/ssm/types"

	"github.com/vettid/vettid-relay/relayclient"
	"github.com/vettid/vettid-vault/vms/envelope"
	"github.com/vettid/vettid-vault/vms/suite"

	"github.com/vettid/service-vault/anchor"
	"github.com/vettid/service-vault/internal/api"
	"github.com/vettid/service-vault/internal/approval"
	"github.com/vettid/service-vault/internal/ballot"
	"github.com/vettid/service-vault/internal/connect"
	"github.com/vettid/service-vault/internal/keystore"
	"github.com/vettid/service-vault/internal/peer"
	"github.com/vettid/service-vault/internal/publish"
	"github.com/vettid/service-vault/internal/sealstore"
	"github.com/vettid/service-vault/internal/service"
	"github.com/vettid/service-vault/internal/signin"
	"github.com/vettid/service-vault/internal/store"
	"github.com/vettid/service-vault/internal/tlsid"
	"github.com/vettid/service-vault/internal/webhook"
	sdkwebhook "github.com/vettid/service-vault/sdk/go/webhook"
	"github.com/vettid/service-vault/vote"
)

// version is set at build time with -ldflags '-X main.version=...'.
var version = "dev"

func main() {
	flag.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(), "usage: service-vault serve [flags] | healthcheck | admin bootstrap -email E | admin bootstrap -connection ID [-fingerprint 16HEX] | table restore -from RESTORED -to TABLE [-other-keys] [-newer-point] | version\n")
	}
	flag.Parse()
	switch flag.Arg(0) {
	case "version":
		fmt.Println(version)
	case "serve":
		if err := serve(flag.Args()[1:]); err != nil {
			slog.Error("serve", "err", err)
			os.Exit(1)
		}
	case "admin":
		if err := admin(flag.Args()[1:], os.Stdout); err != nil {
			fmt.Fprintln(os.Stderr, "admin:", err)
			os.Exit(1)
		}
	case "table":
		if err := table(flag.Args()[1:], os.Stdout); err != nil {
			fmt.Fprintln(os.Stderr, "table:", err)
			os.Exit(1)
		}
	case "healthcheck":
		if err := healthcheck(os.Getenv("SV_LISTEN")); err != nil {
			fmt.Fprintln(os.Stderr, "unhealthy:", err)
			os.Exit(1)
		}
	default:
		flag.Usage()
		os.Exit(2)
	}
}

// Config is the daemon's configuration (README "Deployment").
type Config struct {
	RelayURL string
	Table    string
	// BallotsTable is the write-once copy of accepted ballots
	// (BALLOT-PROTOCOL §6); without it, vote requests are unsupported.
	BallotsTable string
	// Sigstore is the Sigstore instance votes are anchored in: staging or
	// production (BALLOT-PROTOCOL §3.3).
	Sigstore string
	// VotesURL is votes.vettid.org (or staging's); without it, proposals
	// can't be published, so none can be created.
	VotesURL      string
	KMSKeyID      string
	Listen        string
	WebhookURL    string
	ServiceName   string
	TLSName       string
	TLSPinParam   string
	APIKeyHashes  [][32]byte
	WebhookSecret []byte
	Profile       peer.Profile
	EmailLimits   []signin.Limit // SV_SIGNIN_LIMITS_EMAIL
	SourceLimits  []signin.Limit // SV_SIGNIN_LIMITS_SOURCE
	// ApprovalLimits limit creating approvals, per action
	// (SV_APPROVAL_LIMITS, default approval.DefaultCreateLimits).
	ApprovalLimits []signin.Limit
	// Admin approvals (MEMBER-SERVICE-PLAN §4.5).
	AdminBootstrapEmail string        // SV_ADMIN_BOOTSTRAP_EMAIL, normalized; "" for none
	AdminThreshold      int           // SV_ADMIN_THRESHOLD (m), default 1
	ApprovalTTL         time.Duration // SV_APPROVAL_TTL, default 24h (1h on staging)
	Channel             string        // SV_CHANNEL: staging | production (default)
	AllowNoPurpose      bool          // SV_APPROVAL_ALLOW_NO_PURPOSE, default false
	LongChallenges      bool          // SV_LONG_APPROVAL_CHALLENGES, default false
	// TestSignIns serves POST /v1/signins/unsigned (SV_TEST_SIGNINS, default
	// false): for test deployments only.
	TestSignIns bool
	// RecordKeyVersion is the lowest record key version to use
	// (SV_RECORD_KEY_VERSION, default 1; README "Rotating the record key").
	RecordKeyVersion uint32
	// AnchorSigner is the AnchorSigner function's unqualified ARN, in the
	// signer's own account (SV_ANCHOR_SIGNER; key protection, GC #7406):
	// with it, documents are published through the signer and this service
	// never holds the anchor key.
	AnchorSigner string
	// AnchorMovedParam is the SSM parameter that marks the anchor key as
	// moved to the signer (SV_ANCHOR_MOVED_PARAM). Once it exists, the
	// daemon refuses to start without AnchorSigner, and never reads the
	// anchor-key blob. Required with ballots unless AnchorSigner is set.
	AnchorMovedParam string
	// AnchorKey pins the anchor key: its SubjectPublicKeyInfo, DER
	// (SV_ANCHOR_KEY, standard base64, set by the owner). Required with
	// AnchorSigner: only this key is certified and listed, and every
	// answer and bundle of the signer is checked against it. Without the
	// signer, if set, the stored key must be this one.
	AnchorKey []byte
}

// anchorSignerARN is a Lambda function's unqualified ARN.
var anchorSignerARN = regexp.MustCompile(`^arn:aws[a-z-]*:lambda:[a-z0-9-]+:[0-9]{12}:function:[A-Za-z0-9_-]+$`)

// Bounds of the approval settings (chosen; not in the spec).
const (
	maxAdminThreshold = 64
	minApprovalTTL    = approval.RemindInterval
	maxApprovalTTL    = 7 * 24 * time.Hour
	// maxStagingApprovalTTL bounds an approval's life on the staging channel
	// (STAGING-TIME-SCALE N16; VAULT-MESSAGING 0.82.0 §10.4).
	maxStagingApprovalTTL = time.Hour
)

// Release channels (SV_CHANNEL).
const (
	ChannelStaging    = "staging"
	ChannelProduction = "production"
)

// configFromEnv reads and checks the SV_* variables.
func configFromEnv(getenv func(string) string) (*Config, error) {
	c := &Config{
		RelayURL: strings.TrimRight(getenv("SV_RELAY_URL"), "/"), Table: getenv("SV_TABLE"), BallotsTable: getenv("SV_BALLOTS_TABLE"), Sigstore: getenv("SV_SIGSTORE"), VotesURL: strings.TrimRight(getenv("SV_VOTES_URL"), "/"), KMSKeyID: getenv("SV_KMS_KEY_ID"),
		Listen: getenv("SV_LISTEN"), WebhookURL: getenv("SV_WEBHOOK_URL"), ServiceName: getenv("SV_SERVICE_NAME"),
		TLSName: getenv("SV_TLS_NAME"), TLSPinParam: getenv("SV_TLS_PIN_PARAM"), WebhookSecret: []byte(getenv("SV_WEBHOOK_SECRET")),
	}
	var missing []string
	for _, kv := range [][2]string{{"SV_RELAY_URL", c.RelayURL}, {"SV_TABLE", c.Table}, {"SV_KMS_KEY_ID", c.KMSKeyID},
		{"SV_LISTEN", c.Listen}, {"SV_WEBHOOK_URL", c.WebhookURL}, {"SV_SERVICE_NAME", c.ServiceName},
		{"SV_TLS_NAME", c.TLSName}, {"SV_TLS_PIN_PARAM", c.TLSPinParam}, {"SV_API_KEY_HASHES", getenv("SV_API_KEY_HASHES")},
		{"SV_WEBHOOK_SECRET", string(c.WebhookSecret)}} {
		if kv[1] == "" {
			missing = append(missing, kv[0])
		}
	}
	if len(missing) > 0 {
		return nil, fmt.Errorf("missing %s", strings.Join(missing, ", "))
	}
	if c.BallotsTable != "" && c.Sigstore != anchor.Staging && c.Sigstore != anchor.Production {
		return nil, errors.New("SV_SIGSTORE must be staging or production when SV_BALLOTS_TABLE is set")
	}
	if c.VotesURL != "" && (c.BallotsTable == "" || !strings.HasPrefix(c.VotesURL, "https://")) {
		return nil, errors.New("SV_VOTES_URL must be https, with SV_BALLOTS_TABLE")
	}
	if !strings.HasPrefix(c.WebhookURL, "https://") {
		return nil, errors.New("SV_WEBHOOK_URL must be https")
	}
	if len(c.WebhookSecret) < sdkwebhook.MinSecretLen {
		return nil, fmt.Errorf("SV_WEBHOOK_SECRET shorter than %d bytes", sdkwebhook.MinSecretLen)
	}
	var err error
	if c.APIKeyHashes, err = parseKeyHashes(getenv("SV_API_KEY_HASHES")); err != nil {
		return nil, err
	}
	if c.Profile, err = splitName(c.ServiceName); err != nil {
		return nil, err
	}
	if c.EmailLimits, err = signin.ParseLimits(getenv("SV_SIGNIN_LIMITS_EMAIL"), signin.DefaultEmailLimits); err != nil {
		return nil, fmt.Errorf("SV_SIGNIN_LIMITS_EMAIL: %w", err)
	}
	if c.SourceLimits, err = signin.ParseLimits(getenv("SV_SIGNIN_LIMITS_SOURCE"), signin.DefaultSourceLimits); err != nil {
		return nil, fmt.Errorf("SV_SIGNIN_LIMITS_SOURCE: %w", err)
	}
	if c.ApprovalLimits, err = signin.ParseLimits(getenv("SV_APPROVAL_LIMITS"), approval.DefaultCreateLimits); err != nil {
		return nil, fmt.Errorf("SV_APPROVAL_LIMITS: %w", err)
	}
	if v := strings.TrimSpace(getenv("SV_ADMIN_BOOTSTRAP_EMAIL")); v != "" {
		if c.AdminBootstrapEmail, err = connect.NormalizeEmail(v); err != nil {
			return nil, errors.New("SV_ADMIN_BOOTSTRAP_EMAIL: not an email address")
		}
	}
	c.AdminThreshold = 1
	if v := strings.TrimSpace(getenv("SV_ADMIN_THRESHOLD")); v != "" {
		if c.AdminThreshold, err = strconv.Atoi(v); err != nil || c.AdminThreshold < 1 || c.AdminThreshold > maxAdminThreshold {
			return nil, fmt.Errorf("SV_ADMIN_THRESHOLD: an integer from 1 to %d", maxAdminThreshold)
		}
	}
	c.Channel = ChannelProduction
	switch v := strings.TrimSpace(getenv("SV_CHANNEL")); v {
	case "", ChannelProduction:
	case ChannelStaging:
		c.Channel = v
	default:
		return nil, errors.New("SV_CHANNEL: staging or production")
	}
	c.ApprovalTTL = approval.DefaultTTL
	if c.Channel == ChannelStaging {
		c.ApprovalTTL = maxStagingApprovalTTL
	}
	if v := strings.TrimSpace(getenv("SV_APPROVAL_TTL")); v != "" {
		if c.ApprovalTTL, err = time.ParseDuration(v); err != nil || c.ApprovalTTL < minApprovalTTL || c.ApprovalTTL > maxApprovalTTL {
			return nil, fmt.Errorf("SV_APPROVAL_TTL: a duration from %v to %v", minApprovalTTL, maxApprovalTTL)
		}
		if c.Channel == ChannelStaging && c.ApprovalTTL > maxStagingApprovalTTL {
			return nil, fmt.Errorf("SV_APPROVAL_TTL: at most %v when SV_CHANNEL=staging", maxStagingApprovalTTL)
		}
	}
	switch v := strings.TrimSpace(getenv("SV_APPROVAL_ALLOW_NO_PURPOSE")); v {
	case "", "false":
	case "true":
		c.AllowNoPurpose = true
	default:
		return nil, errors.New("SV_APPROVAL_ALLOW_NO_PURPOSE: true or false")
	}
	// Off until the channel's member vaults carry VAULT-MESSAGING 0.82.0
	// (§10.4, "Older vaults"); chosen; not in the spec.
	switch v := strings.TrimSpace(getenv("SV_LONG_APPROVAL_CHALLENGES")); v {
	case "", "false":
	case "true":
		c.LongChallenges = true
	default:
		return nil, errors.New("SV_LONG_APPROVAL_CHALLENGES: true or false")
	}
	switch v := strings.TrimSpace(getenv("SV_TEST_SIGNINS")); v {
	case "", "false":
	case "true":
		c.TestSignIns = true
	default:
		return nil, errors.New("SV_TEST_SIGNINS: true or false")
	}
	c.RecordKeyVersion = 1
	if v := strings.TrimSpace(getenv("SV_RECORD_KEY_VERSION")); v != "" {
		n, err := strconv.ParseUint(v, 10, 32)
		if err != nil || n < 1 || n > sealstore.MaxVersion {
			return nil, fmt.Errorf("SV_RECORD_KEY_VERSION: an integer from 1 to %d", sealstore.MaxVersion)
		}
		c.RecordKeyVersion = uint32(n)
	}
	if err := approval.CheckServiceName(c.ServiceName); err != nil {
		return nil, fmt.Errorf("SV_SERVICE_NAME: %w", err)
	}
	c.AnchorSigner = strings.TrimSpace(getenv("SV_ANCHOR_SIGNER"))
	c.AnchorMovedParam = strings.TrimSpace(getenv("SV_ANCHOR_MOVED_PARAM"))
	if c.AnchorSigner != "" && (c.VotesURL == "" || !anchorSignerARN.MatchString(c.AnchorSigner)) {
		return nil, errors.New("SV_ANCHOR_SIGNER: a Lambda function's unqualified ARN, with SV_VOTES_URL")
	}
	if v := strings.TrimSpace(getenv("SV_ANCHOR_KEY")); v != "" {
		spki, err := base64.StdEncoding.DecodeString(v)
		if err != nil {
			return nil, errors.New("SV_ANCHOR_KEY: not standard base64")
		}
		if _, err := p256(spki); err != nil {
			return nil, fmt.Errorf("SV_ANCHOR_KEY: %w", err)
		}
		c.AnchorKey = spki
	}
	if c.AnchorSigner != "" && c.AnchorKey == nil {
		return nil, errors.New("SV_ANCHOR_KEY is required with SV_ANCHOR_SIGNER: the anchor key is pinned, never learned from the signer")
	}
	if c.BallotsTable != "" && c.AnchorSigner == "" && c.AnchorMovedParam == "" {
		// Without the marker's name, a moved key couldn't be told from one
		// never moved: fail closed.
		return nil, errors.New("SV_ANCHOR_MOVED_PARAM is required with SV_BALLOTS_TABLE unless SV_ANCHOR_SIGNER is set")
	}
	return c, nil
}

// parseKeyHashes parses comma-separated hex SHA-256 values.
func parseKeyHashes(s string) ([][32]byte, error) {
	var out [][32]byte
	for _, h := range strings.Split(s, ",") {
		h = strings.TrimSpace(h)
		if h == "" {
			continue
		}
		b, err := hex.DecodeString(h)
		if err != nil || len(b) != 32 {
			return nil, errors.New("SV_API_KEY_HASHES: not comma-separated hex SHA-256")
		}
		out = append(out, [32]byte(b))
	}
	if len(out) == 0 {
		return nil, errors.New("SV_API_KEY_HASHES: no key")
	}
	return out, nil
}

// splitName makes the service's account names from its display name: the
// first word is the first name and the rest the last name ("VettID
// Member Service" → "VettID" / "Member Service"), which members' apps
// join back as the connection's title (VAULT-MESSAGING §10.8).
func splitName(name string) (peer.Profile, error) {
	first, last, ok := strings.Cut(strings.TrimSpace(name), " ")
	last = strings.TrimSpace(last)
	if !ok || first == "" || last == "" {
		return peer.Profile{}, errors.New("SV_SERVICE_NAME must be at least two words (first name, last name)")
	}
	return peer.Profile{FirstName: first, LastName: last}, nil
}

// devFlags are local-development escape hatches; none is on by default.
type devFlags struct {
	awsEndpoint string // LocalStack: KMS, DynamoDB and SSM at this URL
	relayCA     string // PEM file of an extra CA for the relay (a dev relay's own CA)
}

func serve(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	var dev devFlags
	fs.StringVar(&dev.awsEndpoint, "dev-aws-endpoint", "", "local development only: send KMS, DynamoDB and SSM calls to this URL (LocalStack)")
	fs.StringVar(&dev.relayCA, "dev-relay-ca", "", "local development only: also trust this PEM CA for the relay")
	if err := fs.Parse(args); err != nil {
		return err
	}
	cfg, err := configFromEnv(os.Getenv)
	if err != nil {
		return err
	}
	log := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	slog.SetDefault(log)
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()

	ac, err := newAWSClients(ctx, dev.awsEndpoint)
	if err != nil {
		return err
	}
	sc := ac.ssm
	tbl := &store.Table{Client: ac.ddb, Name: cfg.Table}

	secrets, err := keystore.LoadOrCreate(ctx, &keystore.AWSKMS{Client: ac.kms}, cfg.KMSKeyID, tbl.Blobs(), keystore.SecretsName, newSecretsIfFresh(ctx, tbl.AnyRecord, func(ctx context.Context) (bool, error) { return tbl.AnyBlob(ctx, sealstore.KeyName) }))
	if err != nil {
		return fmt.Errorf("keystore: %w", err)
	}
	records, err := sealedStore(ctx, &keystore.AWSKMS{Client: ac.kms}, cfg.KMSKeyID, tbl.Blobs(), tbl.Peer(), tbl, tbl.AnyRecord, true, cfg.RecordKeyVersion, os.Getenv(sealstore.MigrateEnv) == "1", log)
	if err != nil {
		return err
	}
	keys, err := peer.KeysFromSeeds(secrets.Peer)
	if err != nil {
		return err
	}
	email, err := connect.NewEmailIndex(secrets.EmailPepper)
	if err != nil {
		return err
	}
	cert, pin, err := tlsid.Certificate(secrets.TLSKey, []string{cfg.TLSName, "localhost"}, time.Now(), 397*24*time.Hour)
	if err != nil {
		return err
	}
	publishPin := func(ctx context.Context) error {
		_, err := sc.PutParameter(ctx, &ssm.PutParameterInput{Name: aws.String(cfg.TLSPinParam), Value: aws.String(pin),
			Type: ssmtypes.ParameterTypeString, Overwrite: aws.Bool(true)})
		return err
	}
	if err := publishPin(ctx); err != nil {
		return fmt.Errorf("publish TLS pin: %w", err)
	}
	// Published again every hour: a stack update that touches the
	// parameter puts back its "unset", and the API's client would then
	// refuse to start until this task restarts.
	go func() {
		t := time.NewTicker(time.Hour)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				if err := publishPin(ctx); err != nil {
					log.Warn("publish TLS pin", "err", err.Error())
				}
			}
		}
	}()

	rc := relayclient.New(cfg.RelayURL, keys.Relay)
	if dev.relayCA != "" {
		hc, err := clientTrusting(dev.relayCA)
		if err != nil {
			return err
		}
		rc.HTTP = hc
	}
	sender := &webhook.Dispatcher{URL: cfg.WebhookURL, Secret: cfg.WebhookSecret}
	svc := &service.Service{Store: records, ServiceName: cfg.ServiceName, Log: log,
		Hooks:   &webhook.Outbox{Store: records, Kind: service.HookKind, Sender: sender, Log: log},
		Limiter: &signin.Limiter{Counters: tbl.Counters(), Email: cfg.EmailLimits, Source: cfg.SourceLimits}}
	bootKey := ""
	if cfg.AdminBootstrapEmail != "" {
		if bootKey, err = email.Key(cfg.AdminBootstrapEmail); err != nil {
			return errors.New("SV_ADMIN_BOOTSTRAP_EMAIL: not an email address")
		}
	}
	approvals := &approval.Manager{Store: records, Pager: records, ServiceName: cfg.ServiceName,
		Threshold: cfg.AdminThreshold, TTL: cfg.ApprovalTTL, LongChallenges: cfg.LongChallenges, AllowNoPurpose: cfg.AllowNoPurpose, BootstrapKey: bootKey, BoundConnection: svc.BoundConnection, Log: log,
		Rate:  &approval.RateLimit{Counters: tbl.Counters(), Limits: cfg.ApprovalLimits},
		Hooks: &webhook.Outbox{Store: records, Kind: approval.HookKind, Sender: sender, Log: log}}
	if err := approvals.Start(ctx); err != nil {
		return fmt.Errorf("approvals: %w", err)
	}
	svc.Approvals = approvals
	pc := peer.Config{Keys: keys, Relay: rc, RelayURL: cfg.RelayURL, Profile: cfg.Profile, Store: records,
		Events: svc, Log: log}
	var ballots *ballot.RecordStore
	signIK := func(label string, msg []byte) ([]byte, error) { return suite.Sign(keys.IK, label, msg) }
	if cfg.BallotsTable != "" {
		raw := &store.Ballots{Client: ac.ddb, Name: cfg.BallotsTable, Main: tbl}
		cs, err := ballotCopySeal(ctx, &keystore.AWSKMS{Client: ac.kms}, cfg.KMSKeyID, tbl.Blobs(), records, raw)
		var ck *errCopyKey
		switch {
		case errors.As(err, &ck):
			// Sign-ins and approvals go on; votes wait for the operator.
			log.Error("ballots off: "+ck.why, "alarm", "ballots_off")
		case err != nil:
			return err
		default:
			ballots = &ballot.RecordStore{Records: records, Copy: &ballot.SealedCopy{Inner: raw, Seal: cs.Seal, Open: cs.Open}, Log: log}
			pc.Votes = &ballot.Box{Store: ballots, Sign: signIK, Log: log}
		}
	}
	if restored, err := tbl.Restored(ctx); err != nil {
		return fmt.Errorf("restore marker: %w", err)
	} else if restored {
		pc.AfterRestore = tbl.ClearRestored
	}
	rebuild, err := ballotsRebuild(ctx, tbl, pc.AfterRestore != nil, ballots != nil, time.Now())
	if err != nil {
		return err
	}
	p, err := peer.New(pc)
	if err != nil {
		return err
	}
	svc.Peer = p
	var proposals api.Proposals
	var anchorInfo *api.AnchorKey
	// Member sends run under their own context: they go on through the
	// HTTP drain at shutdown, which then waits for them (bounded).
	sendsCtx, stopSends := context.WithCancel(context.Background())
	defer stopSends()
	waitSends := func() {}
	stopQueueing := func() {}
	if ballots != nil {
		// Publishing (BALLOT-PROTOCOL §3.3) needs SV_VOTES_URL; without it,
		// creating a proposal answers publication_not_configured.
		ls := &publish.LambdaSigner{Client: ac.lambda, FunctionARN: cfg.AnchorSigner}
		as, err := setupAnchor(ctx, cfg, ls, ac.ssm, &keystore.AWSKMS{Client: ac.kms}, tbl.Blobs())
		if err != nil {
			return err
		}
		if as.signer != nil {
			go watchSigner(ctx, ls, as.spki, log)
		}
		// Only the pinned key (or the stored one, before the signer) is
		// certified.
		h := sha256.Sum256(as.spki)
		cert, err := signIK(vote.LabelAnchorKey, h[:])
		if err != nil {
			return err
		}
		anchorInfo = &api.AnchorKey{Key: as.spki, Cert: cert, IK: keys.IKPublic(), Sigstore: cfg.Sigstore}
		mgr := &ballot.Manager{Store: ballots, Sign: signIK, IK: keys.IKPublic(), Roster: p, Sender: p, Background: sendsCtx,
			Catcher: p, Approvals: approvals, NewID: envelope.NewULID, Now: time.Now, Log: log}
		waitSends, stopQueueing = mgr.Wait, mgr.StopSends
		approvals.EligibleCount = func(context.Context) (int, error) { return len(p.Eligible()), nil }
		approvals.ProposalTitle = func(ctx context.Context, id string) (string, bool, error) {
			// The document alone: the members aren't read for a title.
			pr, err := ballots.ProposalDocument(ctx, id)
			if err != nil || pr == nil {
				return "", false, err
			}
			return pr.Title, true, nil
		}
		if cfg.VotesURL != "" {
			mgr.Timestamp = func(bundle json.RawMessage, doc []byte) (int64, error) {
				return anchor.TimestampTime(cfg.Sigstore, bundle, doc)
			}
			mgr.AuthorityTime = authorityTime(as.anc, cfg.Sigstore)
			mgr.Publisher = votesPublisher(cfg.VotesURL, as, records, mgr, log)
		}
		if rebuild {
			// The table was restored: ballots it lost are in the copy (§6).
			n, err := mgr.RebuildAll(ctx)
			if err != nil {
				return fmt.Errorf("rebuild ballots after the restore: %w", err)
			}
			if err := tbl.ClearBallotsRebuild(ctx); err != nil {
				return fmt.Errorf("ballots rebuild marker: %w", err)
			}
			log.Info("ballots rebuilt after the restore", "count", n)
		}
		proposals = mgr
	}
	approvals.Peer = p

	srv := &http.Server{
		Addr: cfg.Listen,
		Handler: (&api.Server{TestSignIns: cfg.TestSignIns, Keys: cfg.APIKeyHashes, Email: email, Invites: svc.Invites(), SignIns: svc.SignIns(),
			Approvals: approvals, Proposals: proposals, AnchorKey: anchorInfo, Log: log}).Handler(),
		TLSConfig:         tlsid.ServerConfig(cert),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       2 * time.Minute,
		ErrorLog:          slog.NewLogLogger(log.Handler(), slog.LevelWarn),
	}
	// The heartbeat tells the restore that the service is running
	// (README "Restoring the table").
	// A task that can't write it for heartbeatStopAfter stops, so that a
	// restore never runs beside it unnoticed.
	start, err := firstHeartbeat(ctx, tbl.Heartbeat, time.Now())
	if err != nil {
		return err
	}
	hbErr := make(chan error, 1)
	go func() {
		t := time.NewTicker(store.HeartbeatInterval)
		defer t.Stop()
		if err := heartbeat(ctx, tbl.Heartbeat, start, t.C, log); err != nil {
			hbErr <- err
		}
	}()
	peerErr := make(chan error, 1)
	go func() { peerErr <- p.Run(ctx) }()
	go approvals.Run(ctx)
	go svc.Hooks.Run(ctx)
	go approvals.Hooks.Run(ctx)
	srvErr := make(chan error, 1)
	go func() { srvErr <- srv.ListenAndServeTLS("", "") }()
	warnTestMode(log, cfg)
	log.Info("serving", "version", version, "listen", cfg.Listen, "mailbox", keys.Mailbox(), "test_signins", cfg.TestSignIns)

	var runErr error
	select {
	case <-ctx.Done():
	case err := <-peerErr:
		runErr = fmt.Errorf("peer: %w", err)
	case err := <-srvErr:
		runErr = fmt.Errorf("api: %w", err)
	case runErr = <-hbErr:
	}
	stop()
	sctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	_ = srv.Shutdown(sctx)
	// The member sends: nothing more is queued, and those running get at
	// most sendsGrace, within the 20 seconds above, so that the heartbeat
	// is still cleared below. Then they are stopped and given
	// sendsStopWait to return, so that none still writes the peer's state
	// after "stopped".
	stopQueueing()
	sendsDone := make(chan struct{})
	go func() { waitSends(); close(sendsDone) }()
	select {
	case <-sendsDone:
	case <-sctx.Done():
	case <-time.After(sendsGrace):
	}
	stopSends()
	select {
	case <-sendsDone:
	default:
		returned := true
		select {
		case <-sendsDone:
		case <-time.After(sendsStopWait):
			returned = false
		}
		log.Warn("member sends stopped at shutdown: members not yet sent learn of them as BALLOT-PROTOCOL §4.2, §8.3 and §10 say",
			"all_returned", returned)
	}
	if runErr == nil {
		if err := <-peerErr; err != nil && !errors.Is(err, context.Canceled) {
			runErr = fmt.Errorf("peer: %w", err)
		}
	}
	hctx, hcancel := context.WithTimeout(context.Background(), heartbeatWriteTimeout)
	defer hcancel()
	if err := tbl.ClearHeartbeat(hctx); err != nil {
		log.Warn("clear heartbeat", "err", err.Error())
	}
	log.Info("stopped")
	return runErr
}

// The heartbeat's limits. A restore takes the service for stopped once
// its last heartbeat is store.HeartbeatStale (2 minutes) old, so the
// daemon must have stopped by then. It stops once heartbeatStopAfter has
// passed since its last good write; each write gives up after
// heartbeatWriteTimeout. At worst the stop starts at about 70 seconds
// (a tick at 60 seconds plus a write timing out) and shutdown takes at
// most 32 more (the HTTP drain and the member sends' grace within 20,
// sendsStopWait, then the heartbeat's clear), inside the 2 minutes,
// whatever DynamoDB does. (The wait for the peer to return is not bounded
// here; it returns once ctx is done.)
const (
	heartbeatStopAfter    = store.HeartbeatStale / 2
	heartbeatWriteTimeout = 10 * time.Second
	// sendsGrace is how long a shutdown waits for member sends to end.
	sendsGrace = 10 * time.Second
	// sendsStopWait is how long it then waits for them to return, once
	// stopped.
	sendsStopWait = 2 * time.Second
)

// firstHeartbeat writes the first heartbeat, stamped now, under
// heartbeatWriteTimeout. The stop rule counts from now, the time the item
// carries, not from when the write returned.
func firstHeartbeat(ctx context.Context, write func(context.Context, time.Time) error, now time.Time) (time.Time, error) {
	wctx, cancel := context.WithTimeout(ctx, heartbeatWriteTimeout)
	defer cancel()
	if err := write(wctx, now); err != nil {
		return time.Time{}, fmt.Errorf("heartbeat: %w", err)
	}
	return now, nil
}

// heartbeat writes the heartbeat at every tick until ctx ends, starting
// from a good write at start. It returns an error, for the daemon to
// stop, at the first failed write heartbeatStopAfter or more after the
// last good one (times are the ticks').
func heartbeat(ctx context.Context, write func(context.Context, time.Time) error, start time.Time, tick <-chan time.Time, log *slog.Logger) error {
	lastOK := start
	for {
		var at time.Time
		select {
		case <-ctx.Done():
			return nil
		case at = <-tick:
		}
		wctx, cancel := context.WithTimeout(ctx, heartbeatWriteTimeout)
		err := write(wctx, at)
		cancel()
		if err == nil {
			lastOK = at
			continue
		}
		if ctx.Err() != nil {
			return nil
		}
		since := at.Sub(lastOK)
		if since < heartbeatStopAfter {
			log.Warn("heartbeat", "err", err.Error(), "since_ok", since.Round(time.Second).String())
			continue
		}
		return fmt.Errorf("heartbeat: no write succeeded for %s: %w", since.Round(time.Second), err)
	}
}

// awsClients are the AWS clients the daemon uses.
type awsClients struct {
	ddb    *dynamodb.Client
	kms    *kms.Client
	ssm    *ssm.Client
	lambda *lambda.Client // the anchor signer, in its own account
}

// newAWSClients loads the default AWS configuration; endpoint, when set,
// sends every call there (LocalStack, local development only).
func newAWSClients(ctx context.Context, endpoint string) (*awsClients, error) {
	awsCfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		return nil, fmt.Errorf("aws config: %w", err)
	}
	ep := func(u *string) {
		if endpoint != "" {
			*u = endpoint
		}
	}
	return &awsClients{
		ddb: dynamodb.NewFromConfig(awsCfg, func(o *dynamodb.Options) { setEndpoint(&o.BaseEndpoint, ep) }),
		kms: kms.NewFromConfig(awsCfg, func(o *kms.Options) { setEndpoint(&o.BaseEndpoint, ep) }),
		ssm: ssm.NewFromConfig(awsCfg, func(o *ssm.Options) { setEndpoint(&o.BaseEndpoint, ep) }),
		// The signer's retries are this service's (the claim makes them a
		// resume), so the SDK makes one attempt.
		lambda: lambda.NewFromConfig(awsCfg, func(o *lambda.Options) {
			setEndpoint(&o.BaseEndpoint, ep)
			o.RetryMaxAttempts = 1
		}),
	}, nil
}

// table runs `service-vault table restore -from RESTORED -to TABLE`, the
// operator's restore path (README "Restoring the table"). DynamoDB
// restores a backup into a new table; this makes the stack's table hold
// exactly that table's items. It runs from the operator's machine with
// their AWS credentials, while the service is stopped; it checks first
// that RESTORED is a finished restore of TABLE with the same keys and
// that no task has written a heartbeat lately.
func table(args []string, out io.Writer) error {
	const usage = "usage: service-vault table restore -from RESTORED -to TABLE [-other-keys] [-newer-point]"
	if len(args) == 0 || args[0] != "restore" {
		return errors.New(usage)
	}
	fs := flag.NewFlagSet("table restore", flag.ContinueOnError)
	from := fs.String("from", "", "the table DynamoDB restored the backup into")
	to := fs.String("to", "", "the stack's table (vettid-service-vault-<env>); its items are replaced")
	newerPoint := fs.Bool("newer-point", false, "restore although RESTORED's point in time lies between an earlier restore's and when it was done: members' vaults will suspend every connection (README \"Restoring the table\")")
	otherKeys := fs.Bool("other-keys", false, "TABLE holds keys other than RESTORED's (the daemon started on it after the table was lost): replace them")
	awsEndpoint := fs.String("dev-aws-endpoint", "", "local development only: send DynamoDB calls to this URL (LocalStack)")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	if fs.NArg() > 0 || *from == "" || *to == "" {
		return errors.New(usage)
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	ac, err := newAWSClients(ctx, *awsEndpoint)
	if err != nil {
		return err
	}
	dst := &store.Table{Client: ac.ddb, Name: *to}
	point, err := dst.CheckRestore(ctx, *from, *otherKeys, *newerPoint, time.Now())
	if err != nil {
		return err
	}
	start := time.Now()
	// The heartbeat again before anything is deleted: a task started
	// during the copy stops it there.
	recheck := func(ctx context.Context) error { return dst.CheckTarget(ctx, *from, true, time.Now()) }
	written, deleted, err := dst.CopyFrom(ctx, *from, recheck)
	fmt.Fprintf(out, "%d items written, %d deleted, in %s\n", written, deleted, time.Since(start).Round(time.Second))
	if err != nil {
		return err
	}
	// The next start reconnects every connection (README "Restoring the
	// table").
	if err := dst.RecordRestore(ctx, point, time.Now()); err != nil {
		return err
	}
	return dst.MarkRestored(ctx, time.Now())
}

// errNoSecrets: the admin command found no keystore; it never makes one.
var errNoSecrets = errors.New("the service vault has no keys yet: run serve first")

// admin runs `service-vault admin bootstrap -email E`: it arms a new
// one-shot admin bootstrap in the store, the operator's recovery when the
// admin set has become empty (README "Admin approvals"). It runs with the
// same environment as serve (it needs the table and the KMS key to
// compute the email's index key) and refuses while the set is not empty.
// The running daemon picks the armed bootstrap up within seconds.
func admin(args []string, out io.Writer) error {
	if len(args) > 0 && args[0] == "reseal-blobs" {
		return adminReseal(args[1:], out)
	}
	if len(args) == 0 || args[0] != "bootstrap" {
		return errors.New(adminUsage)
	}
	fs := flag.NewFlagSet("admin bootstrap", flag.ContinueOnError)
	conn := fs.String("connection", "", "the connection waiting to become the first admin (shown when it connects): with -fingerprint, confirms it; alone, shows it")
	fprint := fs.String("fingerprint", "", "the 16 hex digits of the fingerprint of its identity key, which you have checked with the member out of band")
	addr := fs.String("email", "", "the email of the member to become the first admin; their connection must come from an invitation with a verified email")
	awsEndpoint := fs.String("dev-aws-endpoint", "", "local development only: send KMS and DynamoDB calls to this URL (LocalStack)")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	if fs.NArg() > 0 || (*conn != "") == (*addr != "") || *fprint != "" && *conn == "" {
		return errors.New(adminUsage)
	}
	if *addr != "" {
		if _, err := connect.NormalizeEmail(*addr); err != nil {
			return errors.New("-email: not an email address")
		}
	}
	cfg, err := configFromEnv(os.Getenv)
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	ac, err := newAWSClients(ctx, *awsEndpoint)
	if err != nil {
		return err
	}
	tbl := &store.Table{Client: ac.ddb, Name: cfg.Table}
	kc := &keystore.AWSKMS{Client: ac.kms}
	records, err := sealedStore(ctx, kc, cfg.KMSKeyID, tbl.Blobs(), tbl.Peer(), tbl, tbl.AnyRecord, false, cfg.RecordKeyVersion, false, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		return err
	}
	if *conn != "" {
		return confirmBootstrap(ctx, records, *conn, *fprint, out)
	}
	return armBootstrap(ctx, kc, cfg.KMSKeyID, tbl.Blobs(), records, *addr, out)
}

const adminUsage = "usage: service-vault admin bootstrap -email E | -connection ID [-fingerprint 16HEX]\n" +
	"       service-vault admin reseal-blobs"

// adminReseal moves every sealed blob of the keystore to its encryption
// context (key protection, GC #7406 §7: the code is step 1, running it
// step 2). It is owner-run, as a
// one-off task with the service stopped, in the same environment as
// serve. It prints the names it moved and those already moved, never
// what they hold.
func adminReseal(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("admin reseal-blobs", flag.ContinueOnError)
	awsEndpoint := fs.String("dev-aws-endpoint", "", "local development only: send KMS and DynamoDB calls to this URL (LocalStack)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() > 0 {
		return errors.New(adminUsage)
	}
	cfg, err := configFromEnv(os.Getenv)
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	ac, err := newAWSClients(ctx, *awsEndpoint)
	if err != nil {
		return incomplete(out, err)
	}
	tbl := &store.Table{Client: ac.ddb, Name: cfg.Table}
	// Only with the service stopped, as table restore asks.
	at, ok, err := tbl.LastHeartbeat(ctx)
	if err != nil {
		return incomplete(out, err)
	}
	if ok && time.Since(at) < store.HeartbeatStale {
		return incomplete(out, fmt.Errorf("the service is running (heartbeat %s ago): stop it first", time.Since(at).Round(time.Second)))
	}
	return resealBlobs(ctx, &keystore.AWSKMS{Client: ac.kms}, cfg.KMSKeyID, tbl.Blobs(), out)
}

// incomplete says the re-seal isn't done, and returns err.
func incomplete(out io.Writer, err error) error {
	fmt.Fprintln(out, "INCOMPLETE: run it again once the error is fixed")
	return err
}

// resealBlobs runs keystore.Reseal and reports it.
func resealBlobs(ctx context.Context, kc keystore.KMS, keyID string, blobs keystore.Blobs, out io.Writer) error {
	rep, err := keystore.Reseal(ctx, kc, keyID, blobs)
	if rep != nil {
		fmt.Fprintf(out, "resealed %d: %s\nalready with their context %d: %s\nleft for deletion %d: %s\n",
			len(rep.Resealed), strings.Join(rep.Resealed, " "), len(rep.Already), strings.Join(rep.Already, " "),
			len(rep.Left), strings.Join(rep.Left, " "))
	}
	if err != nil {
		return incomplete(out, err)
	}
	return nil
}

// confirmBootstrap shows the connection waiting to become the first admin,
// or, given its identity key's fingerprint, confirms it. The operator
// checks the fingerprint with the member out of band (the member's vault
// key fingerprint, VAULT-MESSAGING §10.8) before confirming.
func confirmBootstrap(ctx context.Context, st peer.Store, conn, fp string, out io.Writer) error {
	m := &approval.Manager{Store: st, Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	if fp == "" {
		w, err := m.BootstrapWaiting(ctx)
		if err != nil {
			return err
		}
		if w == nil {
			return errors.New("no connection is waiting for confirmation")
		}
		fmt.Fprintf(out, "connection: %s\nconnected: %s\ninvitation: %s\nidentity key fingerprint: %s\n", w.ConnectionID,
			w.ConnectedAt.UTC().Format("2006-01-02 15:04:05 UTC"), w.InviteID, w.Fingerprint)
		fmt.Fprintln(out, "ask the member out of band whether they connected at that time from the invitation you sent, and check the fingerprint with them, then confirm with -connection ID -fingerprint 16HEX")
		return nil
	}
	if err := m.ConfirmBootstrap(ctx, conn, fp); err != nil {
		return err
	}
	fmt.Fprintln(out, "admin bootstrap confirmed: the running service makes the connection the first admin within seconds")
	return nil
}

// armBootstrap computes the email's index key under the service vault's
// pepper and arms the bootstrap for it.
func armBootstrap(ctx context.Context, kc keystore.KMS, keyID string, blobs keystore.Blobs, st peer.Store, addr string, out io.Writer) error {
	secrets, err := keystore.LoadOrCreate(ctx, kc, keyID, blobs, keystore.SecretsName,
		func() (*keystore.Secrets, error) { return nil, errNoSecrets })
	if err != nil {
		return fmt.Errorf("keystore: %w", err)
	}
	idx, err := connect.NewEmailIndex(secrets.EmailPepper)
	if err != nil {
		return err
	}
	key, err := idx.Key(addr)
	if err != nil {
		return errors.New("-email: not an email address")
	}
	m := &approval.Manager{Store: st, Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	if err := m.ArmBootstrap(ctx, key); err != nil {
		if errors.Is(err, approval.ErrAdminsExist) {
			return errors.New("the admin set is not empty: a bootstrap is armed only while it is empty")
		}
		return err
	}
	fmt.Fprintln(out, "admin bootstrap armed: the next connection bound to this email (from an invitation with a verified email) waits for your confirmation, then becomes the first admin, once")
	return nil
}

func setEndpoint(dst **string, f func(*string)) {
	var u string
	f(&u)
	if u != "" {
		*dst = aws.String(u)
	}
}

// clientTrusting returns an HTTP client that also trusts the CA in a PEM
// file.
func clientTrusting(path string) (*http.Client, error) {
	pem, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	pool, err := x509.SystemCertPool()
	if err != nil {
		pool = x509.NewCertPool()
	}
	if !pool.AppendCertsFromPEM(pem) {
		return nil, errors.New("dev-relay-ca: no certificate")
	}
	t := http.DefaultTransport.(*http.Transport).Clone()
	t.TLSClientConfig = &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
	return &http.Client{Transport: t, Timeout: 60 * time.Second}, nil
}

// healthcheck probes GET /health on the local API. The connection goes
// to the loopback address only, so the certificate is not checked: the
// probe asks whether this process serves, not who it is.
func healthcheck(listen string) error {
	if listen == "" {
		return errors.New("SV_LISTEN not set")
	}
	_, port, err := net.SplitHostPort(listen)
	if err != nil {
		return err
	}
	c := &http.Client{Timeout: 3 * time.Second, Transport: &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS13}, //nolint:gosec // loopback only
	}}
	resp, err := c.Get("https://" + net.JoinHostPort("127.0.0.1", port) + "/health")
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("status %d", resp.StatusCode)
	}
	return nil
}

// authorityTime is the ballot manager's and the publisher's AuthorityTime:
// the timestamp authority's verified time (BALLOT-PROTOCOL §7, 0.13.12),
// never this clock's.
func authorityTime(anc *anchor.Anchorer, instance string) func(context.Context) (int64, error) {
	return func(ctx context.Context) (int64, error) { return anchor.AuthorityTime(ctx, anc, instance) }
}

// votesPublisher is the ballot manager's publisher: its results checked by
// the manager's Timestamp, its re-anchors waiting on its AuthorityTime.
// With the signer, the signer anchors and uploads; this service keeps
// the bundles and reads the site (its Client).
func votesPublisher(url string, as *anchorSetup, records peer.Store, mgr *ballot.Manager, log *slog.Logger) *publish.Publisher {
	p := &publish.Publisher{URL: url, Client: anchor.Client(time.Minute), Records: records,
		Timestamp: mgr.Timestamp, AuthorityTime: mgr.AuthorityTime, Log: log}
	if as.signer != nil {
		p.Signer, p.AnchorKey = as.signer, as.spki
	} else {
		p.Anchor = as.anc
	}
	return p
}

// recordKinds is every kind the service vault stores.
func recordKinds() []string {
	return slices.Concat(peer.Kinds(), service.Kinds(), approval.Kinds(), ballot.Kinds(), publish.Kinds())
}

// errKeysLost: a key is missing from a table that holds records. A new
// one would leave the records unreadable (the record key) or the
// service's identity replaced (the secrets), so the start stops for the
// operator (README "Restoring the table").
var errKeysLost = errors.New("the table holds records but no keys: restore the table from a backup")

// newSecretsIfFresh makes the service vault's secrets only for a new
// deployment: a table with no records and no version of the record key
// (the start makes the secrets first).
func newSecretsIfFresh(ctx context.Context, anyRecord func(context.Context) ([]byte, bool, error), anyRecordKey func(context.Context) (bool, error)) func() (*keystore.Secrets, error) {
	return func() (*keystore.Secrets, error) {
		if has, err := anyRecordKey(ctx); err != nil || has {
			if err == nil {
				err = errKeysLost
			}
			return nil, err
		}
		if _, has, err := anyRecord(ctx); err != nil || has {
			if err == nil {
				err = errKeysLost
			}
			return nil, err
		}
		return keystore.NewSecrets()
	}
}

// ballotCopySeal returns the sealing of the write-once ballot copy, under
// a key of its own (keystore.BallotCopyKeyName) that the record key's
// rotation doesn't touch, and ties that key to the copy: the copy holds a
// key-check item (an HMAC under the key, written once), so a key that
// isn't the one its ballots are under is found at the start. A copy
// holding ballots under a lost key can't be read, so no new key is made
// while proposals exist or the copy has a key check or any ballot; a copy
// from before the check gets its first check only under a key that opens
// one of its ballots. Such a start, or a key that doesn't match the
// check, is errCopyKey, and the daemon runs with ballots off rather than
// not at all.
func ballotCopySeal(ctx context.Context, kc keystore.KMS, keyID string, blobs keystore.Blobs, records peer.Store, cp scannableCopy) (*sealstore.Store, error) {
	rk, err := keystore.LoadOrCreate(ctx, kc, keyID, blobs, keystore.BallotCopyKeyName, func() (*sealstore.RecordKey, error) {
		props, err := records.Load(ctx, ballot.KindProposal)
		if err != nil {
			return nil, err
		}
		checks, err := cp.List(ctx, copyKeyCheckID)
		if err != nil {
			return nil, err
		}
		if len(props) > 0 || len(checks) > 0 {
			return nil, &errCopyKey{"the ballot copy's key is missing while proposals or copied ballots exist: restore it from a backup of the table"}
		}
		// A copy from before the key check has ballots but no check.
		if _, _, ok, err := cp.Any(ctx, copyKeyCheckID); err != nil {
			return nil, err
		} else if ok {
			return nil, &errCopyKey{"the ballot copy's key is missing while copied ballots exist: restore it from a backup of the table"}
		}
		return sealstore.NewRecordKey()
	})
	if err != nil {
		var ck *errCopyKey
		if errors.As(err, &ck) {
			return nil, ck
		}
		return nil, fmt.Errorf("keystore: %w", err)
	}
	defer clear(rk.Key)
	mac := hmac.New(sha256.New, rk.Key)
	mac.Write([]byte("vettid/ballot-copy-key-check/1"))
	check := mac.Sum(nil)
	ss, err := sealstore.New(nil, map[uint32][]byte{1: rk.Key}, 1, false)
	if err != nil {
		return nil, err
	}
	checks, err := cp.List(ctx, copyKeyCheckID)
	if err != nil {
		return nil, fmt.Errorf("ballot copy key check: %w", err)
	}
	if len(checks) == 0 {
		// The first check: the key must open a ballot the copy holds from
		// before the check, if any.
		pid, it, ok, err := cp.Any(ctx, copyKeyCheckID)
		if err != nil {
			return nil, fmt.Errorf("ballot copy key check: %w", err)
		}
		if ok {
			if _, err := ss.Open(ballot.KindBallot, ballot.BallotID(pid, it.Tag), it.Data); err != nil {
				return nil, &errCopyKey{"the ballot copy's key doesn't open its ballots: restore the keystore's ballot-copy-key from a backup of the table"}
			}
		}
	}
	stored, err := cp.PutOnce(ctx, copyKeyCheckID, []byte{0}, check, nil)
	if err != nil {
		return nil, fmt.Errorf("ballot copy key check: %w", err)
	}
	if !hmac.Equal(stored, check) {
		return nil, &errCopyKey{"the ballot copy's key isn't the one its ballots are under: restore the keystore's ballot-copy-key from a backup of the table"}
	}
	// The guarded write's permission (a transaction that checks the main
	// table) must be there from the start, not found at the first cast. The
	// guard names a record that doesn't exist, so nothing is written: the
	// answer is ErrGuard. The item, were it ever written, is in the key
	// check's partition, which no proposal uses.
	_, err = cp.PutOnce(ctx, copyKeyCheckID, []byte{1}, []byte{1}, &ballot.Guard{Kind: "_guard_check", ID: "none", Version: 1})
	if err != nil && !errors.Is(err, ballot.ErrGuard) {
		return nil, fmt.Errorf("ballot copy guarded write check: %w", err)
	}
	return ss, nil
}

// scannableCopy is the ballot copy with a way to find any ballot in it
// (store.Ballots).
type scannableCopy interface {
	ballot.Copy
	Any(ctx context.Context, skip string) (proposalID string, it ballot.CopyItem, ok bool, err error)
}

// copyKeyCheckID is the copy's partition for its key check: not a
// proposal id (those are ULIDs).
const copyKeyCheckID = "_copy_key"

// errCopyKey is a ballot copy whose key is missing or not its own.
type errCopyKey struct{ why string }

func (e *errCopyKey) Error() string { return e.why }

// errNoKey: a version of the record key that is not in the keystore.
var errNoKey = errors.New("no such record key")

// sealedStore returns the record store sealed under the record key
// (internal/sealstore). The version in use is the table's: the highest
// of version (SV_RECORD_KEY_VERSION, the operator's minimum), the
// version a record of the table is sealed under, and any later version
// in the keystore. So a deploy that leaves the setting out, a task
// definition from before a rotation (a rollback, an admin run) and a
// lowered setting all use the table's current key.
//
// Only the daemon (create) makes a version, and only:
//   - over a table with no records (a new deployment);
//   - as a rotation: the previous version exists (README "Rotating the
//     record key"). The start reseals every record under the new
//     version. The older versions are deleted at a later start that
//     finds them, after it reseals what was written under them in the
//     meantime (a process that read the version before the rotation,
//     such as an admin run);
//   - with migrate (the operator's SV_RECORD_SEAL_MIGRATE=1, for the
//     deploy that upgrades a deployment from before sealing) over
//     unsealed records: the start seals them in place.
//
// A start cut short goes on: the next one reseals what is left.
func sealedStore(ctx context.Context, kc keystore.KMS, keyID string, blobs keystore.Blobs, inner peer.Store, pages sealstore.Pager, anyRecord func(context.Context) ([]byte, bool, error), create bool, version uint32, migrate bool, log *slog.Logger) (*sealstore.Store, error) {
	sample, hasRecords, err := anyRecord(ctx)
	if err != nil {
		return nil, err
	}
	version = max(version, min(sealstore.VersionOf(sample), sealstore.MaxVersion))
	for version < sealstore.MaxVersion {
		_, err := blobs.Get(ctx, sealstore.KeyNameOf(version+1))
		if errors.Is(err, keystore.ErrNotFound) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("keystore: %w", err)
		}
		version++
	}
	keys := map[uint32][]byte{}
	defer func() {
		for _, k := range keys {
			clear(k)
		}
	}()
	// The older versions still kept: those just below, down to the first
	// one missing (all of them are deleted together).
	var older []uint32
	for v := version - 1; v >= 1; v-- {
		rk, err := keystore.LoadOrCreate(ctx, kc, keyID, blobs, sealstore.KeyNameOf(v), func() (*sealstore.RecordKey, error) { return nil, errNoKey })
		if errors.Is(err, errNoKey) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("keystore: %w", err)
		}
		keys[v] = rk.Key
		older = append(older, v)
	}
	made := false
	rk, err := keystore.LoadOrCreate(ctx, kc, keyID, blobs, sealstore.KeyNameOf(version), func() (*sealstore.RecordKey, error) {
		switch {
		case !create:
			return nil, errors.New("no record key: start the daemon first")
		case !hasRecords:
		case keys[version-1] != nil:
		case migrate && sealstore.VersionOf(sample) == 0:
		default:
			if _, err := blobs.Get(ctx, sealstore.KeyNameOf(version-2)); version > 2 && err == nil {
				return nil, fmt.Errorf("SV_RECORD_KEY_VERSION %d skips a version: raise it by one", version)
			}
			return nil, errKeysLost
		}
		made = true
		return sealstore.NewRecordKey()
	})
	if err != nil {
		return nil, fmt.Errorf("keystore: %w", err)
	}
	keys[version] = rk.Key
	st, err := sealstore.New(inner, keys, version, migrate)
	if err != nil {
		return nil, err
	}
	st.Pages = pages
	if !create || (!migrate && len(older) == 0) {
		return st, nil
	}
	if err := st.Reseal(ctx, recordKinds()); err != nil {
		return nil, fmt.Errorf("seal records: %w", err)
	}
	st.Legacy = false
	if migrate {
		log.Warn("records sealed: remove " + sealstore.MigrateEnv)
	}
	if made && len(older) > 0 {
		log.Warn("record key version made, records resealed: start again to retire the older versions", "version", version)
		return st, nil
	}
	for _, v := range slices.Backward(older) { // lowest first: what is left stays just below
		if err := blobs.Delete(ctx, sealstore.KeyNameOf(v)); err != nil {
			return nil, fmt.Errorf("keystore: retire record key %d: %w", v, err)
		}
	}
	if len(older) > 0 {
		log.Warn("record key rotated", "version", version, "retired", len(older))
	}
	return st, nil
}

// rebuildMarkers is the table's ballots rebuild marker (store.Table).
type rebuildMarkers interface {
	MarkBallotsRebuild(ctx context.Context, now time.Time) error
	BallotsRebuild(ctx context.Context) (bool, error)
}

// ballotsRebuild reports whether this start puts back the ballots a
// restore lost. After a restore with ballots off, the restore marker
// still goes once the reconnects are sent, so the rebuild is kept for
// later in its own marker; the start that has ballots on rebuilds and
// then clears it.
func ballotsRebuild(ctx context.Context, m rebuildMarkers, restored, ballotsOn bool, now time.Time) (bool, error) {
	if !ballotsOn {
		if restored {
			if err := m.MarkBallotsRebuild(ctx, now); err != nil {
				return false, fmt.Errorf("ballots rebuild marker: %w", err)
			}
		}
		return false, nil
	}
	if restored {
		return true, nil
	}
	pending, err := m.BallotsRebuild(ctx)
	if err != nil {
		return false, fmt.Errorf("ballots rebuild marker: %w", err)
	}
	return pending, nil
}

// warnTestMode says at start that a test-only setting is on.
func warnTestMode(log *slog.Logger, cfg *Config) {
	if cfg.TestSignIns {
		log.Warn("unsigned sign-ins enabled: test deployments only")
	}
}

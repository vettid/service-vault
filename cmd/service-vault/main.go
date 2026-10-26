// Command service-vault is the VettID service vault: the component an
// application runs to connect with VettID members. It is a VMS v2 peer on
// the relay (VAULT-MESSAGING §6.4, §10.4) and serves the application a
// private HTTPS API and signed webhooks (MEMBER-SERVICE-PLAN §3, §7.2).
//
//	service-vault serve        run (configuration from SV_* variables, README "Deployment")
//	service-vault healthcheck  probe GET /health on the local API; exit 0 or 1
//	service-vault version
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	ssmtypes "github.com/aws/aws-sdk-go-v2/service/ssm/types"

	"github.com/vettid/vettid-relay/relayclient"

	"github.com/vettid/service-vault/internal/api"
	"github.com/vettid/service-vault/internal/connect"
	"github.com/vettid/service-vault/internal/keystore"
	"github.com/vettid/service-vault/internal/peer"
	"github.com/vettid/service-vault/internal/service"
	"github.com/vettid/service-vault/internal/store"
	"github.com/vettid/service-vault/internal/tlsid"
	"github.com/vettid/service-vault/internal/webhook"
	sdkwebhook "github.com/vettid/service-vault/sdk/go/webhook"
)

// version is set at build time with -ldflags '-X main.version=...'.
var version = "dev"

func main() {
	flag.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(), "usage: service-vault serve [flags] | healthcheck | version\n")
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
	RelayURL      string
	Table         string
	KMSKeyID      string
	Listen        string
	WebhookURL    string
	ServiceName   string
	TLSName       string
	TLSPinParam   string
	APIKeyHashes  [][32]byte
	WebhookSecret []byte
	Profile       peer.Profile
}

// configFromEnv reads and checks the SV_* variables.
func configFromEnv(getenv func(string) string) (*Config, error) {
	c := &Config{
		RelayURL: strings.TrimRight(getenv("SV_RELAY_URL"), "/"), Table: getenv("SV_TABLE"), KMSKeyID: getenv("SV_KMS_KEY_ID"),
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

	awsCfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		return fmt.Errorf("aws config: %w", err)
	}
	endpoint := func(u *string) {
		if dev.awsEndpoint != "" {
			*u = dev.awsEndpoint
		}
	}
	ddb := dynamodb.NewFromConfig(awsCfg, func(o *dynamodb.Options) { setEndpoint(&o.BaseEndpoint, endpoint) })
	kc := kms.NewFromConfig(awsCfg, func(o *kms.Options) { setEndpoint(&o.BaseEndpoint, endpoint) })
	sc := ssm.NewFromConfig(awsCfg, func(o *ssm.Options) { setEndpoint(&o.BaseEndpoint, endpoint) })
	tbl := &store.Table{Client: ddb, Name: cfg.Table}

	secrets, err := keystore.LoadOrCreate(ctx, &keystore.AWSKMS{Client: kc}, cfg.KMSKeyID, tbl.Blobs(), keystore.SecretsName, keystore.NewSecrets)
	if err != nil {
		return fmt.Errorf("keystore: %w", err)
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
	if _, err := sc.PutParameter(ctx, &ssm.PutParameterInput{Name: aws.String(cfg.TLSPinParam), Value: aws.String(pin),
		Type: ssmtypes.ParameterTypeString, Overwrite: aws.Bool(true)}); err != nil {
		return fmt.Errorf("publish TLS pin: %w", err)
	}

	rc := relayclient.New(cfg.RelayURL, keys.Relay)
	if dev.relayCA != "" {
		hc, err := clientTrusting(dev.relayCA)
		if err != nil {
			return err
		}
		rc.HTTP = hc
	}
	svc := &service.Service{Store: tbl.Peer(), ServiceName: cfg.ServiceName, Log: log,
		Webhooks: &webhook.Dispatcher{URL: cfg.WebhookURL, Secret: cfg.WebhookSecret}}
	p, err := peer.New(peer.Config{Keys: keys, Relay: rc, RelayURL: cfg.RelayURL, Profile: cfg.Profile, Store: tbl.Peer(),
		Events: svc, Log: log})
	if err != nil {
		return err
	}
	svc.Peer = p

	srv := &http.Server{
		Addr:              cfg.Listen,
		Handler:           (&api.Server{Keys: cfg.APIKeyHashes, Email: email, Invites: svc.Invites(), SignIns: svc.SignIns(), Log: log}).Handler(),
		TLSConfig:         tlsid.ServerConfig(cert),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       2 * time.Minute,
		ErrorLog:          slog.NewLogLogger(log.Handler(), slog.LevelWarn),
	}
	peerErr := make(chan error, 1)
	go func() { peerErr <- p.Run(ctx) }()
	srvErr := make(chan error, 1)
	go func() { srvErr <- srv.ListenAndServeTLS("", "") }()
	log.Info("serving", "version", version, "listen", cfg.Listen, "mailbox", keys.Mailbox())

	var runErr error
	select {
	case <-ctx.Done():
	case err := <-peerErr:
		runErr = fmt.Errorf("peer: %w", err)
	case err := <-srvErr:
		runErr = fmt.Errorf("api: %w", err)
	}
	stop()
	sctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	_ = srv.Shutdown(sctx)
	if runErr == nil {
		if err := <-peerErr; err != nil && !errors.Is(err, context.Canceled) {
			runErr = fmt.Errorf("peer: %w", err)
		}
	}
	log.Info("stopped")
	return runErr
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

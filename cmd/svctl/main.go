// Command svctl is an operator's CLI over a service vault's private API,
// for trying a deployment (staging) before an application is in front of
// it. It drives the API only through the Go SDK (sdk/go/servicevault), so
// it sees exactly what an application sees.
//
//	svctl [global flags] invite -email E [-verified]
//	svctl [global flags] signin -email E [-source S]
//	svctl [global flags] approve -action A -summary S -payload JSON
//	svctl [global flags] remind ID
//	svctl [global flags] admins
//	svctl [global flags] audit [-since ID] [-limit N]
//	svctl [global flags] health
//
// The API's URL comes from -url or SVCTL_URL, the API key from
// SVCTL_API_KEY only (never a flag, never printed), and the server key's
// pin from -pin or SVCTL_PIN, or from the SSM parameter the stack exports
// (-pin-param, with -profile and -region).
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ssm"

	"github.com/vettid/service-vault/sdk/go/servicevault"
)

// Exit codes.
const (
	exitOK      = 0 // done; for a flow, it ended connected or approved
	exitError   = 1 // the call failed, or svctl stopped waiting
	exitUsage   = 2
	exitOutcome = 3 // a flow ended otherwise: declined, denied or expired
)

const usage = `usage: svctl [global flags] <command> [flags]

commands:
  invite -email E [-verified]      make an invitation; print its URL and QR code, then follow it
  signin -email E [-source S]      start an email sign-in; print the match code, then follow it
  approve -action A -summary S -payload JSON
                                   submit an action for admin approval, then follow it
  remind ID                        challenge again the admins who have not answered
  admins                           print the admin set and the threshold
  audit [-since ID] [-limit N]     print a page of the audit log, one JSON entry per line
  anchor-key                       print GET /v1/anchor-key (for the votes site's service list)
  proposal create -in FILE         create a proposal from its JSON input; print the answer
  proposal status|publish|close|results ID
                                   a proposal's status; retry its publication; count and
                                   publish its results; print them
  health                           check GET /health

environment:
  SVCTL_URL       the API's URL (or -url)
  SVCTL_API_KEY   the API key (environment only)
  SVCTL_PIN       the server key's pin, sha256/... (or -pin, or -pin-param)

global flags:
`

// env is how svctl reads the environment (os.Getenv; a map in tests).
type env func(string) string

// pinFromSSM reads the pin from an SSM parameter; replaced in tests.
var pinFromSSM = func(ctx context.Context, name, profile, region string) (string, error) {
	var opts []func(*config.LoadOptions) error
	if profile != "" {
		opts = append(opts, config.WithSharedConfigProfile(profile))
	}
	if region != "" {
		opts = append(opts, config.WithRegion(region))
	}
	cfg, err := config.LoadDefaultConfig(ctx, opts...)
	if err != nil {
		return "", fmt.Errorf("aws config: %w", err)
	}
	out, err := ssm.NewFromConfig(cfg).GetParameter(ctx, &ssm.GetParameterInput{Name: aws.String(name)})
	if err != nil {
		return "", fmt.Errorf("reading the pin from SSM: %w", err)
	}
	if out.Parameter == nil || aws.ToString(out.Parameter.Value) == "" {
		return "", errors.New("reading the pin from SSM: empty parameter")
	}
	return aws.ToString(out.Parameter.Value), nil
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	code := run(ctx, os.Args[1:], os.Getenv, os.Stdout, os.Stderr)
	stop()
	os.Exit(code)
}

// cli is one run's configuration and output.
type cli struct {
	c        *servicevault.Client
	out, err io.Writer
	poll     time.Duration
}

// run parses the arguments and runs one command; it returns the exit
// code.
func run(ctx context.Context, args []string, getenv env, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("svctl", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() {
		fmt.Fprint(stderr, usage)
		fs.PrintDefaults()
	}
	baseURL := fs.String("url", "", "the API's URL (default $SVCTL_URL)")
	pin := fs.String("pin", "", "the server key's pin, sha256/... (default $SVCTL_PIN)")
	pinParam := fs.String("pin-param", "", "read the pin from this SSM parameter (the stack's TlsPinParameterName)")
	profile := fs.String("profile", "", "with -pin-param: the AWS profile")
	region := fs.String("region", "", "with -pin-param: the AWS region")
	poll := fs.Duration("poll", 2*time.Second, "how often to poll a flow's status")
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}
	if fs.NArg() == 0 {
		fs.Usage()
		return exitUsage
	}
	if *poll <= 0 {
		fmt.Fprintln(stderr, "svctl: -poll must be positive")
		return exitUsage
	}
	cmd, cargs := fs.Arg(0), fs.Args()[1:]
	commands := map[string]func(*cli, context.Context, []string) error{
		"invite": (*cli).invite, "signin": (*cli).signin, "approve": (*cli).approve, "remind": (*cli).remind,
		"admins": (*cli).admins, "audit": (*cli).audit, "health": (*cli).health,
		"anchor-key": (*cli).anchorKey, "proposal": (*cli).proposal,
	}
	f, ok := commands[cmd]
	if !ok {
		fmt.Fprintf(stderr, "svctl: unknown command %q\n", cmd)
		fs.Usage()
		return exitUsage
	}
	if *baseURL == "" {
		*baseURL = getenv("SVCTL_URL")
	}
	if *pin == "" {
		*pin = getenv("SVCTL_PIN")
	}
	c := &cli{out: stdout, err: stderr, poll: *poll}
	var err error
	switch {
	case *baseURL == "":
		err = errors.New("no URL: set SVCTL_URL or -url")
	case getenv("SVCTL_API_KEY") == "":
		err = errors.New("no API key: set SVCTL_API_KEY")
	case *pin != "" && *pinParam != "":
		err = errors.New("give the pin or -pin-param, not both")
	case *pinParam != "":
		*pin, err = pinFromSSM(ctx, *pinParam, *profile, *region)
	case *pin == "":
		err = errors.New("no pin: set SVCTL_PIN, -pin or -pin-param")
	}
	if err == nil {
		c.c, err = servicevault.New(servicevault.Config{BaseURL: *baseURL, APIKey: getenv("SVCTL_API_KEY"), Pin: *pin})
	}
	if err != nil {
		fmt.Fprintln(stderr, "svctl:", err)
		return exitUsage
	}
	if err := f(c, ctx, cargs); err != nil {
		var o outcome
		if errors.As(err, &o) {
			return exitOutcome
		}
		var u usageError
		if errors.As(err, &u) {
			fmt.Fprintf(stderr, "svctl %s: %v\n", cmd, err)
			return exitUsage
		}
		fmt.Fprintf(stderr, "svctl %s: %v\n", cmd, err)
		return exitError
	}
	return exitOK
}

// outcome ends a flow that finished other than connected or approved.
type outcome string

func (o outcome) Error() string { return string(o) }

// usageError is a command's bad flags or arguments.
type usageError struct{ error }

// flags parses a command's flags; positional is how many positional
// arguments it takes.
func (c *cli) flags(fs *flag.FlagSet, args []string, positional int) error {
	fs.SetOutput(c.err)
	if err := fs.Parse(args); err != nil {
		return usageError{err}
	}
	if fs.NArg() != positional {
		return usageError{fmt.Errorf("want %d argument(s), got %d", positional, fs.NArg())}
	}
	return nil
}

func (c *cli) printf(format string, a ...any) { fmt.Fprintf(c.out, format, a...) }

// follow calls step until it reports the flow finished says the flow is finished or wait runs
// out; wait 0 polls not at all.
func (c *cli) follow(ctx context.Context, wait time.Duration, step func(context.Context) (done bool, err error)) error {
	if wait <= 0 {
		return nil
	}
	ctx, cancel := context.WithTimeout(ctx, wait)
	defer cancel()
	t := time.NewTicker(c.poll)
	defer t.Stop()
	for {
		done, err := step(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return fmt.Errorf("stopped waiting after %v", wait)
			}
			return err
		}
		if done {
			return nil
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("stopped waiting after %v", wait)
		case <-t.C:
		}
	}
}

func (c *cli) invite(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("invite", flag.ContinueOnError)
	email := fs.String("email", "", "the email the visitor entered")
	verified := fs.Bool("verified", false, "the email is verified (the member proved control of it, e.g. with a one-time code); without it the invitation carries no email")
	noQR := fs.Bool("no-qr", false, "do not print the QR code")
	invert := fs.Bool("qr-invert", false, "print the QR code for a terminal with a light background")
	wait := fs.Duration("wait", 11*time.Minute, "how long to follow the invitation (0: not at all)")
	if err := c.flags(fs, args, 0); err != nil {
		return err
	}
	if *email == "" {
		return usageError{errors.New("-email is required")}
	}
	v := servicevault.EmailUnverified
	if *verified {
		v = servicevault.EmailVerified
	}
	inv, err := c.c.CreateInvite(ctx, *email, v)
	if err != nil {
		return err
	}
	c.printf("invite_id: %s\nexpires_at: %s\nurl: %s\n", inv.ID, inv.ExpiresAt.UTC().Format(time.RFC3339), inv.URL)
	if !*noQR {
		q, err := renderQR(inv.URL, *invert)
		if err != nil {
			return err
		}
		c.printf("%s", q)
	}
	last := ""
	return c.follow(ctx, *wait, func(ctx context.Context) (bool, error) {
		st, err := c.c.InviteStatus(ctx, inv.ID)
		if err != nil {
			return false, err
		}
		if st.Status == last {
			return false, nil
		}
		last = st.Status
		c.printf("status: %s\n", st.Status)
		if st.SAS != "" {
			c.printf("sas: %s\n", st.SAS)
		}
		if st.ConnectionID != "" {
			c.printf("connection_id: %s\n", st.ConnectionID)
		}
		switch st.Status {
		case servicevault.InviteStatusConnected:
			return true, nil
		case servicevault.InviteStatusDeclined, servicevault.InviteStatusExpired:
			return true, outcome(st.Status)
		}
		return false, nil
	})
}

func (c *cli) signin(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("signin", flag.ContinueOnError)
	email := fs.String("email", "", "the member's email")
	source := fs.String("source", "", "the end user's address, for the per-source rate limit (optional)")
	wait := fs.Duration("wait", 3*time.Minute, "how long to follow the sign-in (0: not at all)")
	if err := c.flags(fs, args, 0); err != nil {
		return err
	}
	if *email == "" {
		return usageError{errors.New("-email is required")}
	}
	si, err := c.c.StartSignIn(ctx, servicevault.SignInRequest{Email: *email, Source: *source})
	if err != nil {
		return err
	}
	c.printf("signin_id: %s\nmatch_code: %s\n", si.ID, si.MatchCode)
	return c.follow(ctx, *wait, func(ctx context.Context) (bool, error) {
		st, err := c.c.SignInStatus(ctx, si.ID)
		if err != nil || st.Status == servicevault.SignInStatusPending {
			return false, err
		}
		c.printf("status: %s\n", st.Status)
		if st.ConnectionID != "" {
			c.printf("connection_id: %s\n", st.ConnectionID)
		}
		if st.KeyChanged != nil {
			c.printf("key_changed: %t\n", *st.KeyChanged)
		}
		if st.Status != servicevault.SignInStatusApproved {
			return true, outcome(st.Status)
		}
		return true, nil
	})
}

func (c *cli) approve(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("approve", flag.ContinueOnError)
	action := fs.String("action", "", "the action, e.g. vote.open or admin_set.add")
	summary := fs.String("summary", "", "what the admins read on the phone")
	payload := fs.String("payload", "{}", "the action's payload, a JSON object")
	wait := fs.Duration("wait", 30*time.Minute, "how long to follow the approval (0: not at all)")
	if err := c.flags(fs, args, 0); err != nil {
		return err
	}
	if *action == "" || *summary == "" {
		return usageError{errors.New("-action and -summary are required")}
	}
	if !json.Valid([]byte(*payload)) {
		return usageError{errors.New("-payload is not JSON")}
	}
	req := servicevault.ApprovalRequest{Action: *action, Summary: *summary, Payload: json.RawMessage(*payload)}
	ap, err := c.c.CreateApproval(ctx, req)
	if err != nil {
		return err
	}
	c.printf("approval_id: %s\naction_hash: %s\nexpires_at: %s\n", ap.ID, ap.ActionHash, ap.ExpiresAt.UTC().Format(time.RFC3339))
	if h, err := servicevault.ActionHash(req.Action, req.Summary, req.Payload); err != nil || h != ap.ActionHash {
		return errors.New("the action hash does not match the one computed here")
	}
	c.printf("action_hash_check: ok\n")
	return c.follow(ctx, *wait, func(ctx context.Context) (bool, error) {
		st, err := c.c.Approval(ctx, ap.ID)
		if err != nil || st.Status == servicevault.ApprovalStatusPending {
			return false, err
		}
		c.printf("status: %s\n", st.Status)
		if st.Reason != "" {
			c.printf("reason: %s\n", st.Reason)
		}
		c.printf("threshold: %d\n", st.Threshold)
		for _, a := range st.Approvals {
			c.printf("approved_by: %s key_changed=%t\n", a.ConnectionID, a.KeyChanged)
		}
		for _, d := range st.Denials {
			c.printf("denied_by: %s\n", d.ConnectionID)
		}
		if st.Applied != nil {
			c.printf("applied: %t\n", *st.Applied)
		}
		if st.Status != servicevault.ApprovalStatusApproved {
			return true, outcome(st.Status)
		}
		return true, nil
	})
}

func (c *cli) remind(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("remind", flag.ContinueOnError)
	if err := c.flags(fs, args, 1); err != nil {
		return err
	}
	r, err := c.c.RemindApproval(ctx, fs.Arg(0))
	if err != nil {
		return err
	}
	c.printf("approval_id: %s\n", r.ID)
	for _, id := range r.Reminded {
		c.printf("reminded: %s\n", id)
	}
	return nil
}

func (c *cli) admins(ctx context.Context, args []string) error {
	if err := c.flags(flag.NewFlagSet("admins", flag.ContinueOnError), args, 0); err != nil {
		return err
	}
	a, err := c.c.Admins(ctx)
	if err != nil {
		return err
	}
	c.printf("threshold: %d\n", a.Threshold)
	for _, id := range a.Admins {
		c.printf("admin: %s\n", id)
	}
	return nil
}

func (c *cli) audit(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("audit", flag.ContinueOnError)
	since := fs.String("since", "", "print the entries after this entry id")
	limit := fs.Int("limit", 100, "at most this many entries (1-100)")
	if err := c.flags(fs, args, 0); err != nil {
		return err
	}
	if *limit < 1 || *limit > 100 {
		return usageError{errors.New("-limit must be from 1 to 100")}
	}
	p, err := c.c.Audit(ctx, *since, *limit)
	if err != nil {
		return err
	}
	enc := json.NewEncoder(c.out)
	for _, e := range p.Entries {
		if err := enc.Encode(e); err != nil {
			return err
		}
	}
	if p.Next != "" {
		fmt.Fprintf(c.err, "more: svctl audit -since %s\n", p.Next)
	}
	return nil
}

func (c *cli) anchorKey(ctx context.Context, args []string) error {
	if err := c.flags(flag.NewFlagSet("anchor-key", flag.ContinueOnError), args, 0); err != nil {
		return err
	}
	b, err := c.c.AnchorKey(ctx)
	if err != nil {
		return err
	}
	return c.printJSON(b)
}

// proposal runs one proposal subcommand and prints the API's answer.
func (c *cli) proposal(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return usageError{errors.New("want a subcommand: create, status, publish, close or results")}
	}
	sub, args := args[0], args[1:]
	var b json.RawMessage
	var err error
	switch sub {
	case "create":
		fs := flag.NewFlagSet("proposal create", flag.ContinueOnError)
		in := fs.String("in", "", "the proposal input, a JSON file")
		if err := c.flags(fs, args, 0); err != nil {
			return err
		}
		if *in == "" {
			return usageError{errors.New("-in is required")}
		}
		raw, rerr := os.ReadFile(*in)
		if rerr != nil {
			return rerr
		}
		if !json.Valid(raw) {
			return usageError{fmt.Errorf("%s: not JSON", *in)}
		}
		b, err = c.c.CreateProposal(ctx, raw)
		var ae *servicevault.APIError
		if errors.As(err, &ae) && ae.ProposalID != "" {
			fmt.Fprintf(c.err, "proposal %s is kept but not published: retry with svctl proposal publish %s\n", ae.ProposalID, ae.ProposalID)
		}
	case "status", "publish", "close", "results":
		if err := c.flags(flag.NewFlagSet("proposal "+sub, flag.ContinueOnError), args, 1); err != nil {
			return err
		}
		id := args[len(args)-1]
		switch sub {
		case "status":
			b, err = c.c.Proposal(ctx, id)
		case "publish":
			b, err = c.c.PublishProposal(ctx, id)
		case "close":
			b, err = c.c.CloseProposal(ctx, id)
		default:
			b, err = c.c.ProposalResults(ctx, id)
		}
	default:
		return usageError{fmt.Errorf("unknown subcommand %q", sub)}
	}
	if err != nil {
		return err
	}
	return c.printJSON(b)
}

// printJSON prints an answer indented.
func (c *cli) printJSON(b json.RawMessage) error {
	var buf bytes.Buffer
	if err := json.Indent(&buf, b, "", "  "); err != nil {
		return err
	}
	buf.WriteByte('\n')
	_, err := c.out.Write(buf.Bytes())
	return err
}

func (c *cli) health(ctx context.Context, args []string) error {
	if err := c.flags(flag.NewFlagSet("health", flag.ContinueOnError), args, 0); err != nil {
		return err
	}
	if err := c.c.Health(ctx); err != nil {
		return err
	}
	c.printf("ok\n")
	return nil
}

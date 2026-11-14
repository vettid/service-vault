// Command svctl is an operator's CLI over a service vault's private API,
// for trying a deployment (staging) before an application is in front of
// it. It drives the API only through the Go SDK (sdk/go/servicevault), so
// it sees exactly what an application sees.
//
//	svctl [global flags] invite -email E [-verified]
//	svctl [global flags] signin -email E [-source S]
//	svctl [global flags] signin -unsigned
//	svctl [global flags] approve -action A -summary S -payload JSON
//	svctl [global flags] approval ID
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
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"regexp"
	"slices"
	"strings"
	"syscall"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ssm"

	"github.com/vettid/service-vault/internal/approval"
	"github.com/vettid/service-vault/internal/ballot"
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
  signin -unsigned                 testing only (staging test connections); members of a
                                   real service must sign in themselves. Sends one
                                   sign-in challenge to each eligible connection that
                                   has never signed in (sends 10 challenges and looks at
                                   100 connections per run, one challenge each; none to
                                   one with a challenge pending, declined within the hour
                                   or 10 in 24 h); print each match code or why it was
                                   skipped; does not wait for the answers; exit 1 if the
                                   run stopped early
  approve -action A -summary S -payload JSON
                                   (no -summary for proposal.create, vote.extend, admin.repin, admin_set.add
                                   and admin_set.remove: the service writes it from the payload)
                                   submit an action for admin approval, then follow it
                                   (ask_budget, exit 1, if fewer admins than the threshold
                                   can be asked: the others are at their ask limit, 4
                                   approval challenges still counting, 5 for admin.repin
                                   and admin_set.*; nothing is sent)
  approval ID                      print an approval's status; "remind needed" lists admins with no live challenge
  remind [-force CONN,...] ID      challenge again the admins who have not answered (with long
                                   approval challenges, only those holding no live challenge;
                                   exit 0 and "nothing to remind" if there are none; exit 1 on
                                   too_soon; an admin at the ask limit (4 approval
                                   challenges still counting, 5 for a repair) is left out, and if that leaves none to
                                   challenge, ask_budget, exit 1). -force names admins to challenge again even with a
                                   live challenge (the old one is withdrawn); each forced re-send
                                   spends one of that admin's 5 approval asks per 24 h, and a
                                   force naming an admin at the ask limit (each challenge
                                   counting until its expiry + 24 h) is refused
                                   (ask_budget, exit 1): use it only when the admin reports not
                                   seeing the request
  admins                           print the admin set and the threshold
  audit [-since ID] [-limit N]     print a page of the audit log, one JSON entry per line
  anchor-key                       print GET /v1/anchor-key (for the votes site's service list)
  proposal create -in FILE [-wait D] [-approval ID]
                                   ask the admins to approve the proposal input (they read a
                                   summary built from it), wait for them, then create the
                                   proposal with the approval (used up); print the answer
  proposal extend ID -in FILE [-wait D] [-approval ID]
                                   the same for an extension of the proposal's close
  proposal status|publish|close|results ID
                                   a proposal's status; retry its publication; count and
                                   publish its results (collecting, timestamp_unavailable,
                                   stamped_early: retry later; the last two say to check
                                   the clocks or the timestamp authority); print them
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
		"invite": (*cli).invite, "signin": (*cli).signin, "approve": (*cli).approve, "remind": (*cli).remind, "approval": (*cli).approval,
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
	unsigned := fs.Bool("unsigned", false, "testing only (staging test connections); members of a real service must sign in themselves. Instead of an email: challenge the eligible connections that have never signed in: 10 challenges sent and 100 connections looked at per run, one challenge each (the answers are not waited for)")
	if err := c.flags(fs, args, 0); err != nil {
		return err
	}
	if *unsigned {
		waitSet := false
		fs.Visit(func(f *flag.Flag) { waitSet = waitSet || f.Name == "wait" })
		if *email != "" || *source != "" || waitSet {
			return usageError{errors.New("-unsigned takes no -email, -source or -wait")}
		}
		return c.signinUnsigned(ctx)
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

// signinUnsigned challenges the connections that have never signed in,
// so a member's vault does not refuse their vote for want of one.
func (c *cli) signinUnsigned(ctx context.Context) error {
	u, err := c.c.StartUnsignedSignIns(ctx)
	var ae *servicevault.APIError
	if errors.As(err, &ae) && ae.Status == http.StatusForbidden && ae.Code == "test_only" {
		return errors.New("signin -unsigned is for testing only: this service vault has SV_TEST_SIGNINS off")
	}
	if err != nil {
		return err
	}
	for _, s := range u.SignIns {
		c.printf("connection_id: %s\n", s.ConnectionID)
		if s.SignInID != "" {
			c.printf("signin_id: %s\n", s.SignInID)
		}
		// A not_recorded entry has a code and no signin_id; the
		// operator is the only one who can tell the member.
		if s.MatchCode != "" {
			c.printf("match_code: %s\n", s.MatchCode)
		}
		if s.Skipped != "" {
			c.printf("skipped: %s\n", s.Skipped)
		}
	}
	if u.More > 0 {
		c.printf("more: %d (run again)\n", u.More)
	}
	if u.Stopped != "" {
		c.printf("stopped: %s\n", u.Stopped)
		return fmt.Errorf("stopped early (%s): what is printed was done; run again for the rest", u.Stopped)
	}
	return nil
}

func (c *cli) approve(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("approve", flag.ContinueOnError)
	action := fs.String("action", "", "the action, e.g. contract_template.change or admin_set.add")
	summary := fs.String("summary", "", "what the admins read on the phone")
	payload := fs.String("payload", "{}", "the action's payload, a JSON object")
	wait := fs.Duration("wait", 30*time.Minute, "how long to follow the approval (0: not at all)")
	if err := c.flags(fs, args, 0); err != nil {
		return err
	}
	built := approval.BuiltSummary(*action)
	switch {
	case *action == "" || *summary == "" && !built:
		return usageError{errors.New("-action and -summary are required")}
	case built && *summary != "":
		return usageError{fmt.Errorf("%s takes no -summary: the service builds it from the payload", *action)}
	}
	if !json.Valid([]byte(*payload)) {
		return usageError{errors.New("-payload is not JSON")}
	}
	req := servicevault.ApprovalRequest{Action: *action, Summary: *summary, Payload: json.RawMessage(*payload)}
	_, err := c.approveAndFollow(ctx, req, *wait)
	return err
}

// approveAndFollow submits req for approval, checks the hash the service
// answers and follows the approval until it is decided (up to wait). It
// returns the approval's id once it is approved; any other end is an
// error (an outcome for denied or expired).
//
// For the actions whose summary the service builds from the payload
// (ballot.SummaryFor), req.Summary is left empty; the summary the
// service reports must be the one built here from the payload, and the
// hash is checked with it.
func (c *cli) approveAndFollow(ctx context.Context, req servicevault.ApprovalRequest, wait time.Duration) (string, error) {
	ap, err := c.c.CreateApproval(ctx, req)
	var ae *servicevault.APIError
	if errors.As(err, &ae) && ae.Code == servicevault.CodeAskBudget {
		return "", fmt.Errorf("approve: too few admins can be asked now: the others are at their ask limit (4 approval challenges still counting, 5 for admin.repin and admin_set.*) "+
			"(each until its expiry plus 24 hours); nothing was sent (%w)", err)
	}
	if err != nil {
		return "", err
	}
	c.printf("approval_id: %s\naction_hash: %s\nexpires_at: %s\n", ap.ID, ap.ActionHash, ap.ExpiresAt.UTC().Format(time.RFC3339))
	summary := req.Summary
	hashPayload := req.Payload // what the action hash covers
	title := ""
	if req.Action == servicevault.ActionVoteExtend {
		if title, err = c.proposalTitle(ctx, req.Payload); err != nil {
			return "", err
		}
	}
	if req.Action == servicevault.ActionAdminSetAdd || req.Action == servicevault.ActionAdminSetRemove || req.Action == servicevault.ActionAdminRepin {
		// The summary is the service's: who is added or removed, from its
		// own record of the connection. It must name the connection asked.
		var p struct {
			ConnectionID string `json:"connection_id"`
		}
		st, err := c.c.Approval(ctx, ap.ID)
		if err != nil {
			return ap.ID, err
		}
		if json.Unmarshal(req.Payload, &p) != nil || p.ConnectionID == "" || !strings.HasSuffix(st.Summary, ", connection "+p.ConnectionID) ||
			(req.Action == servicevault.ActionAdminSetAdd && (!strings.Contains(st.Summary, ", connected ") || !addedKey.MatchString(st.Summary))) ||
			(req.Action == servicevault.ActionAdminRepin && !repinKeys.MatchString(st.Summary)) {
			return ap.ID, errors.New("the summary the admins read does not name the connection asked for")
		}
		summary = st.Summary
		c.printf("summary: %s\n", summary)
		if req.Action == servicevault.ActionAdminRepin {
			// The key the admins read in the summary is the key in the
			// payload the hash covers.
			var got struct {
				NewKey string `json:"new_key"`
			}
			key, kerr := []byte(nil), error(nil)
			if json.Unmarshal(st.Payload, &got) == nil {
				key, kerr = base64.StdEncoding.DecodeString(got.NewKey)
			}
			if kerr != nil || len(key) != 32 || !strings.Contains(st.Summary, ", new key "+approval.CredentialKeyFingerprint(key)+", ") {
				return ap.ID, errors.New("the new key in the payload does not match the fingerprint the admins read")
			}
		}
		if req.Action == servicevault.ActionAdminRepin && !strings.Contains(string(req.Payload), "new_key") {
			// The service filled in new_key (the connection's credential
			// key now): the hash covers the payload it returns, which must
			// be the one given with that key added.
			var got, asked struct {
				ConnectionID string `json:"connection_id"`
				NewKey       string `json:"new_key"`
			}
			if json.Unmarshal(st.Payload, &got) != nil || json.Unmarshal(req.Payload, &asked) != nil ||
				got.ConnectionID != asked.ConnectionID || got.NewKey == "" {
				return ap.ID, errors.New("the payload the service approved is not the one asked for")
			}
			hashPayload = st.Payload
		}
	} else if want, built, err := ballot.SummaryFor(req.Action, req.Payload, title); err != nil {
		return ap.ID, fmt.Errorf("the payload can't be summarized: %w", err)
	} else if built {
		st, err := c.c.Approval(ctx, ap.ID)
		if err != nil {
			return ap.ID, err
		}
		if st.Summary != want {
			return ap.ID, errors.New("the summary the admins read does not match the one built here from the payload")
		}
		summary = want
		c.printf("summary: %s\n", want)
	}
	if h, err := servicevault.ActionHash(req.Action, summary, hashPayload); err != nil || h != ap.ActionHash {
		return ap.ID, errors.New("the action hash does not match the one computed here")
	}
	c.printf("action_hash_check: ok\n")
	c.printf("%s", askBudgetLines(ap.AskBudget))
	var told string     // the remind-needed line last printed
	var queued []string // the admins whose challenge was queued at the last poll
	err = c.follow(ctx, wait, func(ctx context.Context) (bool, error) {
		st, err := c.c.Approval(ctx, ap.ID)
		if err != nil {
			return false, err
		}
		if st.Status == servicevault.ApprovalStatusPending {
			c.printf("%s", sentLine(queued, st))
			queued = st.Queued
			if line := remindLine(st); line != told {
				told = line
				if line != "" {
					c.printf("%s", line)
				}
			}
			return false, nil
		}
		c.printApproval(st)
		if st.Status != servicevault.ApprovalStatusApproved {
			return true, outcome(st.Status)
		}
		return true, nil
	})
	return ap.ID, err
}

// repinKeys is the new key's fingerprint of an admin.repin summary (16 hex
// digits in 4 groups) and when the key changed (or that it is not recorded).
var repinKeys = regexp.MustCompile(`, new key [0-9a-f]{4}( [0-9a-f]{4}){3}, (key changed [0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2} UTC|key changed time not recorded), connection `)

// addedKey is the key fingerprint of an admin_set.add summary: 16 hex
// digits in 4 groups.
var addedKey = regexp.MustCompile(`, key [0-9a-f]{4}( [0-9a-f]{4}){3}, connection `)

// proposalTitle reads the title of the proposal a vote.extend payload is
// for, as the service has it, to build the summary the admins read.
func (c *cli) proposalTitle(ctx context.Context, payload []byte) (string, error) {
	id, err := ballot.ExtensionProposalID(payload)
	if err != nil {
		return "", err
	}
	raw, err := c.c.Proposal(ctx, id)
	if err != nil {
		return "", err
	}
	var st struct {
		Proposal string `json:"proposal"`
	}
	var doc struct {
		Title string `json:"title"`
	}
	if json.Unmarshal(raw, &st) != nil || json.Unmarshal([]byte(st.Proposal), &doc) != nil || doc.Title == "" {
		return "", errors.New("the proposal's title can't be read")
	}
	return doc.Title, nil
}

// requireApproved fails unless approval id is approved now (after a wait
// of 0, or one that ran out, it may still be pending).
func (c *cli) requireApproved(ctx context.Context, id string) error {
	st, err := c.c.Approval(ctx, id)
	if err != nil {
		return err
	}
	if st.Status != servicevault.ApprovalStatusApproved {
		return fmt.Errorf("approval %s is %s: run again with -approval %s once it is approved", id, st.Status, id)
	}
	return nil
}

// now is the clock (replaced in tests).
var now = time.Now

// remindLine tells the operator, while the approval is pending, which
// admins' challenges are queued, not sent yet, and which admins hold no
// live challenge and have not answered (remind needed, with the command
// and any ask budget); "" when there are neither.
func remindLine(st *servicevault.Approval) string {
	if st.Status != servicevault.ApprovalStatusPending {
		return ""
	}
	out := ""
	if len(st.Queued) > 0 {
		out = fmt.Sprintf("queued, not sent yet: %s\n", strings.Join(st.Queued, ","))
	}
	if len(st.RemindNeeded) == 0 {
		return out
	}
	cmd := "svctl remind " + st.ID
	if st.RemindAfter != nil && now().Before(*st.RemindAfter) {
		cmd += " after " + st.RemindAfter.UTC().Format("15:04:05Z")
	}
	return out + fmt.Sprintf("remind needed: %s (%s)\n", strings.Join(st.RemindNeeded, ","), cmd) + askBudgetLines(st.AskBudget)
}

// sentLine names the admins of was (queued at the last poll) whose
// challenge has gone since: no longer queued, and not in remind_needed
// (where one that left the outbox undelivered goes); "" when there are
// none.
func sentLine(was []string, st *servicevault.Approval) string {
	var gone []string
	for _, a := range was {
		if !slices.Contains(st.Queued, a) && !slices.Contains(st.RemindNeeded, a) {
			gone = append(gone, a)
		}
	}
	if len(gone) == 0 {
		return ""
	}
	return fmt.Sprintf("sent, no longer queued: %s\n", strings.Join(gone, ","))
}

// askBudgetLines says which admins were left out for the ask budget and
// when each can be asked again; "" when there are none.
func askBudgetLines(l []servicevault.AskBudget) string {
	var sb strings.Builder
	for _, a := range l {
		fmt.Fprintf(&sb, "ask budget: %s can be asked after %s\n", a.ConnectionID, a.NextAskAt.UTC().Format(time.RFC3339))
	}
	return sb.String()
}

func (c *cli) printApproval(st *servicevault.Approval) {
	c.printf("status: %s\n", st.Status)
	if st.Reason != "" {
		c.printf("reason: %s\n", st.Reason)
	}
	c.printf("threshold: %d\n", st.Threshold)
	for _, a := range st.Approvals {
		if !a.Counted {
			c.printf("not_counted: %s reason=%s key_changed=%t (it does not count; the other admins re-pin with: svctl approve -action admin.repin -payload '{\"connection_id\":\"%s\"}')\n",
				a.ConnectionID, a.Reason, a.KeyChanged, a.ConnectionID)
			continue
		}
		c.printf("approved_by: %s key_changed=%t\n", a.ConnectionID, a.KeyChanged)
	}
	for _, d := range st.Denials {
		// A denial may be the admin's or their vault's, for a muted or
		// paused service (VAULT-MESSAGING §10.4.1): the service cannot tell.
		c.printf("not_approved_by: %s\n", d.ConnectionID)
	}
	c.printf("%s", remindLine(st))
	if st.Applied != nil {
		c.printf("applied: %t\n", *st.Applied)
	}
}

func (c *cli) approval(ctx context.Context, args []string) error {
	if err := c.flags(flag.NewFlagSet("approval", flag.ContinueOnError), args, 1); err != nil {
		return err
	}
	st, err := c.c.Approval(ctx, args[0])
	if err != nil {
		return err
	}
	c.printApproval(st)
	return nil
}

func (c *cli) remind(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("remind", flag.ContinueOnError)
	force := fs.String("force", "", "challenge again these admins (connection ids, comma-separated) even if they hold a live challenge")
	if err := c.flags(fs, args, 1); err != nil {
		return err
	}
	var named []string
	for _, id := range strings.Split(*force, ",") {
		if id = strings.TrimSpace(id); id != "" {
			named = append(named, id)
		}
	}
	if *force != "" && len(named) == 0 {
		return usageError{errors.New("remind: -force needs connection ids")}
	}
	r, err := c.c.RemindApproval(ctx, fs.Arg(0), named...)
	var ae *servicevault.APIError
	if errors.As(err, &ae) && ae.Code == servicevault.CodeNothingToRemind {
		c.printf("nothing to remind: every admin who has not answered still holds a live challenge\n")
		return nil
	}
	if errors.As(err, &ae) && ae.Code == servicevault.CodeAskBudget {
		if len(named) > 0 {
			return fmt.Errorf("remind: a named admin is at their ask limit (4 approval challenges still counting, 5 for admin.repin and admin_set.*), each until its expiry plus 24 hours; "+
				"one more would leave none for a repair, or come back as a denial (%w)", err)
		}
		return fmt.Errorf("remind: no admin to challenge is within the budget: each is at their ask limit (4 approval challenges still counting, 5 for admin.repin and admin_set.*) "+
			"(each until its expiry plus 24 hours) or has an ask log that cannot be read; nothing was sent or withdrawn (%w)", err)
	}
	if err != nil {
		return err
	}
	c.printf("approval_id: %s\n", r.ID)
	for _, id := range r.Reminded {
		c.printf("reminded: %s\n", id)
	}
	c.printf("%s", askBudgetLines(r.AskBudget))
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
		return usageError{errors.New("want a subcommand: create, extend, status, publish, close or results")}
	}
	sub, args := args[0], args[1:]
	var b json.RawMessage
	var err error
	switch sub {
	case "create":
		fs := flag.NewFlagSet("proposal create", flag.ContinueOnError)
		in := fs.String("in", "", "the proposal input, a JSON file")
		wait := fs.Duration("wait", 30*time.Minute, "how long to wait for the admins' approval (0: not at all)")
		apv := fs.String("approval", "", "use this approved proposal.create approval of the input, instead of asking for one")
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
		var input ballot.ProposalInput
		if err := decodeStrict(raw, &input); err != nil {
			return usageError{fmt.Errorf("%s: %w", *in, err)}
		}
		payload, perr := ballot.CanonicalProposal(input)
		if perr != nil {
			return usageError{perr}
		}
		id, aerr := c.approvedAction(ctx, servicevault.ActionProposalCreate, payload, *apv, *wait)
		if aerr != nil {
			return aerr
		}
		b, err = c.c.CreateProposal(ctx, id, payload)
		if err == nil {
			var made struct {
				Unsigned int `json:"unsigned"`
			}
			if json.Unmarshal(b, &made) == nil && made.Unsigned > 0 {
				fmt.Fprintf(c.err, "warning: %d eligible connection(s) have never signed in; their vaults will refuse to vote until they do: ask them to sign in to the service once (on a test deployment: svctl signin -unsigned)\n", made.Unsigned)
			}
		}
		var ae *servicevault.APIError
		if errors.As(err, &ae) && ae.ProposalID != "" {
			fmt.Fprintf(c.err, "proposal %s is kept but not published: retry with svctl proposal publish %s\n", ae.ProposalID, ae.ProposalID)
		}
		if err != nil {
			fmt.Fprintf(c.err, "approval %s is used up whatever the outcome: a new proposal.create needs a new approval\n", id)
		}
	case "extend":
		fs := flag.NewFlagSet("proposal extend", flag.ContinueOnError)
		in := fs.String("in", "", "the extension, a JSON file: {closes_at, outage: {from, to, source}}")
		wait := fs.Duration("wait", 30*time.Minute, "how long to wait for the admins' approval (0: not at all)")
		apv := fs.String("approval", "", "use this approved vote.extend approval of the extension, instead of asking for one")
		if len(args) == 0 || strings.HasPrefix(args[0], "-") {
			return usageError{errors.New("want the proposal id first")}
		}
		pid := args[0]
		if err := c.flags(fs, args[1:], 0); err != nil {
			return err
		}
		if *in == "" {
			return usageError{errors.New("-in is required")}
		}
		raw, rerr := os.ReadFile(*in)
		if rerr != nil {
			return rerr
		}
		var input ballot.ExtensionInput
		if err := decodeStrict(raw, &input); err != nil {
			return usageError{fmt.Errorf("%s: %w", *in, err)}
		}
		payload, perr := ballot.CanonicalExtension(pid, input)
		if perr != nil {
			return usageError{perr}
		}
		id, aerr := c.approvedAction(ctx, servicevault.ActionVoteExtend, payload, *apv, *wait)
		if aerr != nil {
			return aerr
		}
		body, perr := json.Marshal(input)
		if perr != nil {
			return perr
		}
		b, err = c.c.ExtendProposal(ctx, pid, id, body)
		if err != nil {
			fmt.Fprintf(c.err, "approval %s may be used up whatever the outcome (a refusal of the input itself, such as an outage not over, leaves it unused): a new vote.extend needs a new approval\n", id)
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

// decodeStrict decodes one JSON object into v: no duplicate names, no
// unknown ones.
func decodeStrict(raw []byte, v any) error {
	if _, err := servicevault.CanonicalJSON(raw); err != nil {
		return err
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	return dec.Decode(v)
}

// approvedAction returns the id of an approved approval of action with
// payload: the one named (checked to be approved), or a new one that is
// followed until the admins approve it.
func (c *cli) approvedAction(ctx context.Context, action string, payload []byte, existing string, wait time.Duration) (string, error) {
	if existing != "" {
		st, err := c.c.Approval(ctx, existing)
		if err != nil {
			return "", err
		}
		if st.Action != action || st.Status != servicevault.ApprovalStatusApproved {
			return "", fmt.Errorf("approval %s is %s for %s, not an approved %s", existing, st.Status, st.Action, action)
		}
		return existing, nil
	}
	id, err := c.approveAndFollow(ctx, servicevault.ApprovalRequest{Action: action, Payload: payload}, wait)
	if err != nil {
		return "", err
	}
	if err := c.requireApproved(ctx, id); err != nil {
		return "", err
	}
	return id, nil
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

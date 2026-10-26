// Package signin runs email-initiated sign-in (MEMBER-SERVICE-PLAN §4.2):
// a uniform lookup of the email the member typed, then a
// connection.authenticate.challenge (VAULT-MESSAGING §10.4) to the
// member's vault carrying a two-digit match code that the site also shows.
package signin

import (
	"context"
	"crypto/rand"
	"fmt"
	"math/big"
	"time"
)

// ChallengeTTL is the life of a sign-in challenge: the inner exp of
// connection.authenticate.challenge, which caps the member vault's own
// 10-minute bound (§10.4).
const ChallengeTTL = 2 * time.Minute

// MaxContext is the bound on a challenge's context (§10.4).
const MaxContext = 256

// MatchCode returns a uniformly random two-digit code, 10 to 99, so it is
// always shown as two digits.
func MatchCode() (string, error) {
	n, err := rand.Int(rand.Reader, big.NewInt(90))
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%02d", n.Int64()+10), nil
}

// Context is the text the member's app shows with the approval (§10.4
// "context … shown to the member"); serviceName is the service's display
// name.
func Context(serviceName, code string) (string, error) {
	s := fmt.Sprintf("Sign in to %s — match code %s", serviceName, code)
	if len(s) > MaxContext {
		return "", fmt.Errorf("signin: context of %d bytes exceeds %d", len(s), MaxContext)
	}
	return s, nil
}

// Uniform runs f and then waits until floor has passed since start, so a
// lookup that finds a connection and one that does not take the same
// time from the caller's point of view (MEMBER-SERVICE-PLAN §4.2). f's
// own duration must stay below floor; Uniform reports when it did not, so
// the floor can be raised.
func Uniform(ctx context.Context, floor time.Duration, f func(context.Context)) (overran bool) {
	start := time.Now()
	f(ctx)
	rest := floor - time.Since(start)
	if rest <= 0 {
		return true
	}
	t := time.NewTimer(rest)
	defer t.Stop()
	select {
	case <-t.C:
	case <-ctx.Done():
	}
	return false
}

# VettID Service Vault

The component an application runs to connect with VettID members. It is
a VMS v2 peer on the VettID relay: members connect to it from a link or QR
code, sign in by approving on their phone, and sign what they agree to in
their own vault. The application talks to it through a private HTTPS API
and signed webhooks, and holds no VettID keys and no member secrets.

It is designed to be cheap and ordinary to run: one container, no enclave,
`cdk deploy`.

## Status

**Phase 1, in progress.** `service-vault serve` runs the peer (members
connect from an invitation and sign in by approving a challenge on their
phone, [docs/SERVICE-VAULT.md](docs/SERVICE-VAULT.md) §5) and the private
API.
The plan, its decisions and its phases are in
[MEMBER-SERVICE-PLAN](https://github.com/vettid/member-service/blob/main/docs/MEMBER-SERVICE-PLAN.md).
The first deployment is vettid.org's own member service
([vettid/member-service](https://github.com/vettid/member-service)), which
integrates exactly as a third party would.

This repository replaces
[vettid/vettid-service-vault](https://github.com/vettid/vettid-service-vault),
a NATS-based prototype that is retired; none of its code is reused.

## Build and test

```sh
make build        # bin/service-vault
make test         # go test ./...
make lint         # go vet + staticcheck
```

Requires Go 1.26 (`go.mod` pins the toolchain).

`make integration` runs the store and keystore tests on LocalStack.
`make devstack-test` (not in CI) runs the service vault in process
against a real member vault: vettid-vault's dev stack at the pinned
commit (`make devstack-up` in another terminal; about 8 GB of memory and
podman or docker compose), with the member played by its `vaultctl`. It
connects from an invitation, checks that both sides show the same SAS,
approves, checks the title the member's vault shows, signs in with the
match code in the challenge and removes the connection.

## Deployment

The container image is built from the [Dockerfile](Dockerfile) (static
binary on `scratch`, CA bundle only, non-root, amd64 and arm64:
`make image`). [`cdk/`](cdk) is an AWS CDK app that runs it as
MEMBER-SERVICE-PLAN §9 describes. Nothing is deployed from CI.

```sh
cd cdk && npm ci && npm test
npx cdk deploy \
  -c envName=prod \
  -c image=ghcr.io/vettid/service-vault@sha256:<digest> \
  -c webhookUrl=https://<application>/webhooks/service-vault \
  -c apiClientSecurityGroupId=sg-<member API task>
```

| Context | Required | Meaning |
|---|---|---|
| `image` | yes | Image pinned by digest (`<repo>@sha256:…`); a tag is refused. GHCR (public) or private ECR (the stack grants the pull). |
| `webhookUrl` | yes | Where the application receives signed webhooks (https). |
| `envName` | no (`prod`) | Part of every name and export: stack `ServiceVault-<envName>`. |
| `relayUrl` | no (`https://relay.vettid.org`) | The relay. |
| `serviceName` | no (`VettID Member Service`) | The name members see. |
| `apiClientSecurityGroupId` / `apiClientCidr` | no | Who may reach the API port. Neither: nobody until a rule is added. An open CIDR is refused. |
| `vpcCidr` | no (`10.60.0.0/24`) | The VPC (two /26 public subnets). |

**What it creates.** A VPC with public subnets in two AZs, no NAT gateway,
the free DynamoDB gateway endpoint and no interface endpoints. An ECS
cluster (Container Insights off) with one ARM64 Fargate task, 0.25 vCPU /
512 MB, on `FARGATE_SPOT` only: ECS does not fall back from Spot to
on-demand by itself, and a reclaimed task is simply replaced (all state is
in DynamoDB). Deploys run with minimum 0 / maximum 100 % so only one task
ever holds the relay mailboxes, with the circuit breaker rolling back a
failed deploy. The task has a public IP for its outbound calls and a
security group with no inbound rule from the internet and HTTPS (443)
outbound only. One DynamoDB table (`pk`/`sk`, on-demand, point-in-time
recovery, deletion protection), one KMS key (rotation on) of which the
task may only `GenerateDataKey` and `Decrypt`, two Secrets Manager
secrets and a log group (30 days). The table, key, secrets and log group
are retained if the stack is deleted.

**Why no load balancer.** The API's only client is the member API, a
Fargate task in the same VPC. It finds the service vault through Cloud Map
private DNS (`service-vault.<envName>.vettid.internal:8080`), and the
service vault's security group admits the API port from the member API's
security group only. An internal ALB would add ~$16/month and an
interface endpoint or PrivateLink more, for no extra isolation; the API is
still authenticated with an API key on every `/v1` route, and it is
served over TLS 1.3 with a self-signed certificate whose key is pinned:
the daemon keeps its TLS key with its other secrets and writes the key's
pin (`sha256/…` of the SubjectPublicKeyInfo) to an SSM parameter at
start, and the application's client (`sdk/go/pinned`) accepts only that
key. No certificate authority is involved. The stack
exports `ServiceVault-<envName>-{VpcId, PublicSubnetIds, SecurityGroupId,
NamespaceId, NamespaceArn, NamespaceName, ApiUrl, WebhookSecretArn,
TlsPinParameterName, TlsPinParameterArn}` for
the member-service stack, which can add its own ingress rule to the
exported security group instead of passing `apiClientSecurityGroupId`.

**Container configuration.**

| Variable | Source | Meaning |
|---|---|---|
| `SV_RELAY_URL` | env | Relay base URL |
| `SV_TABLE` | env | DynamoDB table name |
| `SV_KMS_KEY_ID` | env | KMS key ARN for the keystore |
| `SV_LISTEN` | env | API listen address (`:8080`) |
| `SV_WEBHOOK_URL` | env | Webhook destination |
| `SV_SERVICE_NAME` | env | Display name, at least two words: the first is the service's first name and the rest its last name in the profile members see (`VettID Member Service` → `VettID` / `Member Service`, VAULT-MESSAGING §10.8) |
| `SV_TLS_NAME` | env | DNS name in the private API's self-signed certificate |
| `SV_TLS_PIN_PARAM` | env | SSM parameter the daemon writes its TLS key pin to |
| `SV_API_KEY_HASHES` | Secrets Manager | Comma-separated hex SHA-256 of the accepted API keys |
| `SV_WEBHOOK_SECRET` | Secrets Manager | Webhook signing secret (≥ 32 bytes) |
| `SV_SIGNIN_LIMITS_EMAIL` | env, optional | Sign-in limits per email, comma-separated `N/window` (default `5/15m,20/24h`; `none` for none) |
| `SV_SIGNIN_LIMITS_SOURCE` | env, optional | Sign-in limits per source (default `20/15m`; `none` for none) |

Secret values are never in the repository. The stack generates both: the
webhook secret is usable as is (the application reads it from the
exported ARN), and the API key hashes start as a random 64-hex placeholder
that matches no known key, so no API key works until the operator stores
the real hashes with `aws secretsmanager put-secret-value` and restarts
the task. The container runs `/service-vault serve` and its health check
is `/service-vault healthcheck`, which probes `GET /health` on
`127.0.0.1` at the `SV_LISTEN` port (the image has
no shell).

**Cost** (us-east-1, MEMBER-SERVICE-PLAN §9): the Spot task is about
$3/month (~$8 on-demand); DynamoDB on-demand, the KMS key ($1), two
secrets ($0.80), logs and transfer are a few dollars more at the member
service's scale. No NAT gateway, interface endpoint or load balancer is
billed.

**Private API.** Every `/v1` route takes `Authorization: Bearer <API key>`.

| Route | Answer |
|---|---|
| `POST /v1/invites` `{email}` | `201 {invite_id, url, expires_at}`: a 10-minute, in-person invitation; `url` is the button on mobile and the QR on desktop |
| `GET /v1/invites/{id}` | `{invite_id, status, sas?, connection_id?}`; `status` is `waiting`, `sas` (show `sas`: the member compares it on the phone and approves), `connected`, `declined` or `expired` |
| `POST /v1/signins` `{email, source?}` | `202 {signin_id, match_code}`, the same way and after the same delay whether or not the email is known and whether or not a rate limit was reached; `source` (optional, at most 64 printable ASCII bytes) is the end user's address as the application sees it, e.g. an IP or its /64, used only for the per-source limit |
| `GET /v1/signins/{id}` | `{signin_id, status, connection_id?, key_changed?}`; `status` is `pending`, `approved`, `denied` or `expired`; `connection_id` and `key_changed` come with `approved` |
| `GET /health` | `{status: "ok"}` (no key) |

**Webhooks** (signed as `sdk/go/webhook` verifies): `connection.pending`
`{invite_id, sas, name}`, `connection.added` `{invite_id, name, email_bound}`,
`connection.declined` / `connection.expired` `{invite_id}`,
`connection.removed` `{direction: in|out}`, `signin.approved`
`{signin_id, key_changed}`, `signin.denied` `{signin_id, reason}`,
`signin.expired` `{signin_id}`, each with its `connection_id`. `name` is
the member's account name as their vault presents it.

**Email binding.** The email entered for an invitation is bound to the
connection it becomes (MEMBER-SERVICE-PLAN §4.1), as an HMAC under the
pepper, and sign-in looks the member up by it. The first active
connection with an email keeps the binding: a later connection made with
the same email is connected but not bound (`email_bound: false` on its
`connection.added`), so it cannot be signed in to by email. When the
bound connection is removed, the binding is freed and the next
connection made with that email binds. `POST /v1/invites` answers the
same either way; the binding is decided when the connection is added,
with a conditional write so that two connections added at once cannot
both bind.

**Sign-in controls** (MEMBER-SERVICE-PLAN §4.2):

- *Two-minute TTL.* The challenge's inner `exp` is two minutes; an
  unanswered sign-in reads `expired`.
- *One pending sign-in per member.* A new sign-in for an email supersedes
  that email's pending one, whether or not the email is bound: the older
  one reads `expired` at once, gets no webhook, and its challenge is
  cancelled on the service's side, so approving it on the phone does
  nothing (VAULT-MESSAGING §10.4 has no message to withdraw a challenge;
  the phone shows it until its `exp`). (chosen; not in the spec)
- *Rate limits*, counted per email and per `source` in fixed windows in
  DynamoDB (so a restart does not reset them): by default 5 per 15
  minutes and 20 per 24 hours per email, and 20 per 15 minutes per
  source (chosen; not in the spec). A sign-in over a limit is answered
  exactly like any other — the same shape, the same delay, a fresh
  `signin_id` and match code — but sends no challenge and expires, so a
  limit reveals nothing about whether an email is known. Every start
  counts, limited or not. The service logs a counter of limited
  sign-ins, never the email or source.
- *Denying on the phone* ends the challenge: the sign-in reads `denied`
  (`signin.denied` with `reason: denied`) and a later answer is ignored.
- *Key change.* `signin.approved` carries `key_changed: true` (and
  `GET /v1/signins/{id}` `"key_changed": true`) when the member signed
  with a credential key other than the one pinned at the connection's
  first sign-in that no rotation chain reaches (VAULT-MESSAGING §10.4).
  The sign-in is still approved; the application decides what to do
  with it (for example ask the member to confirm, or alert).

**Local development** flags of `serve`, never on by default:
`-dev-aws-endpoint URL` (KMS, DynamoDB and SSM at LocalStack) and
`-dev-relay-ca FILE` (also trust a dev relay's CA).

## Go SDK

[`sdk/go/servicevault`](sdk/go/servicevault) is the client for the
private API and the receiver for webhooks; the member API
([vettid/member-service](https://github.com/vettid/member-service)) uses
it exactly as a third party would. It depends only on the standard
library and the two packages beside it: [`sdk/go/pinned`](sdk/go/pinned)
(TLS 1.3, one pinned server key) and [`sdk/go/webhook`](sdk/go/webhook)
(signatures).

```go
c, err := servicevault.New(servicevault.Config{
	BaseURL: "https://service-vault.prod.vettid.internal:8080",
	APIKey:  apiKey, // one whose SHA-256 is in SV_API_KEY_HASHES
	Pin:     pin,    // "sha256/…": the TlsPinParameterName parameter's value
})
inv, err := c.CreateInvite(ctx, email)              // POST /v1/invites
st, err := c.InviteStatus(ctx, inv.ID)              // GET /v1/invites/{id}
si, err := c.StartSignIn(ctx, servicevault.SignInRequest{Email: email, Source: clientIP})
ss, err := c.SignInStatus(ctx, si.ID)               // GET /v1/signins/{id}
err = c.Health(ctx)                                 // GET /health
```

- **Errors.** A non-2xx answer is an `*servicevault.APIError{Status,
  Code}` (`Code` is the body's `error`: `invalid_email`, `not_found`, …);
  `servicevault.IsNotFound(err)` for an unknown id. A server key that
  does not match the pin fails with `pinned.ErrPin`.
- **Retries.** GETs (`InviteStatus`, `SignInStatus`, `Health`) are tried
  up to `GetAttempts` times (3) on network errors and 5xx, with backoff
  from `RetryBackoff` (200 ms, doubling, at most 2 s); 4xx and a pin
  mismatch are not retried. POSTs create something and are never
  retried. `Timeout` (10 s) bounds each attempt; `POST /v1/signins`
  answers after its uniform delay (about 1.5 s).
- **Tests only:** `servicevault.WithHTTPClient(c)` replaces the pinned
  client (then `Pin` is not checked and `BaseURL` may be http).
- **Configuration is the application's.** The SDK has no AWS dependency
  and fetches nothing: the application reads the pin from the SSM
  parameter the stack exports (`ServiceVault-<envName>-TlsPinParameterName`)
  and the webhook secret from the exported `WebhookSecretArn`, and passes
  the values in. The pin changes only if the service vault's TLS key does.

**Webhooks.** `servicevault.Receiver` verifies the signature
(`VettID-Signature` over timestamp, `VettID-Event-Id` and body; default
tolerance 5 minutes), limits the body (64 KiB), checks that the body's
`id` is the signed event id and decodes the event into
`*ConnectionPending{InviteID, SAS, Name}`, `*ConnectionAdded{InviteID,
Name, EmailBound}`, `*ConnectionDeclined{InviteID}`,
`*ConnectionExpired{InviteID}`, `*ConnectionRemoved{Direction}`,
`*SignInApproved{SignInID, KeyChanged}`, `*SignInDenied{SignInID,
Reason}`, `*SignInExpired{SignInID}`, or `*UnknownEvent{Data}` for a
type added later; each embeds `Header{ID, Type, ConnectionID,
CreatedAt}`. With `Replay` set (a `ReplayCache`;
`MemoryReplayCache` is in-process, a shared store makes the check hold
across several receivers) an event id seen within the window is refused.

```go
rc := &servicevault.Receiver{Secret: secret, Replay: &servicevault.MemoryReplayCache{}}
http.Handle("POST /webhooks/service-vault", rc.Handler(func(ctx context.Context, e servicevault.Event) error {
	switch e := e.(type) {
	case *servicevault.SignInApproved:
		// e.SignInID, e.ConnectionID, e.KeyChanged
	}
	return nil
}))
```

`Handler` answers 204 when the function returns nil, 200 for a replayed
event (not handled again), 401 for a signature that is not accepted, 400
for a malformed event, 413 for an oversized body, and 500 when the
function fails, in which case the event id is forgotten and the service
vault's redelivery is handled. Delivery is at least once, so handlers
should be idempotent by event id. `ParseWebhook(r, secret, now)` and
`Receiver.Parse` are the same checks without the handler.

## Documents

| Document | Contents |
|---|---|
| [docs/SERVICE-VAULT.md](docs/SERVICE-VAULT.md) | Architecture and trust model |
| [docs/BALLOT-PROTOCOL.md](docs/BALLOT-PROTOCOL.md) | Secret-ballot protocol (to be written before ballot code) |
| [docs/SOURCE.md](docs/SOURCE.md) | Pinned vettid-vault and vettid-relay commits |

Specifications it implements live in
[vettid/vettid.org](https://github.com/vettid/vettid.org/tree/master/docs):
VAULT-MESSAGING and RELAY-PROTOCOL.

## License

AGPL-3.0. See [LICENSE](LICENSE).

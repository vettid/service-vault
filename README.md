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
phone, [docs/SERVICE-VAULT.md](docs/SERVICE-VAULT.md) §5), admin approvals
of governance actions (§7) and the private API.
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
make svctl        # bin/svctl, the operator CLI (see "svctl")
```

Requires Go 1.26 (`go.mod` pins the toolchain).

`make integration` runs the store and keystore tests on LocalStack.
`make devstack-test` (not in CI) runs the service vault in process
against a real member vault: vettid-vault's dev stack at the pinned
commit (`make devstack-up` in another terminal; about 8 GB of memory and
podman or docker compose), with the member played by its `vaultctl`. It
connects from an invitation, checks that both sides show the same SAS,
approves, checks the title the member's vault shows, signs in with the
match code in the challenge, approves a governance action as the
bootstrap admin (checking the hash in the challenge and the signature in
the audit log) and removes the connection.

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
  -c apiClientSecurityGroupId=sg-<member API task> \
  -c alarmTopicArn=arn:aws:sns:<region>:<account>:<topic>
```

| Context | Required | Meaning |
|---|---|---|
| `image` | yes | Image pinned by digest (`<repo>@sha256:…`); a tag is refused. GHCR (public) or private ECR (the stack grants the pull). |
| `webhookUrl` | yes | Where the application receives signed webhooks (https). |
| `envName` | no (`prod`) | Part of every name and export: stack `ServiceVault-<envName>`. |
| `relayUrl` | no (`https://relay.vettid.org`) | The relay. |
| `serviceName` | no (`VettID Member Service`) | The name members see. |
| `apiClientSecurityGroupId` / `apiClientCidr` | no | Who may reach the API port. Neither: nobody until a rule is added. `apiClientCidr` is IPv4, /16 or narrower (an operator is /32). |
| `vpcCidr` | no (`10.60.0.0/24`) | The VPC (two /26 public subnets). |
| `adminBootstrapEmail` | no | `SV_ADMIN_BOOTSTRAP_EMAIL` (see "Admin approvals"). It is plain text in the task definition and stays in that definition's revisions after a redeploy without it: use an address you don't mind being kept there (a staging test member), or arm the bootstrap with `service-vault admin bootstrap` instead |
| `adminThreshold` | no (1) | `SV_ADMIN_THRESHOLD` |
| `approvalTtl` | no (`24h`) | `SV_APPROVAL_TTL` |
| `recordSealMigrate` | no | `true` only for the deploy that upgrades a deployment from before sealing (see "Records at rest") |
| `alarmTopicArn` or `alarmEmail` | one of them | Where the alarms go (below). Either an SNS topic that reaches a person, or an address for a topic of the stack's own; confirm that subscription from the email AWS sends. For staging, use vettid.org's vault alerts topic, which emails the admin address: `aws ssm get-parameter --name /vettid-org/staging/vault/alerts-topic-arn` |

**Alarms.** They always notify someone: synth fails without a
destination.
- `rotate_conflict`: a member's identity key got two successors, so a
  connection is suspended (see "When a member moves phones").
- `webhook_dropped`: a webhook was given up after 24 hours, so the
  application missed an event.
- `key_change`: the keystore KMS key was changed (a grant, its
  policy, an alias, tags, rotation, disabled, or scheduled for
  deletion). CloudTrail's KMS management events reach EventBridge from
  the account's or the organization's trail; without a trail logging
  management events in the region the alarm never fires. They are kept a
  year in a log group of their own. A deploy that changes the key's
  policy fires it too, as expected.
- `down`: no task has run for 10 minutes. It watches the ECS service's
  CPU samples, which ECS reports without Container Insights. A
  reclaimed Spot task is replaced well within that time.

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
key. No certificate authority is involved.

The stack publishes what the application's stack needs as SSM parameters
under `/vettid/service-vault/<envName>/`: `vpc-id`,
`public-subnet-ids` (comma-separated), `security-group-id`,
`namespace-id`, `namespace-arn`, `namespace-name`, `api-url`,
`webhook-secret-arn` and the TLS pin's `tls-pin`. An application stack
reads them at deploy time. Unlike `Fn::ImportValue`, that never stops
this stack from changing a value later. The application's stack can add
its own ingress rule to the security group instead of passing
`apiClientSecurityGroupId`. The same values are also CloudFormation
exports, `ServiceVault-<envName>-{VpcId, PublicSubnetIds,
SecurityGroupId, NamespaceId, NamespaceArn, NamespaceName, ApiUrl,
WebhookSecretArn, TlsPinParameterName, TlsPinParameterArn}`. Importing
those locks them, so prefer the parameters.

**Records at rest.** Every record the service vault keeps in DynamoDB is
sealed with AES-256-GCM before it is written (`internal/sealstore`):
- the peer's: connections with their session keys, handshakes in
  flight, the tokens members issued, the outbox, the dedupe markers and
  cached responses;
- sign-ins, the email index, approvals, the admin set and the bootstrap
  state;
- both webhook outboxes and the audit log.

The associated data is the record's kind and id, so a record can't be
moved to another place. The record key is kept in the keystore, sealed by
the KMS key that only the task role may use. So the table, or a backup of
it, gives away no traffic, and a table writer can't forge an admin or a
connection. One thing a table writer can still do: put back an older
sealed copy of a record, or delete one. The KMS key policy lets the
account administer the key but not grant itself its use: there is no
`CreateGrant`.

An unsealed record is refused and fails the start. Only the operator
turns on accepting them, for the one deploy that upgrades a deployment
from before sealing. Nothing in the table can turn it on, whether by
deleting a marker or the record key, so nobody can slip in forged
plaintext records.
1. Take an on-demand backup:
   `aws dynamodb create-backup --table-name vettid-service-vault-<env> --backup-name pre-seal`.
2. Deploy with `-c recordSealMigrate=true` (`SV_RECORD_SEAL_MIGRATE=1`).
   The start seals every record in place and logs `records sealed`. If
   it is cut short, the next start goes on.
3. Deploy again without it.

This upgrade is one-way. An image from before sealing can't read sealed
records, so the circuit breaker's rollback to it won't start. If the new
image fails after sealing, deploy a fixed image, or restore the backup
and deploy the old image. A new deployment starts sealed: its first start
creates the record key and needs no migration.

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
| `SV_ADMIN_BOOTSTRAP_EMAIL` | env, optional | The connection bound to this email (from an invitation with a verified email) becomes the first admin, once: the bootstrap is one-shot, and the setting is ignored after it (see "Admin approvals") |
| `SV_ADMIN_THRESHOLD` | env, optional | m: how many distinct admins must approve a governance action (default 1; 1–64) |
| `SV_APPROVAL_TTL` | env, optional | How long an approval stays open (default `24h`; `10m` to `168h`) |

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
| `POST /v1/invites` `{email, email_verified}` | `201 {invite_id, url, expires_at}`: a 10-minute, in-person invitation; `url` is the button on mobile and the QR on desktop. `email_verified` (boolean) is required (`bad_request` without it); see "Email binding" |
| `GET /v1/invites/{id}` | `{invite_id, status, sas?, connection_id?}`; `status` is `waiting`, `sas` (show `sas`: the member compares it on the phone and approves), `connected`, `declined` or `expired` |
| `POST /v1/signins` `{email, source?}` | `202 {signin_id, match_code}`, the same way and after the same delay whether or not the email is known and whether or not a rate limit was reached; `source` (optional, at most 64 printable ASCII bytes) is the end user's address as the application sees it, e.g. an IP or its /64, used only for the per-source limit |
| `GET /v1/signins/{id}` | `{signin_id, status, connection_id?, key_changed?}`; `status` is `pending`, `approved`, `denied` or `expired`; `connection_id` and `key_changed` come with `approved` |
| `POST /v1/approvals` `{action, summary, payload}` | `201 {approval_id, action_hash, status: "pending", expires_at}`; refused with `invalid_action`, `invalid_summary`, `invalid_payload` (400), `invalid_connection`, `unreachable`, `last_admin` (422) |
| `GET /v1/approvals/{id}` | `{approval_id, action, summary, action_hash, status, reason?, threshold, admins, approvals: [{connection_id, at, key_changed}], denials: [{connection_id, at}], created_at, expires_at, applied?}`; `status` is `pending`, `approved`, `denied` or `expired` |
| `POST /v1/approvals/{id}/remind` | `{approval_id, reminded: [connection_id]}`: the challenge again to the admins who have not answered; `too_soon` (429) within 10 minutes of the last, `not_pending` (409) once settled |
| `GET /v1/admins` | `{admins: [connection_id], threshold}` |
| `GET /v1/audit?since=&limit=` | `{entries: [...], next?}`: the audit log after entry `since`, oldest first, `limit` 1–100 (default 100); pass `next` as `since` for the next page |
| `GET /health` | `{status: "ok"}` (no key) |

**Webhooks** (signed as `sdk/go/webhook` verifies): `connection.pending`
`{invite_id, sas, name}`, `connection.added` `{invite_id, name, email_bound}`,
`connection.declined` / `connection.expired` `{invite_id}`,
`connection.removed` `{direction: in|out}`, `signin.approved`
`{signin_id, key_changed}`, `signin.denied` `{signin_id, reason}`,
`signin.expired` `{signin_id}`, each with its `connection_id`. `name` is
the member's account name as their vault presents it. Admin approvals add
`approval.approved` `{approval_id, action, action_hash, applied?}`,
`approval.denied` `{approval_id, action, action_hash, reason}`,
`approval.expired` `{approval_id, action, action_hash}` and
`admin_set.changed` `{admins, added?, removed?, reason, approval_id?}`
(its `connection_id` is the connection added or removed).

**Delivery.** Webhooks wait in the store and go out from their own loop,
in the order they were made (connection and sign-in events in one queue,
approval events in another). An endpoint that is slow or down delays only
the webhooks behind it, never connections, sign-ins or approvals. An
event is done when the endpoint answers 2xx; a 4xx other than 408 and 429
drops it (logged as `webhook rejected`); anything else is tried again
with backoff (1 s, doubling, at most 5 min) until the event is 24 hours
old, when it is dropped (logged as `webhook dropped: undeliverable`) so
the events behind it go out. A dropped event's outcome is still in the
API (`GET` of the invite, sign-in or approval). Answer 2xx, or 4xx to
drop an event you cannot use, rather than failing the same event again.

**Email binding.** The email entered for an invitation is bound to the
connection it becomes (MEMBER-SERVICE-PLAN §4.1), as an HMAC under the
pepper, and sign-in looks the member up by it — **only if the application
has verified that the member controls it.** The service vault cannot send
email, so the application verifies: it emails a one-time code to the
address and has the visitor enter it, and only then asks for the
invitation with `email_verified: true`. With `email_verified: false` the
invitation carries no email at all: the connection is made but never
bound (`email_bound: false`), so it cannot be signed in to by email and
cannot become the first admin. The application **must not** send `true`
for an address it has not verified this way: the first connection bound
to an email keeps it, so binding an unverified address would let anyone
who types someone else's email squat on it: sign-ins with that email
would then challenge the squatter's vault, the owner's own connection
would not be bound, and, when the address is `SV_ADMIN_BOOTSTRAP_EMAIL`,
the squatter would become the first admin. `email_verified` has
no default (a request without it is refused with `bad_request`), so every
application decides. The first active
connection with an email keeps the binding: a later connection made with
the same email is connected but not bound (`email_bound: false` on its
`connection.added`), so it cannot be signed in to by email. When the
bound connection is removed, the binding is freed and the next
connection made with that email binds. `POST /v1/invites` answers the
same either way; the binding is decided when the connection is added,
with a conditional write so that two connections added at once cannot
both bind.

**Sign-in controls** (MEMBER-SERVICE-PLAN §4.2):

- *Five-minute TTL.* The challenge's inner `exp` is five minutes; an
  unanswered sign-in reads `expired`. The member finds the request on
  the phone and enters the credential password, so a website should say
  that the phone will ask for it.
- *One pending sign-in per member.* A new sign-in for an email that is
  within the rate limits supersedes that email's pending one, whether or
  not the email is bound: the older
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
  sign-ins, never the email or source. A sign-in over a limit does not
  supersede the email's pending sign-in, so starting sign-ins with
  someone's email cannot cancel theirs (chosen; not in the spec).
- *Denying on the phone* ends the challenge: the sign-in reads `denied`
  (`signin.denied` with `reason: denied`) and a later answer is ignored.
- *Key change.* `signin.approved` carries `key_changed: true` (and
  `GET /v1/signins/{id}` `"key_changed": true`) when the member signed
  with a credential key other than the one pinned at the connection's
  first sign-in that no rotation chain reaches (VAULT-MESSAGING §10.4).
  The sign-in is still approved; the application decides what to do
  with it (for example ask the member to confirm, or alert).

**When a member moves phones** (VAULT-MESSAGING §3.4, 0.68.0). A
transfer, a recovery or a `credential.rotate` rotates the member vault's
keys, and the service follows each rotation, so the connection survives
the move:
- *Relay key.* `relay.address.update` moves the connection to the new
  mailbox, with the tokens for it. The service answers with fresh tokens
  for the new key, which is the member vault's signal that the service
  has the address. The previous key is still recognized, for messages
  already in flight and for resends of the update, until the first
  message from the new key (or 30 days). The tokens issued to it are then
  revoked. Only the current key can move the connection.
- *Identity and KEM keys.* `identity.rotate`, signed by the old and the
  new key, is followed when it starts at the stored key. The member
  vault's rekey under the new key is then answered, and a rekey the
  service had started under the old keys is dropped. A member that
  rotated while the session was down reconnects with the chain in its
  `hs.init` (§6.6), and the service follows that the same way. Links it
  already followed may come first. If two different
  successors of one key arrive ("one successor per key"), the connection
  is suspended: nothing is sent or accepted, an ERROR with
  `alarm: rotate_conflict` is logged, and the member's next connection
  from a new invitation replaces it. A service can't do the out-of-band
  check that resolves a conflict for a person.
- *Credential key.* `connection.authenticate.rotated` moves the pinned
  key along its chain.

**Admin approvals** (MEMBER-SERVICE-PLAN §4.5, §5.2). Governance actions
need the approval of m admins, signed on their phones. Until contracts
land (Phase 3, `admin-v1`), an approval is a
`connection.authenticate.challenge` (VAULT-MESSAGING §10.4) to each
admin's connection.

- *Admins* are connections, kept in DynamoDB. **Bootstrap:** while the set
  is empty, the connection whose bound email (see "Email binding") is
  `SV_ADMIN_BOOTSTRAP_EMAIL` becomes the first admin, when it is added or,
  if it is connected already, within seconds of the start. Only an email
  the application verified is ever bound, so only a member who proved
  control of that address can become the first admin. The bootstrap is
  **one-shot**: when it sets the first admin it records so in DynamoDB,
  and from then on the setting is ignored (the start logs so), even if
  the set later becomes empty. A store whose set was not empty before
  this record existed is marked at the start. (chosen; not in the spec)
- *Recovering an empty set* takes an explicit operator action:
  `service-vault admin bootstrap -email <address>`, run with the same
  environment as `serve` (for example as a one-off ECS task with the
  service's task definition and the command overridden), arms a new
  one-shot bootstrap in DynamoDB for that address. It is refused while
  the set is not empty, replaces a bootstrap armed earlier, is audited
  (`admin_set.bootstrap_armed`, without the email) and is picked up by
  the running task within seconds; the member then connects from an
  invitation with a verified email, as for the first bootstrap.
- *Changing the set* is itself a governance action: `admin_set.add` and
  `admin_set.remove`, with payload `{"connection_id": "…"}`. The service
  vault applies them when approved (`applied` says whether it still could)
  and sends `admin_set.changed`. The last admin cannot be removed by
  approval (`last_admin`), nor can one whose removal would leave fewer
  admins than m (`unreachable`); with two such removals approved at once
  the second is not applied. A member can always remove their connection,
  though: that takes them out of the set, even the last admin, and is
  recovered only by `service-vault admin bootstrap` or by lowering m.
- *Threshold.* m = `SV_ADMIN_THRESHOLD` (default 1, 1-of-n); each
  approval keeps the m it was created with, so m changes by configuration
  only. m distinct admins (connections) among those asked must approve,
  and only approvals of admins still in the set count: an admin removed
  or severed after approving no longer stands behind the action. A
  denial does not veto: the approval is `denied` only when m can no
  longer be reached (`reason: denied`, or `admins_removed` when admins
  left the set) (chosen; not in the spec). m larger than the number of
  admins is refused at creation (`unreachable`).
- *The request.* `action` is one of `proposal.create`, `vote.open`,
  `vote.close`, `contract_template.change`, `admin_set.add`,
  `admin_set.remove`, `assignment.push`; `summary` is plain text, 1–120
  bytes, without control characters, line separators or bidirectional
  controls; `payload` is a JSON object of at most 16 KiB in canonical
  form. Every admin gets a challenge whose context is
  `Approve on <service name>: <summary> — ref <first 8 hex of action_hash>`
  (at most 256 bytes; a long summary is cut and ends in `…`).
- *The action hash* is
  `hex(SHA-256(JCS({"action": …, "payload": …, "summary": …})))`, JCS
  being the JSON Canonicalization Scheme (RFC 8785): sorted keys (by
  UTF-16 code units), no whitespace, minimal string escaping, numbers as
  ECMAScript prints doubles (carry large integers as strings). Duplicate
  keys, invalid UTF-8 and lone surrogates are refused. The SDK's
  `servicevault.ActionHash` computes it, so the application can check the
  hash it is given; fixed vectors are in
  `sdk/go/servicevault/testdata/action_hash.json`.
- *Timing.* An approval stays open for `SV_APPROVAL_TTL` (24 h); each
  challenge lives 10 minutes, the connauth maximum. `POST
  /v1/approvals/{id}/remind` sends it again to the admins who have not
  answered, at most once per 10 minutes per approval.
- *The member vault's ask gate* (VAULT-MESSAGING §10.4.1) applies to
  admins as to anyone: at most 5 asks per connection in 24 hours, sign-in
  challenges included; after a denial, the service's challenges are in a
  7-day cooldown; three denials within 30 days pause its asks. A
  suppressed challenge is answered as a denial after a delay of 1 to 20
  minutes, so it counts as that admin's denial. Remind sparingly.
- *Outcomes.* `approval.approved` when m admins approved; the application
  applies the action (except `admin_set.*`, applied by the service
  vault). A signature that does not verify is audited and not counted;
  a signature by a changed key counts and is reported
  (`key_changed`).
- *The audit log* (DynamoDB, append-only: each entry written once,
  never changed or deleted; ids increase): every request
  (`approval.requested`, with the canonical payload, the hash, m, the
  admins asked and the challenges), every reminder, every admin's answer
  (`approval.response`: the connection, the request id, the context as
  signed, the answer, whether it counted, and for a signed answer the
  credential key, the signature and `signed_at` — the evidence, which
  verifies against the challenge as VAULT-MESSAGING §10.4 defines it), every
  outcome, and every change of the admin set. Logs carry ids and counts,
  never contexts, summaries or signatures.

**Local development** flags of `serve`, never on by default:
`-dev-aws-endpoint URL` (KMS, DynamoDB and SSM at LocalStack) and
`-dev-relay-ca FILE` (also trust a dev relay's CA); `admin bootstrap`
takes `-dev-aws-endpoint` too.

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
inv, err := c.CreateInvite(ctx, email, servicevault.EmailVerified) // POST /v1/invites; after a one-time code
st, err := c.InviteStatus(ctx, inv.ID)              // GET /v1/invites/{id}
si, err := c.StartSignIn(ctx, servicevault.SignInRequest{Email: email, Source: clientIP})
ss, err := c.SignInStatus(ctx, si.ID)               // GET /v1/signins/{id}
ap, err := c.CreateApproval(ctx, servicevault.ApprovalRequest{
	Action: servicevault.ActionVoteOpen, Summary: "Open the vote on proposal 7",
	Payload: json.RawMessage(`{"proposal":7}`)})   // POST /v1/approvals
st2, err := c.Approval(ctx, ap.ID)                  // GET /v1/approvals/{id}
rm, err := c.RemindApproval(ctx, ap.ID)             // POST /v1/approvals/{id}/remind
ad, err := c.Admins(ctx)                            // GET /v1/admins
pg, err := c.Audit(ctx, since, 100)                 // GET /v1/audit
h, err := servicevault.ActionHash(action, summary, payload) // compare with ap.ActionHash
err = c.Health(ctx)                                 // GET /health
```

- **Invitations.** `CreateInvite` takes `servicevault.EmailVerified`
  only when the application has just verified that the visitor controls
  the address (a one-time code sent to it), otherwise
  `servicevault.EmailUnverified`; the zero value is refused
  (`ErrEmailVerification`), so the choice is always explicit (see
  "Email binding").
- **Errors.** A non-2xx answer is an `*servicevault.APIError{Status,
  Code}` (`Code` is the body's `error`: `invalid_email`, `not_found`, …);
  `servicevault.IsNotFound(err)` for an unknown id. A server key that
  does not match the pin fails with `pinned.ErrPin`.
- **Retries.** GETs (`InviteStatus`, `SignInStatus`, `Approval`,
  `Admins`, `Audit`, `Health`) are tried
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
Reason}`, `*SignInExpired{SignInID}`, `*ApprovalApproved{ApprovalID,
Action, ActionHash, Applied}`, `*ApprovalDenied{ApprovalID, Action,
ActionHash, Reason}`, `*ApprovalExpired{ApprovalID, Action, ActionHash}`,
`*AdminSetChanged{Admins, Added, Removed, Reason, ApprovalID}`, or
`*UnknownEvent{Data}` for a
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

## svctl

`cmd/svctl` (`make svctl`) is a small operator CLI over the private API,
for trying a deployment (staging) before an application is in front of
it. It calls the API only through `sdk/go/servicevault`, so it sees what
an application sees.

| Setting | From |
|---|---|
| API URL | `-url` or `SVCTL_URL` |
| API key | `SVCTL_API_KEY` only: never a flag, never printed |
| Pin | `-pin` or `SVCTL_PIN`; or `-pin-param <name>` (the stack's `TlsPinParameterName`) read from SSM with the default AWS credentials, `-profile` and `-region` optional |

Global flags go before the command; `-poll` (2 s) is how often a flow is
polled.

```sh
svctl invite -email E [-verified] [-no-qr] [-qr-invert] [-wait 11m]
svctl signin -email E [-source S] [-wait 3m]
svctl approve -action vote.open -summary "Open the vote" -payload '{"proposal":7}' [-wait 30m]
svctl remind <approval id>
svctl admins
svctl audit [-since <entry id>] [-limit 100]
svctl health
```

- `invite` prints the invitation's id, expiry and URL and the URL as a QR
  code (half-block characters, for a dark terminal; `-qr-invert` for a
  light one), then follows the invitation, printing each status, the
  `sas` when it appears (compare it with the phone) and the connection
  id. `-verified` sends `email_verified: true`: use it only for an
  address whose control was verified (see "Email binding"); without it
  the invitation carries no email.
- `signin` prints the match code (the member finds it in the request on
  the phone) and follows the sign-in to `approved` (with `connection_id`
  and `key_changed`), `denied` or `expired`.
- `approve` prints the approval's id and action hash, checks the hash
  against `servicevault.ActionHash` of what it sent, and follows it to
  its outcome (the approving admins, `reason`, `applied`).
- `audit` prints one JSON entry per line; when there are more, stderr
  says which `-since` gives the next page.
- `-wait 0` creates without following. Exit status: 0 done (connected,
  approved), 3 another outcome (declined, denied, expired), 1 an error or
  stopped waiting, 2 a usage or configuration error.

Emails are sent as given and are not printed back.

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

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
MEMBER-SERVICE-PLAN §9 describes. Nothing is deployed from CI. Check the digest's provenance first
([Verifying an image](#verifying-an-image)).

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
| `apiClientSecurityGroupId` / `apiClientCidr` | no | Who may reach the API port. Neither: nobody until a rule is added. `apiClientCidr` is a private (RFC 1918) IPv4 range, /16 or narrower: the task has a public IP, so a public range would expose the API port. For an operator's direct access, one public address (`/32`) is allowed with `-c apiClientCidrPublic=true`, still behind the pinned TLS key and an API key. Drop it once the application is the only client. |
| `vpcCidr` | no (`10.60.0.0/24`) | The VPC (two /26 public subnets). |
| `adminBootstrapEmail` | no | `SV_ADMIN_BOOTSTRAP_EMAIL` (see "Admin approvals"). It is plain text in the task definition and stays in that definition's revisions after a redeploy without it: use an address you don't mind being kept there (a staging test member), or arm the bootstrap with `service-vault admin bootstrap` instead |
| `adminThreshold` | no (1) | `SV_ADMIN_THRESHOLD` |
| `approvalTtl` | no (`24h`; `1h` unless `envName` is `prod`) | `SV_APPROVAL_TTL`. The stack also sets `SV_CHANNEL`: `production` only when `envName` is `prod` (as for `SV_SIGSTORE`), `staging` for every other `envName`; and it refuses an `approvalTtl` above `1h` for `staging` |
| `longApprovalChallenges` | no (off) | `true` sets `SV_LONG_APPROVAL_CHALLENGES` (see "Admin approvals", Timing). Set it for a channel only once that channel's member-vault release carries VAULT-MESSAGING 0.82.0 (staging: release 26). `-c longApprovalChallenges=true` or absent; the stack refuses it for `envName` `prod` (production waits for a production member-vault release with 0.82.0) |
| `approvalAllowNoPurpose` | no | `true` sets `SV_APPROVAL_ALLOW_NO_PURPOSE` (see "Admin approvals"): only while an admin's vault predates purposes |
| `testSignIns` | no | `true` sets `SV_TEST_SIGNINS` (see `POST /v1/signins/unsigned`): testing only, so the stack refuses it unless `envName` is `staging`. Context is not remembered: a staging deploy without `-c testSignIns=true` turns the route off again |
| `recordSealMigrate` | no | `true` only for the deploy that upgrades a deployment from before sealing (see "Records at rest") |
| `recordKeyVersion` | no (1) | `SV_RECORD_KEY_VERSION`, the lowest record key version to use: set it one above the table's to rotate the record key (see "Rotating the record key"). Leaving it out later is fine |
| `alarmTopicArn` or `alarmEmail` | one of them | Where the alarms go (below). Either an SNS topic that reaches a person, or an address for a topic of the stack's own; confirm that subscription from the email AWS sends. For staging, use vettid.org's vault alerts topic, which emails the admin address: `aws ssm get-parameter --name /vettid-org/staging/vault/alerts-topic-arn` |

**Alarms.** They always notify someone: synth fails without a
destination.
- `rotate_conflict`: a member's identity key got two successors, so a
  connection is suspended (see "When a member moves phones").
- `webhook_dropped`: a webhook was given up after 24 hours, so the
  application missed an event.
- `reconnect_failed`: after a table restore, a connection's reconnect
  could not start or complete, so that member must connect again (see
  "Restoring the table").
- `reconnect_slow`: such a reconnect is unanswered after a day. It
  stays open for 7 days, since a locked member vault answers when it is
  unlocked.
- `vote_unpublished`: members sent vote requests for a proposal the
  service holds but has not published, or its close was refused (at most
  one line per proposal per 10 minutes). They get no answer, and the vote
  can't close, until it is published (`POST /v1/proposals/{id}/publish`).
  Publish at once. Member vaults send an unanswered cast again at 1, 5
  and 30 minutes, then hourly, and stop at the close, so if the close is
  less than about 1 h 10 min away, also extend the vote (a verified
  extension restarts each vault's schedule; the service logs a WARN when
  it publishes that late). An extension needs the admins' `vote.extend`
  approval, an outage of over an hour that is over and inside the window
  (from the loss to the publication), a request more than a minute
  before the close and at most 24 h in all; a publication lost within
  the last hour or so before the close can't be covered, and casts that
  went unanswered then may not be counted. If publishing fails, fix the
  publisher (Rekor, the timestamp authority, the votes site) and publish
  again: the close stays refused until it succeeds, and publishing works
  at any time, also after the close. A member vault restored meanwhile
  may show the vote as being checked until the member opens it again or
  checks it in the app.
- `count_clock_ahead`: a vote's close has passed by the service's clock
  but not by the timestamp authority's (BALLOT-PROTOCOL §7, 0.13.12:
  just before counting, the service asks the authority for the time, a
  stamp with no transparency-log entry). The vote is not counted yet:
  the close answers 503 `collecting`, and no cast is refused `late` for
  it. Probes are rationed: a passing one holds for that close; after one
  before the close, none until the authority's time, judged from it, can
  have reached the close, but never more than 5 minutes later. The waits
  are timed on the process's monotonic clock, so stepping the task's
  wall clock neither lengthens nor cuts them, and a corrected clock never
  starves the close. Each probe has its own 5 s timeout. Check both clocks, as for
  `results_stamped_early`. A probe that fails (the authority unreachable,
  or a stamp that doesn't verify) counts nothing either: the close
  answers 503 `timestamp_unavailable` and raises `tsa_unavailable`,
  whose ERROR line says why; probes after a failure are at least 10 s
  apart.
- `results_stamped_early`: a vote's results came back from the timestamp
  authority stamped before their close, so the service's clock is more
  than a minute ahead of the authority's (BALLOT-PROTOCOL §8.3 step 2:
  every member vault would fail them; `skew_seconds` on the line is the
  difference seen). They are not published, and the close answers 503
  `stamped_early`. Check both clocks: the task's (Fargate takes it from
  the Amazon Time Sync Service; compare with `date -u` on a trusted host)
  and the authority's (the stamp's time on the line). Then close again.
  Each anchor is a permanent public entry in the transparency log, so
  they are rationed: at most one per close, and none until a probe of the
  authority's time (no log entry, at least 10 s apart) is at or after the
  close (`rec#vote_stamp_wait` keeps the early stamp); a close before
  then answers `stamped_early` at once. Member vaults keep checking for
  7 days, so a late publication is still judged.
- `results_bundle_unverified`: a vote's results bundle failed its
  timestamp check (the authority's signature, the pinned trusted root, or
  its validity period); the results are not published. One anchored by
  that close is dropped, so the next close anchors again; one kept from
  an earlier close stays, as the site may hold it, and blocks the
  results until it is dealt with. The ERROR line names the proposal and
  the error. First check whether votes.vettid.org has the results
  (`GET /v1/p/<proposal id>/results.json`): if it does, keep the bundle
  and fix the check (often a release whose pinned trusted root is out of
  date). If it doesn't, delete the kept bundle, item pk
  `rec#vote_bundle`, sk the hex SHA-256 of the results document
  (`aws dynamodb delete-item --table-name T --key
  '{"pk":{"S":"rec#vote_bundle"},"sk":{"S":"<hex>"}}'`), and close
  again.
- `ballot_not_counted`: a stored ballot failed the count's re-check
  (tag, credential signature or time) and was left out; the ERROR line
  names the proposal and the tag.
- `ballots_off`: the ballot copy's key (`ballot-copy-key`) is missing
  while proposals or copied ballots exist, or isn't the key the copy's
  ballots are under (the copy holds a key check). The daemon runs with
  votes off, so sign-ins and approvals go on; restore the keystore item
  from a backup of the table. After a table restore with votes off, the
  ballots the restore lost are put back from the copy at the first start
  with votes on (marker `run#ballots_rebuild`).
- `gov_migration_waiting`: an admin's governance key (see "Governance
  key" under "Admin approvals") can't be pinned yet, because the service
  doesn't know that admin's connection (logged at most once an hour per
  admin, `connection_id` on the line). Until it can, that admin's
  governance approvals (`admin_set.*`, `admin.repin`, `proposal.create`,
  `vote.extend`, `contract_template.change`) are recorded but don't count.
  Check that the connection is active and reachable (a reconnect after a
  restore, a suspended connection); if it is gone, repair the admin set.
- `admins_short`: an admin's connection was removed (severed, or
  replaced by a new connection) and fewer admins than m remain, so no
  approval can pass (see "Recovering admins" under "Admin approvals").
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
- `task_stopped`: a task stopped on its own: it exited, failed its
  health check or failed to start. A crash loop keeps it raised, while
  `down` may stay quiet because short-lived tasks still report CPU.
  Stops by a deploy, a scale-in, a Spot reclamation or an operator
  (stop codes `ServiceSchedulerInitiated`, `SpotInterruption`,
  `UserInitiated`) don't raise it, except a failed health check.
- `deploy_failed`: the circuit breaker failed a deployment and rolled it
  back.
- `errors`: 5 or more ERROR lines in 15 minutes that no alarm above
  covers (DynamoDB, KMS or the relay failing).

ECS's own events for this cluster (task state changes and the service's
deployments) go to a log group of their own, kept a month, for
`task_stopped` and `deploy_failed`. Each EventBridge rule that writes to
a log group adds an account-wide CloudWatch Logs resource policy
(10 per region): this stack has three, the key changes', the ECS
events' and the control-plane rules' below (one policy for all ten),
so staging and prod in one account and region use 6 of the 10.

**Control-plane alarms.** Someone with AWS access to the account (not the
enclave) could run a task under the task role and read the keystore, or
move the TLS pin. These alarms watch the API calls that make that
possible. They need CloudTrail management events (read and write)
delivered to EventBridge in this region from the account's or the
organization's trail; this stack assumes one and creates none (a second
trail would be a second cost, and without any trail the alarms never
fire). The trail must log read and write management events and must not
exclude KMS (`ExcludeManagementEventSources` must not list
`kms.amazonaws.com`): `Decrypt` and `ReEncrypt` are read-only events,
which reach only a rule in the state
`ENABLED_WITH_ALL_CLOUDTRAIL_MANAGEMENT_EVENTS` (the `keystore_decrypt`
rule is in it; the others are write events). Matches are kept a year in a log group of their own. Verify them
once on staging by making each call.

| Alarm | Fires on | In a deploy? |
|---|---|---|
| `notice-taskdef_registered` | `ecs:RegisterTaskDefinition` for this service's family | **Yes**, every deploy that changes the task definition (new image, setting) |
| `notice-service_updated` | `ecs:UpdateService` on this service | **Yes**, every deploy that changes the service, and a manual scale or force-new-deployment |
| `run_task` | `ecs:RunTask` or `ecs:StartTask` in this cluster | No: never normal (the service scheduler starts its tasks without a RunTask call by the operator) |
| `taskrole_use` | the task role used outside the service: `RegisterTaskDefinition` naming the task role (ARN or short name) in another family; `RunTask`, `StartTask`, `CreateService` or `CreateTaskSet` naming this family (any cluster); `UpdateService` naming this family on another service, in another cluster or in the default cluster; a `RunTask` or `StartTask` override of the task role | Once, on the first create or when CloudFormation replaces the service (its own `CreateService` names the family); not on ordinary deploys |
| `keystore_decrypt` | `kms:Decrypt`, `ReEncrypt` on the keystore key by any caller but a session of the task role | No (the operator's `table restore` does not use the key) |
| `tls_pin_change` | `ssm:PutParameter`, `DeleteParameter`, `DeleteParameters` on the TLS pin parameter by any caller but a session of the task role | Once, on the first deploy, when CloudFormation creates the parameter; and whenever a CloudFormation update touches the `TlsPin` resource, which rewrites its value |
| `taskrole_policy_change` | `iam:UpdateAssumeRolePolicy`, `AttachRolePolicy`, `PutRolePolicy` on the task role (us-east-1 only, see Limits) | Yes, a deploy that changes the task role's permissions (CloudFormation puts its policy); otherwise never |

The two `notice-` alarms are the operator's own deploy and are expected
with it: a change in either with no deploy under way is the alert. The
others are never expected. Limits:

- `iam:PassRole` is not a CloudTrail event (CloudTrail records the call
  that uses the passed role), so `taskrole_use` watches the places the
  role is passed instead: registering any task definition with it,
  or running, starting or creating a service from this one.
- `keystore_decrypt` and `tls_pin_change` exclude by the role that
  issued the session, so code running under the task role elsewhere
  looks like the service. `run_task` and `taskrole_use` are the alarms
  for how it would get there; nothing here tells a task role session on
  another network from the service's own.
- IAM events reach EventBridge only in us-east-1, so
  `taskrole_policy_change` (the trust policy, which lets another
  principal assume the task role without any task) is created only when
  the stack is in us-east-1. In another region it does not exist and
  the trust policy is not watched.
- The CloudTrail event reaches EventBridge a few minutes late, and a
  caller who can stop the trail, or the EventBridge rules or alarms, is
  not watched by these; keep those out of reach in the same way.

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
start and every hour after, in case a stack update puts back the
parameter's initial `unset`, and the application's client (`sdk/go/pinned`) accepts only that
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

Each keystore item's data key is bound to a KMS encryption context,
`{"blob": <item name>}`, so that the key's policy can allow `Decrypt` only
for the items it names (key protection, phase 1). Items sealed before
contexts still open without one. `service-vault admin reseal-blobs`, run
by the operator as a one-off task in the same environment as `serve`
(the service stopped), moves every item to its context: each is sealed
again and put only over its exact old bytes, never deleted first, and
then each is opened with its context. The anchor-key item is left as it
is, without a context, for deletion, so that no copy of it can be opened
once the policy is in place. It prints the items' names, never their
contents, and a run again picks up where one stopped. After it, a table
or backup from before can't be restored into this deployment (its keys
can't be opened once the policy is in place): the re-seal is the last
point to roll back to a release before it. The policy that requires the
context (its allow-list covers record-key.v* and ballot-copy-key, and
never matches anchor-key), and the deletion of the anchor-key item, are
later steps, each on the owner's go.

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
image fails after sealing, deploy a fixed image. Going back to the old
image means restoring the step 1 backup ("Restoring the table") and
deploying the old image on it. A new deployment starts sealed: its first
start creates the record key and needs no migration.

The keys are never made again over existing records. If the record key
(its current version, with no older one to rotate from) or the secrets are missing from a table that holds records, the start
fails ("the table holds records but no keys"). A new record key would
leave every record unreadable, and new secrets would replace the
service's identity, so the way back is restoring the table.

**Rotating the record key.** The record key is versioned: each record
names the version it is sealed under. The write-once copy of accepted
ballots (`SV_BALLOTS_TABLE`) is sealed under a key of its own
(`ballot-copy-key` in the keystore), which a rotation doesn't touch: its
items can't be rewritten, so they can't be resealed, and that key is
kept for as long as the ballots are. Never delete it. The copy holds a
check of it, so a start doesn't make a new one while proposals or copied
ballots exist, and finds a key that isn't the copy's; either turns votes
off with the `ballots_off` alarm. Records under version 1 keep the
layout from before versions, so this image can still be rolled back to
an older one until the first rotation. To rotate:
1. Take an on-demand backup (as in "Restoring the table"). The deploy
   before must not have had `recordSealMigrate`: an image from before
   versions, rolled back to with the migration on, would take the new
   records for unsealed ones.
2. Deploy with `-c recordKeyVersion=<the table's version + 1>`
   (`SV_RECORD_KEY_VERSION`). The table's version is in the last
   `record key rotated` log line; it is 1 before the first rotation. The
   start makes the new version and reseals every record under it, and
   logs `record key version made` (WARN).
3. Start the service again, by a deploy or
   `aws ecs update-service --cluster T --service T --force-new-deployment`.
   That start reseals anything written under the older versions since
   (an admin run that started before the rotation), deletes them from
   the keystore, and logs `record key rotated` (WARN). Don't run
   `service-vault admin` between steps 2 and 3.

The version in use is always the table's: the highest of the setting,
the version the table's records are under, and any later version in the
keystore. So later deploys may leave the setting out, and a task with an
older setting (the circuit breaker's rollback, an admin run from an
older task definition) uses the new version and finishes a rotation cut
short. A setting more than one above the table's is refused, as is a
missing current version over records ("the table holds records but no
keys").

The start reads every record before the API listens, so with a large
audit log it can outlast the health check's grace (30 s, then 3 checks
30 s apart). The reseal keeps what it has done, so the next start goes
on from there. Expired records still in the table stay under the old
version until DynamoDB deletes them; nothing reads them. A backup holds
the versions of its time: after restoring one from before a rotation,
the table is back on the older version. If the stack's setting is still
one above it, the next start rotates again (step 3 then retires the old
version); otherwise rotate as above.

**Restoring the table.** A last resort: it puts the service vault back
as it was at the backup, and loses everything since:
- connections made since, and members' key and relay changes since
  (VAULT-MESSAGING §3.4);
- sessions rekeyed since (§6.5: every active connection rekeys at least
  daily), and tokens refreshed since (§7.2);
- sign-ins, approvals, admin changes and audit entries since;
- webhooks not yet delivered. Webhooks delivered between the backup and
  the restore are in the restored outbox again and are **sent again**:
  the application must ignore ids it has seen (as for any retry).

*What members see.* While the service is stopped (about 5 minutes on
staging, most of it DynamoDB's restore), sign-ins and connections fail,
and the member site shows its "didn't complete" step. After it, a
connection whose state didn't change since the backup works as before
(a restore minutes back, past a sign-in, did on staging). One that
rekeyed, refreshed its tokens or changed keys or relay address since the
backup would stop working (sign-in requests don't reach the phone;
nothing is leaked). So the first start after `table restore` reconnects
every active connection (§6.6): it names its last epoch, which the
member's vault still keeps in its history, carries fresh tokens, and
follows any identity rotation the member made since; it logs
`restored: reconnects started` and `reconnected` per connection. A
reconnect completes when the member's vault next collects, usually
within minutes; until then nothing is sent on that connection (its
sign-ins fail). A restart keeps it open as it was, resending an
unconfirmed deposit with the same bytes; a new one goes out only if that
state was lost, at most 3 per restore (the member's reconnect token
allows 4 messages). If the member's vault starts its own reconnect
meanwhile, the service's yields to it. One that can't
start, or isn't completed within 7 days, fails: the connection becomes
stale, `reconnect_failed` alarms, and the member connects again from a
new invitation, which replaces the old connection (admins then also
need "Recovering admins"). This is VAULT-MESSAGING 0.72.1 §6.6 "After a
restore": the member's vault accepts the older epoch on a service
connection for 35 days after it was superseded, so a backup older than
that fails too; member vaults need the release that has it, and until
then every such reconnect fails. A member who changed relay address
since the backup, past its grace period, connects again in any case.

Before an upgrade that can't be rolled back, take an on-demand backup
right before it, so the loss is minutes. Point-in-time recovery is on,
so a restore can also pick a time within the last 35 days.

DynamoDB restores into a new table, and the stack owns its own table, so
the restored items are copied back into it. With `<env>` the
environment and `T` = `vettid-service-vault-<env>` (the table, the ECS
cluster and the service share the name):
1. Stop the service:
   `aws ecs update-service --cluster T --service T --desired-count 0`,
   then `aws ecs wait services-stable --cluster T --services T`, and
   check that `aws ecs describe-services --cluster T --services T`
   shows `runningCount` 0. Until step 4, don't run `cdk deploy`: it sets
   the desired count back to 1. The `-down` alarm notifies after 10
   minutes stopped; that is expected.
2. Restore into a new table, `T-restore`, from a backup:
   `aws dynamodb restore-table-from-backup --target-table-name T-restore --backup-arn <arn>`
   (`aws dynamodb list-backups --table-name T` lists them), or to a
   point in time:
   `aws dynamodb restore-table-to-point-in-time --source-table-name T --target-table-name T-restore --restore-date-time <time>`
   (`aws dynamodb describe-continuous-backups --table-name T` shows the
   earliest). Then `aws dynamodb wait table-exists --table-name T-restore`;
   a restore can outlast the wait, so run it again until the table is
   `ACTIVE`.
3. Copy it back:
   `service-vault table restore -from T-restore -to T`, built from this
   repository with the operator's AWS credentials. It first checks that
   `T-restore` is a finished restore of `T` (a swapped `-from` and `-to`
   fails), that both hold the same keys (another deployment's table
   fails), and that no task has written its heartbeat to `T` in the last
   2 minutes (the daemon writes one every 30 seconds, deletes it when
   it stops, and stops itself after 90 seconds of failed writes; the
   heartbeat is read again before the deletes). Then it writes every item of `T-restore` into `T`, deletes
   the items `T` has that `T-restore` lacks, prints the counts, and
   leaves a restore marker in `T` for the next start (above). If it is
   cut short, run it again. `-other-keys` is only for a `T` the
   daemon started on after the original table was lost: its new keys are
   replaced by the backup's. It also refuses a backup newer than an
   earlier restore's (in the last 35 days) but older than when that
   restore was done: members' vaults took the epochs of that span for
   replaced ones, and would read a backup from it as a second copy of
   the service and suspend every connection (VAULT-MESSAGING §6.6 "Fork
   detection"). To retry a restore, use the same backup or an older one;
   `-newer-point` overrides, knowing every member must then connect
   again.
   A restore during a vote, or before its close, also brings back the
   backup's record of messages left unacked (kind `unacked`): one handled
   since the backup holds the count again for up to its 24 hours and
   then counts in `unhandled`, and one given up on since the backup is
   forgotten if the relay has dropped it, so `unhandled` can come out too
   high or too low. Note such a restore with the results.
4. If the image changes too, deploy it now. Start the service:
   `aws ecs update-service --cluster T --service T --desired-count 1`.
5. Check `/health`, the TLS pin, the `reconnected` lines and a member's
   sign-in. Then delete `T-restore`.

The operator needs: `dynamodb:CreateBackup`, `ListBackups`,
`DescribeContinuousBackups`, `RestoreTableFromBackup` or
`RestoreTableToPointInTime` (with `PutItem`, `UpdateItem`, `DeleteItem`,
`GetItem`, `Query`, `Scan` and `BatchWriteItem` on `T-restore`, which a
restore requires), `DescribeTable` on both tables, `GetItem` and `Scan`
on `T-restore`, `GetItem`, `Scan` and `BatchWriteItem` on `T`,
`DeleteTable` on `T-restore`, and `ecs:UpdateService` and
`ecs:DescribeServices` on the service.

Rolling the image back past the reconnect after a restore (to
`53a8c41` or older) is safe only when no member's reconnect awaits its
`hs.fin`: an older image would install the epoch without the tokens and
rotation links the reconnect brought. Check the logs for
`reconnected` / `epoch installed` lines settling every reconnect first.

The KMS key must be the one the backup was made under: the stack's key,
which is retained and never deleted with the stack.

**Container configuration.**

| Variable | Source | Meaning |
|---|---|---|
| `SV_RELAY_URL` | env | Relay base URL |
| `SV_TABLE` | env | DynamoDB table name |
| `SV_BALLOTS_TABLE` | env | The write-once DynamoDB table of accepted ballots (BALLOT-PROTOCOL §6); without it, members' vote requests are answered `unsupported_type` |
| `SV_SIGSTORE` | env | `staging` or `production`: the Sigstore instance votes are anchored in (BALLOT-PROTOCOL §3.3); required with `SV_BALLOTS_TABLE`. The CDK sets `production` for the `prod` stack and `staging` otherwise |
| `SV_VOTES_URL` | env | votes.vettid.org (or staging's): where proposals, extensions and results are published, each anchored in Rekor first (BALLOT-PROTOCOL §3.3). Without it, creating a proposal answers `publication_not_configured`. The CDK sets it from the `votesUrl` context |
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
| `SV_APPROVAL_LIMITS` | env, optional | Limits on creating approvals, counted per group of actions (the repair actions `admin.repin`, `admin_set.add` and `admin_set.remove` in one, every other action in the other), comma-separated `N/window` (default `2/1h,4/24h`; `none` for none) |
| `SV_APPROVAL_TTL` | env, optional | How long an approval stays open (default `24h`; `10m` to `168h`; with `SV_CHANNEL=staging`, default `1h` and at most `1h`) |
| `SV_LONG_APPROVAL_CHALLENGES` | env, optional | `true` sends an approval challenge with the approval's own expiry, at most 24 hours, and reminds only admins holding no live challenge (VAULT-MESSAGING 0.82.0 §10.4); default `false`: 10 minutes, and a reminder challenges every admin who has not answered. Turn it on for a channel only once that channel's member vaults carry 0.82.0 (staging: release 26): an older member vault cuts the challenge to 10 minutes without telling the service. Only `true` turns it on; any other value but `false` stops the start (chosen; not in the spec) |
| `SV_CHANNEL` | env, optional | `staging` or `production` (default `production`); anything else stops the start. The default is production, so a staging run outside the CDK stack must set `SV_CHANNEL=staging` itself. On `staging` an approval lasts at most 1 hour (STAGING-TIME-SCALE N16; VAULT-MESSAGING 0.82.0 §10.4), and so does its challenge |
| `SV_APPROVAL_ALLOW_NO_PURPOSE` | env, optional | `true` counts approvals signed without a purpose (vaults before VAULT-MESSAGING 0.65.0), marked `no_purpose`; default `false`, which audits them and doesn't count them (§10.4). For a transition only |
| `SV_TEST_SIGNINS` | env, optional | `true` serves `POST /v1/signins/unsigned` (`svctl signin -unsigned`); default `false`, when it answers `403 test_only`. For testing only: it sends members a sign-in they did not start. A malformed value stops the start |
| `SV_RECORD_KEY_VERSION` | env, optional | The lowest record key version to use (default 1; see "Rotating the record key") |

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
| `POST /v1/signins/unsigned` | For testing only: `403 {error: test_only}` and nothing sent unless `SV_TEST_SIGNINS=true`. Otherwise `200 {signins: [{connection_id, signin_id?, match_code?, skipped?}], more, stopped?}`: one sign-in challenge to each eligible connection (active, vault advertises the vote feature) that has no pinned credential key, i.e. whose member has never signed in on it, so that its vault does not refuse their vote with `not_signed_in` (VAULT-MESSAGING §10.19.5). A call goes through the connections in id order until it has sent 10 challenges or looked at 100 connections; a skipped connection counts only toward the 100, so connections skipped for long do not keep the call from the ones after them. `more` is the number not yet looked at (call again). Within the member vault's limits (§10.4.1): never a second challenge to a connection with a sign-in pending, none within an hour of a decline, at most 10 in 24 h (a challenge that expires unanswered counts; they live 5 minutes); a connection left out says `skipped`: `pending`, `declined`, `daily_limit`, `not_sent`, or `not_recorded` (sent, with its `match_code`, but no `signin_id` to read). An error or the call's 8-second deadline ends it early with `stopped` (`error` or `timeout`) and the entries done so far, still status 200; the call goes on server-side if the client gives up. Each `signin_id` is read at `GET /v1/signins/{id}`, and its outcome is a `signin.*` webhook: the application did not start these sign-ins, so it will see webhooks for ids it does not know. A member's app tells them to approve a sign-in only if they are signing in right now, and one they did not start teaches the opposite, so a real service must not use this: its members sign in themselves. For test connections (`svctl signin -unsigned`) |
| `POST /v1/approvals` `{action, summary, payload}` | `201 {approval_id, action_hash, status: "pending", expires_at, ask_budget?}`, where `ask_budget: [{connection_id, next_ask_at}]` (omitted when empty) lists the admins left out because they have their ask limit of approval challenges still counting (4, or 5 for `admin.repin`, `admin_set.add` and `admin_set.remove`), `next_ask_at` being when their oldest counting challenge stops counting (its expiry plus 24 hours plus the clock skew); refused with `invalid_action`, `invalid_summary`, `invalid_payload` (400), `invalid_connection`, `unreachable`, `last_admin`, `sole_admin` (422); refused with `ask_budget` (409: fewer admins than the threshold can be asked, because the others are at their ask limit; nothing is sent or stored); refused with `rate_limited` (429) past `SV_APPROVAL_LIMITS` for the action's group, counted once the request passes every other check (one refused for being invalid or for `ask_budget` does not count; one refused with `rate_limited` does). Of each admin's 5 approval asks per 24 hours, every action but the repair ones stops at 4, reminders included: the fifth is kept for repairs, so a burst of ordinary approvals from a runaway or buggy application cannot leave the admins unaskable for a change to the admin set. It does not stop a holder of the API key who means harm: repair approvals of their own spend the fifth. A declined approval challenge starts no cooldown in a member vault from VAULT-MESSAGING 0.83.10 (an older one still starts a 7-day cooldown, §10.4.1) |
| `GET /v1/approvals/{id}` | `{approval_id, action, summary, action_hash, payload (canonical; admin.repin's carries the new_key the service filled in), status, reason?, threshold, admins, approvals: [{connection_id, at, key_changed, counted}], denials: [{connection_id, at}], created_at, expires_at, remind_needed: [connection_id], remind_after?, applied?}`; `status` is `pending`, `approved`, `denied` or `expired`; `counted` is `false`, with `reason` `key_changed` or `not_repinned` (and `gov_key_changed: true`), for a governance action (`admin_set.add`, `admin_set.remove`, `admin.repin`, `proposal.create`, `vote.extend`, `contract_template.change`) signed with a key other than the admin's governance key (see *Governance key* below): it does not count toward the threshold, never applies an `admin_set.*` or `admin.repin` change and is audited with that reason; the admin stays in `remind_needed`; `assignment.push` counts it as before; `remind_needed`, while pending, lists the admins who have not answered and hold no live challenge (it ran out, or could not be sent); `remind_after` comes with it: the earliest a reminder is accepted |
| `POST /v1/approvals/{id}/remind` | `{approval_id, reminded: [connection_id]}`: the challenge again to the admins who have not answered and hold no live challenge (the `remind_needed` ones); `too_soon` (429) within 10 minutes of the last, `not_pending` (409) once settled, `nothing_to_remind` (409) when every admin who has not answered still holds a live challenge. An optional body `{"force": [connection_id, ...]}` (chosen; not in the spec) challenges only the named admins again, each even with a live challenge (the old one is withdrawn first): `not_admin` (422) for one outside the approval's admins or the current set, `answered` (409) for one who has answered, `ask_budget` (409) for one at the approval's ask limit, from any approval (4 approval challenges that still count, or 5 for a repair action; each counts until its expiry plus 24 hours, since the member's vault may receive it as late as its expiry; a sixth would come back as a delayed denial); still `too_soon` within 10 minutes of the last. The answer carries the same `ask_budget` list (omitted when empty), and so does `GET /v1/approvals/{id}` for the `remind_needed` admins at the budget. Without a body, an admin at that budget is left out (and stays in `remind_needed`), and `ask_budget` (409) answers when that leaves nobody to challenge (an admin whose ask log cannot be read counts as at the budget), checked before `too_soon` and before anything is withdrawn. Each forced re-send spends one of that admin's 5 approval asks per 24 h (§10.4.1): use it only when the admin reports not seeing the request |
| `GET /v1/admins` | `{admins: [connection_id], threshold}` |
| `GET /v1/audit?since=&limit=` | `{entries: [...], next?}`: the audit log after entry `since`, oldest first, `limit` 1–100 (default 100); pass `next` as `since` for the next page |
| `POST /v1/proposals` `{approval_id, title, text, choices, quorum, binding, removed_may_vote, opens_at, closes_at, outage_rule}` | Needs `approval_id`: the admins' `proposal.create` approval of exactly this input (see "Admin approvals"); it is checked and used up once (`approval_required` 400 without one; `approval_not_found`, `approval_not_approved`, `approval_wrong_action`, `approval_mismatch`, `approval_expired` 403; `approval_used` 409). `201 {proposal_id, proposal_hash, eligible, unsigned, sending}`: the proposal is made from the active connections at this moment whose vault advertised the vote feature (BALLOT-PROTOCOL §3.2), published, and sent to each in the background (BALLOT-PROTOCOL §3): `sending` is how many it is being sent to, and a member a send misses asks with `vote.status`; choices are `{label}` only: the service assigns the ids `c1`, `c2`, … and always adds `abstain`; `text` is empty or the title, `quorum.text` empty, `outage_rule` empty or the default (see "Admin approvals"). `unsigned` is how many of the `eligible` connections have no pinned credential key: their member has never signed in on the connection, and their vault refuses `vote.cast` with `not_signed_in` until they do (VAULT-MESSAGING §10.19.5); members sign in to the service themselves (on a test deployment only, `POST /v1/signins/unsigned`, `svctl signin -unsigned`). `invalid_proposal` (400) for one outside the bounds of BALLOT-PROTOCOL §3.1 (member vaults refuse those) or with no such connection; `too_many_eligible` (400, with `max_eligible`: 15000) when the roster has more than 15,000 eligible members, before the approval is used (requesting the `proposal.create` approval already answers `too_many_eligible` then, before the admins are asked) (a chosen limit, bounded by the results' single upload to the votes site; BALLOT-PROTOCOL §3.2); `publication_not_configured` (503) until publication is configured; `503 {error: not_published, proposal_id}` when it was kept but its publication failed (retry with `/publish`). Served with `SV_BALLOTS_TABLE` |
| `GET /v1/proposals/{id}` | `{proposal_id, proposal, proposal_hash, eligible, opens_at, closes_at, published}`: nothing that counts ballots before the results |
| `POST /v1/proposals/{id}/publish` | `{sending}`: publishes a proposal whose publication failed, and sends it again to each eligible member in the background (`sending` is how many; 0 when those sends are still running, as it doesn't send twice, when the service is stopping, or once the results are published, when members are sent `vote.closed` instead). A proposal not published is no member's: a cast on it is `not_eligible`, `vote.status` `unknown_proposal`. `not_found` (404) |
| `POST /v1/proposals/{id}/extend` `{approval_id, closes_at, outage: {from, to, source}}` | Needs `approval_id`: the admins' `vote.extend` approval of exactly this extension of this proposal, used up once (the same errors as creating). The extension (BALLOT-PROTOCOL §10.2), published and sent to each member in the background: for a relay outage of over an hour within the window that is over (its `to` not after now), by its length rounded up to the hour, 24 h in all at most; an outage still going on near the close is extended in parts (§10.2). `invalid_extension` (400), `outage_not_over` (422) for an outage still going on, `too_late` (409) once the close has passed. Requesting the `vote.extend` approval itself answers `outage_not_over` (422) for an outage still going on. A vote has at most 24 extensions (`invalid_extension` past that) |
| `POST /v1/proposals/{id}/close` | Needs only the API key: it publishes what the closed vote counted and decides nothing (it is refused before `closes_at` + 1 minute). `{proposal_id, results_hash, tally, counts}`: counts the vote and publishes the results (BALLOT-PROTOCOL §7), or reports them if already published. `not_closed` (409) before `closes_at` + 1 minute; `collecting` (503) until the relay's messages from before then are all handled: retry; `stamped_early` (503) while the results come back from the timestamp authority stamped before the close (the service's clock is ahead: see the alarm `results_stamped_early`). A retry is safe: it anchors nothing until the authority's time can have reached the close, so retry with backoff, and fix the clock. `collecting` is also the answer while the timestamp authority's time is before the close (0.13.12: the service's clock alone never starts the count), and `timestamp_unavailable` (503) when the authority's time can't be had or verified: retry |
| `GET /v1/proposals/{id}/results` | `{results, results_sig, rows, bundle}` once published |
| `GET /v1/anchor-key` | `{anchor_key, anchor_cert, service_ik, sigstore}`: the service's anchor key (DER SubjectPublicKeyInfo), certified by its identity key, for registering the service on votes.vettid.org (BALLOT-PROTOCOL §3.3) |
| `GET /health` | `{status: "ok"}` (no key) |

**Webhooks** (signed as `sdk/go/webhook` verifies): `connection.pending`
`{invite_id, sas, name}`, `connection.added` `{invite_id, name, email_bound}`,
`connection.declined` / `connection.expired` `{invite_id}`,
`connection.removed` `{direction: in|out}`, `connection.suspended`
`{reason: rotation_conflict}`, `signin.approved`
`{signin_id, key_changed}`, `signin.denied` `{signin_id, reason}`,
`signin.expired` `{signin_id}`, each with its `connection_id`. `name` is
the member's account name as their vault presents it. Admin approvals add
`approval.approved` `{approval_id, action, action_hash, applied?}`,
`approval.denied` `{approval_id, action, action_hash, reason}`,
`approval.expired` `{approval_id, action, action_hash}`,
`approval.challenge_expired` `{approval_id, action, connection_id,
request_id, expires_at}` (an admin's challenge ran out unanswered while
the approval is still open: every challenge without
`SV_LONG_APPROVAL_CHALLENGES`, which lasts 10 minutes, and a third
concurrent long one with it; remind them; not sent when the challenge ended
with the approval, which is reported as `approval.expired`) and
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
  cancelled, so approving it on the phone does nothing. The service
  sends the member's vault `connection.authenticate.withdraw`
  (VAULT-MESSAGING 0.80.0 §10.4), which closes the ask on the phone; a
  vault before 0.80.0 drops it, and the phone shows the ask until its
  `exp`. An approval's challenges are withdrawn the same way when it is
  decided, reminded or its admin leaves the set. (chosen; not in the
  spec, beyond the withdraw)
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
  is suspended: nothing is sent or accepted, its sign-ins and
  approvals can't be answered, an ERROR with `alarm: rotate_conflict` is
  logged, and the application gets `connection.suspended` (chosen; not
  in the spec). The member's next connection from a new invitation
  replaces it: `connection.removed` for the suspended one, then
  `connection.added`, and the email binding moves to the new one. A service can't do the out-of-band
  check that resolves a conflict for a person. An admin's new connection
  is not an admin: the conflict may mean someone else holds the member's
  keys, so the role comes back only by the other admins' approval or the
  operator (see "Recovering admins").
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
- *Recovering admins.* An admin whose connection is removed leaves the
  set, also when a new connection replaces it (after a suspension, for
  example); the new one is an ordinary member (chosen; not in the
  spec). While m admins remain, the others bring them back with
  `admin_set.add` for the new connection id. When fewer than m remain,
  no approval can pass and `admins_short` alarms: lower
  `SV_ADMIN_THRESHOLD` (`adminThreshold`, a deploy) and approve the add, or, when the set
  is empty, arm a bootstrap for their verified email (below); a member
  already connected with that email becomes the admin within seconds.
  Keep at least m + 1 admins so that losing one blocks nothing.
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
- *Governance key.* Besides the credential key pinned at the last
  sign-in, which moves with every signed sign-in, the service pins a
  governance key per admin: the credential key the connection has when it
  becomes an admin (`admin_set.add` applied, or the bootstrap; for an admin
  from before this existed, at start). A rotation chain that starts at it
  moves it on (continuity), and nothing else does but `admin.repin`. A
  governance approval (`admin_set.add`, `admin_set.remove`, `admin.repin`,
  `proposal.create`, `vote.extend`, `contract_template.change`) counts only
  if it is signed with the governance key; otherwise it is recorded with
  `counted: false` and `reason` `key_changed` (a key the service had not
  seen) or `not_repinned` (a key it has seen sign in since), audited so,
  and the admin can be asked again. `Consume` and the threshold count only
  approvals that count, and `admin_set.*` and `admin.repin` are never
  applied on one that doesn't. `assignment.push` is not governance and
  counts as before. An ordinary sign-in (and a vote) works with the new
  key; only governance waits for the re-pin.
- *Re-pinning.* `admin.repin`, payload `{"connection_id": "…", "new_key":
  "<base64 of the 32-byte credential key>"}` (`new_key` may be left out:
  the service fills in the connection's credential key now), makes the
  connection's current credential key its governance key. It is approved by
  m admins other than the one re-pinned, or all the other admins if
  there are fewer than m (owner decision of 2026-11-02: with 2 admins at
  m = 2 the other one re-pins after asking out of band; never fewer than
  one, counted among the admins in the set when it settles and is
  applied, so removing admins to lower it takes `admin_set.remove`
  approvals at the full m, or an admin leaving on their own); they alone are asked and their own approval
  never counts for their own re-pin; the approvals count as above, and is applied (`admin.repinned` audited) only if `new_key` is
  still the connection's credential key. The application gives no
  `summary`; the service writes `name given "<name>", new key <16 hex
  digits in 4 groups>, key changed <YYYY-MM-DD HH:MM> UTC, connection
  <id>`: the fingerprint is `SHA-256("vettid/vms/2/ck-fp" || key)` (the
  first 16 hex digits) and the time that of the first sign-in with the new
  key. **Before approving, the other admins ask the admin out of band, by
  phone or in person, "did you reset your credential at <that time>?",
  and have them read out the credential-key fingerprint from their app
  (Settings → Vault status, VAULT-MESSAGING 0.83.8 §10.8); they approve
  only on a clear yes and a matching `new key`.** An app that does not
  show it yet leaves the question alone as the check. A summary that says "key changed time not
  recorded" means the key changed before this release recorded it: the
  admins then need a stronger out-of-band check (in person, or by a
  channel they already trust) before approving.
  Know that a stolen copy of the vault, still holding the old key, can
  rotate the governance key away from the real admin's and lock the real
  admin out; they then need a re-pin too. With one admin a re-pin is
  refused (`sole_admin`): a sole admin whose key changed has no one to
  confirm it: the connection is removed (which empties the set) and the
  operator arms `service-vault admin bootstrap` for a new one
  (`ArmBootstrap` is refused while the set is not empty).
  *After the API key may have been misused* (bogus approvals the admins
  declined): rotate the API key first. A member vault from
  VAULT-MESSAGING 0.83.10 starts no cooldown and counts no pause for a
  declined approval challenge, but an older one starts a 7-day cooldown
  of the service's approval challenges, repairs included, and three
  declines in 30 days pause every ask of the connection; a pause, and
  declines recorded before an upgrade, outlast the upgrade. So unless you
  know an admin's vault carries 0.83.10 and their connection to the
  service is not paused, ask them, out of band, to tap "Allow again" on
  the service's connection in their app (`connection.asks.resume`)
  before you create the `admin.repin` or `admin_set.*` approval. It is
  harmless on any release: it clears declines and cooldowns and ends a
  pause.
  `svctl approve -action admin.repin -payload '{"connection_id":"…"}'`
  runs it; `svctl approval` shows an approval that did not count as
  `not_counted: <connection> reason=…`, and each admin who did not
  approve as `not_approved_by: <connection>` (it printed `denied_by`
  before: a denial may be the admin's vault's, for a muted or paused
  service, VAULT-MESSAGING §10.4.1). `approvals[]` of the status answer
  lists every admin's answer, including approvals that do not count
  (`counted: false`); only `counted: true` ones count toward the threshold.
- *Pinning at the start.* The governance key of an admin that has none (one
  from before it existed) is pinned at a tick after the peer has loaded its
  connections, from the audit log: the credential key of the admin's
  earliest signed approval since they became an admin (`gov_key.migrated`,
  reason `evidence`, with the key's fingerprint and `key_changes_seen`
  when a later approval was signed with another key; if the connection holds
  another key now, it needs a re-pin), or with no signed approval at all
  the connection's current credential key (reason `no_evidence`). Open
  governance approvals holding approvals are ended (`expired`, reason
  `gov_key_migrated`) so the admins approve again. `admin_set.add` pins the
  credential key whose fingerprint its summary shows (`cred key <16 hex
  digits>`), and only if it is still the connection's credential key when
  applied; otherwise nothing is applied and `gov_key.refused` is audited.
  The migration ends once (a stored marker `gov_migrated`, written after
  the expiry, so a failure in between retries it); until then and always, a
  governance approval stored without a `counted` field never stands
  (`reason: legacy_unpinned`), and pending ones, and approved
  `proposal.create` and `vote.extend` not yet used, are expired. Known
  limits: the evidence is only what the audit log holds, and the
  fingerprints the admins compare are 64 bits of a SHA-256.
  An approval's threshold is the higher of the one it was created with and
  the current m when it settles and when it is applied.
- *Bootstrap confirmation.* The connection bound to the bootstrap email
  does not become the first admin by itself: the service records it with
  the fingerprint of its identity key (logged, and shown by
  `service-vault admin bootstrap -connection ID`, with the time the
  connection was made and the invitation it came through, so the operator
  can ask the member out of band "did you connect at <time> from the
  invitation we sent?"), and the operator
  confirms with `service-vault admin bootstrap -connection ID -fingerprint
  16HEX` after checking the fingerprint with the member out of band. Its
  governance key is the credential key of its first sign-in.
- *Threshold.* m = `SV_ADMIN_THRESHOLD` (default 1, 1-of-n); each
  approval keeps the m it was created with, so m changes by configuration
  only. m distinct admins (connections) among those asked must approve,
  and only approvals of admins still in the set count: an admin removed
  or severed after approving no longer stands behind the action. A
  denial does not veto: the approval is `denied` only when m can no
  longer be reached (`reason: denied`, or `admins_removed` when admins
  left the set) (chosen; not in the spec). m larger than the number of
  admins is refused at creation (`unreachable`).
- *The request.* `action` is one of `proposal.create`, `vote.extend`,
  `contract_template.change`, `admin_set.add`, `admin_set.remove`,
  `admin.repin`, `assignment.push`; `summary` is plain text, 1–120
  bytes, without control characters, line separators or bidirectional
  controls; `payload` is a JSON object of at most 16 KiB in canonical
  form. Every admin gets a challenge whose context is
  `Approve on <service name>: <label> <summary> — ref <first 16 hex of action_hash>`
  (at most 256 bytes; a long summary is cut and ends in `…`). The label is
  the service's, by action: `New vote:` (`proposal.create`), `Extend vote:`
  (`vote.extend`), `Add admin:` (`admin_set.add`), `Remove admin:`
  (`admin_set.remove`), `Re-pin admin:` (`admin.repin`), `Contract template:` (`contract_template.change`),
  `Push assignment:` (`assignment.push`). For `admin_set.add` and
  `admin_set.remove` the application gives no `summary` (`invalid_summary`):
  the service writes `name given "<name>", connected <date>, key <16 hex
  digits in 4 groups>, cred key <16 hex digits in 4 groups>, connection <id>` for the connection (the credential key is the one pinned as its governance key). The name is the one the
  member's vault sent when it connected, so the wording says it is
  self-declared; it is shown whole, at most 32 characters of printable
  ASCII and Latin-1 letters, or the approval is refused (`field_not_shown`).
  The date is when the connection was activated. The key is the first 4 of the 8 groups of 4 of the
  fingerprint of the connection's identity key,
  `SHA-256("vettid/vms/2/ik-fp" || ik)` (VAULT-MESSAGING §10.8). The
  member's own app does not show it; an admin connected to that member can
  compare it with the vault key fingerprint on their own connection with
  them, as the vault presents one `ik` everywhere. An added connection that is unknown, not active, or has no
  pinned credential key (it has never signed in) is refused
  (`invalid_connection`); removing a connection the service no longer
  knows names only its id. An application's summary can't
  start with a label's words or with `BINDING`, `ADVISORY` or `EXTEND`
  (`invalid_summary`). `SV_SERVICE_NAME` is at most 32 bytes (the service
  vault refuses to start with a longer one), so that a summary built from
  a payload is always shown whole.
- *Proposals and extensions.* A binding vote is started or extended only
  with an approval, used once.
  - `proposal.create`'s payload is the proposal input of `POST
    /v1/proposals` (without `approval_id`) and `vote.extend`'s is
    `{proposal_id, closes_at, outage: {from, to, source}}`, each in
    canonical form (JCS, above) with every field present and exactly
    cased; the service refuses any other form (`invalid_payload`). The
    choices are `{label}` only: the service assigns the ids `c1`, `c2`, …
    in order and adds `abstain` (the ids a vote's ballots name). `text`
    must be empty or the title, `quorum.text` empty, `outage_rule` empty
    or the default (`field_not_shown`); a label is at most 24 characters,
    distinct and not `Abstain`; titles and labels use printable ASCII and
    Latin-1 letters only (`unsupported_characters`), and a title is shown
    whole or the approval is refused (`field_not_shown`); an extension's `outage.source` is an
    `https://` URL of at most 32 bytes of visible ASCII, and its proposal must exist (the
    admins read its title: `unknown_proposal`). These
    two approvals take no `summary` (`invalid_summary` if one is given):
    the service builds what the admins read from the payload: `BINDING` or
    `ADVISORY`, the window, the quorum's minimum, the choice labels and
    the title (cut to fit, never the rest), or for an extension the
    proposal, the new close and the outage. A payload whose text cannot
    be shown whole (control or bidirectional characters, too many or too
    long labels, times outside the years 2000–2200) is refused.
  - `POST /v1/proposals` and `/extend` take `approval_id`. Under the
    approval manager's lock the service checks that the approval is
    approved (its threshold met by the admins in the set now, counted
    again, so an approver removed since no longer counts) and has not run out (`SV_APPROVAL_TTL`
    from its creation), is for that action, and that its payload equals,
    byte for byte, the canonical form of the input in the request, so no
    field comes from the request that was not approved. Then it records
    use (an `apv_used` record written only if absent, and an
    `approval.consumed` audit entry, in one write), and only then makes
    the proposal or the extension. Two uses at once: one succeeds.
  - The use is recorded with the proposal's id (and the extension's
    number) in `apv_used`, the `approval.consumed` audit entry and the
    approval's status (`used`), so a lost answer is resolved by reading it.
    An extension asked for less than a minute before the close is refused
    (`too_late`) before the approval is used.
  - Whatever refuses the input (a bad window, no eligible member, no
    publisher) is checked before the approval is used, so the approval
    stays usable. What fails after (storing, publishing) leaves it used:
    the admins approve again (fail closed). A proposal stored and not
    published is published with `/publish`, with no new approval.
  - `/close` needs no approval: it publishes the count of a vote that has
    already closed. Whether an early close is ever wanted is open.
- *The action hash* is
  `hex(SHA-256(JCS({"action": …, "payload": …, "summary": …})))`, JCS
  being the JSON Canonicalization Scheme (RFC 8785): sorted keys (by
  UTF-16 code units), no whitespace, minimal string escaping, numbers as
  ECMAScript prints doubles (carry large integers as strings). Duplicate
  keys, invalid UTF-8 and lone surrogates are refused. The SDK's
  `servicevault.ActionHash` computes it, so the application can check the
  hash it is given; fixed vectors are in
  `sdk/go/servicevault/testdata/action_hash.json`.
- *Timing.* An approval stays open for `SV_APPROVAL_TTL` (24 h; 1 h on
  staging, `SV_CHANNEL`).
  - With `SV_LONG_APPROVAL_CHALLENGES=true` each challenge lives as long
    as the approval, at least 10 minutes and at most 24 hours
    (VAULT-MESSAGING 0.82.0 §10.4, "Long-lived approval challenges";
    member vault release 26 and later), so an admin whose vault is held
    (its daily owner check, §3.6.3) sees it after passing the check.
    Sign-in challenges stay at 10 minutes. A member vault keeps at most 2
    long-lived challenges per connection and cuts a third to 10 minutes
    without telling the sender, and one before release 26 cuts every one:
    the service vault cannot see that. So it sends at most 2 long
    challenges per connection at a time (a third goes with 10 minutes; a
    place frees when its challenge ends or is withdrawn, and one whose
    withdraw could not be queued counts until its expiry) (chosen; not in
    the spec), and the flag is for channels whose member vaults are all on
    release 26 or later. A challenge that ends with the approval raises no
    `approval.challenge_expired`; the approval's `approval.expired` is
    reported. `POST /v1/approvals/{id}/remind` then sends only to the
    admins who have not answered and hold no live challenge (each re-send
    uses the member vault's approval bucket, below), at most once per 10
    minutes per approval; with none it answers `nothing_to_remind` (409)
    before `too_soon`, and `svctl remind` says so and exits 0 (`too_soon`
    exits non-zero) (chosen; not in the spec). The same holds for the
    member vault's limit of 4 challenges held per connection: a long
    challenge sent while 4 are held (live ones and withdraws not queued,
    counted until their expiry plus a minute for clock skew) goes with 10
    minutes. Known limits: a withdraw that reaches a held member vault
    before its challenge is ignored there, so the member keeps the
    challenge and its place until its expiry while the service has freed
    them; and a challenge the member vault loses for another reason (a
    vault restore, a deposit refused for good) leaves that admin
    unremindable until the challenge's expiry, at most 24 h (1 h on
    staging). For these, `svctl remind -force <connection_id>` (`POST
    /v1/approvals/{id}/remind` with `{"force": [...]}`) withdraws that
    admin's live challenge and sends a new one, once per 10 minutes per
    approval. Each forced re-send spends one of the admin's 5 approval asks
    per 24 hours (§10.4.1), and a sixth would come back as a delayed
    denial, which counts as a denial, so the service refuses a force
    (`ask_budget`) for an admin at the approval's ask limit: 4 approval
    challenges that still count, the fifth being kept for `admin.repin`
    and `admin_set.*`, or 5 for those. It counts each one until its expiry plus 24 hours, since
    a challenge held in the outbox can reach the member's vault as late as
    its expiry, so it never counts fewer than the member's vault does.
    The log starts empty when this version is first deployed, so for
    up to a challenge's expiry plus 24 hours after that, challenges sent
    before it are not counted. Every send is checked: creating an approval,
    a plain reminder and a force skip an admin at the budget, who shows in
    `remind_needed`. Creating an approval answers `ask_budget` (409), sending
    nothing and storing nothing, when fewer admins than the threshold can
    be asked (an admin whose log cannot be read counts as not askable); a
    plain reminder answers `ask_budget` (checked before `too_soon`) when every admin it would
    challenge is at the budget or has a log that cannot be read, before anything is withdrawn. Use a force only when the admin reports not seeing the
    request. If the withdraw was lost, the member may then see
    two requests for the same approval: they should approve the newest (an
    answer to the older one is ignored by the service).
  - Without it (the default, for member vaults before release 26) each
    challenge lives 10 minutes and the service vault reports a run-out challenge as below. When a
    challenge runs out while the approval is open the service vault sends
    `approval.challenge_expired`, the approval's status lists the admin in
    `remind_needed` (`svctl approval ID` prints "remind needed"), and a
    reminder challenges every admin who has not answered, replacing their
    challenge. An admin whose vault is held sees no challenge once the 10
    minutes pass.
- *The member vault's ask gate* (VAULT-MESSAGING 0.65.0 §10.4.1, member
  vault release 24 and later) applies to admins as to anyone. Approval
  challenges (`purpose: "approval"`) have their own bucket: at most 5 per
  connection in 24 hours, apart from sign-in challenges (10 per 24 hours,
  their own). From VAULT-MESSAGING 0.83.10 an admin's denial of an
  approval challenge starts no cooldown and does not count toward a
  pause; an older member vault puts further approval challenges from the
  service in a 7-day cooldown and counts the denial toward a pause (three
  within 30 days pause every ask of the connection). A sign-in denial
  cools only sign-ins, for 1 hour. Mute and pause, and the 8 pending
  asks, cover every kind together. A suppressed challenge is answered as a denial after a
  random delay of 1 to 20 minutes, but at the latest 1 minute before the
  challenge expires (so within about 9 minutes of a 10-minute challenge),
  and it counts as that admin's denial. A sixth approval challenge to a
  connection within 24 hours is suppressed this way (it never reaches the
  admin and comes back as a delayed denial): remind sparingly.
- *Outcomes.* `approval.approved` when m admins approved; the application
  applies the action (except `admin_set.*`, applied by the service
  vault). A signature that does not verify is audited and not counted;
  so is an approval signed without a purpose (a vault before
  VAULT-MESSAGING 0.65.0: nothing in its signature shows it was an
  approval, §10.4), with reason `no_purpose`, unless
  `SV_APPROVAL_ALLOW_NO_PURPOSE=true` (a transition only: it then counts,
  still marked `no_purpose`);
  a signature by a changed key counts and is reported
  (`key_changed`).
- *The audit log* (DynamoDB, append-only: each entry written once,
  never changed or deleted; ids increase): every request
  (`approval.requested`, with the canonical payload, the hash, m, the
  admins asked and the challenges), every reminder, every admin's answer
  (`approval.response`: the connection, the request id, the context as
  signed, the answer, whether it counted, and for a signed answer the
  credential key, the signature, the purpose it covers, `signed_at`, and
  what else the signature covers: the challenge's `nonce`, `service_ik`
  and the admin's `member_ik` — the evidence, which verifies from the
  entry alone against the challenge as VAULT-MESSAGING §10.4 defines it,
  with `approval.AuditEntry.Verify`; entries written before the nonce and
  the identity keys were kept can't be verified this way), every
  outcome, and every change of the admin set. Logs carry ids and counts,
  never contexts, summaries or signatures.

**Local development** flags of `serve`, never on by default:
`-dev-aws-endpoint URL` (KMS, DynamoDB and SSM at LocalStack) and
`-dev-relay-ca FILE` (also trust a dev relay's CA); `admin bootstrap`
takes `-dev-aws-endpoint` too.

### Verifying an image

CI's `publish` job signs build provenance for each image it pushes
(SLSA v1, GitHub artifact attestations on Sigstore's public instance),
stored next to the image in GHCR. Check it before a digest goes into a
deployment:

```sh
make verify-image IMAGE=ghcr.io/vettid/service-vault@sha256:<digest>
```

It runs `gh attestation verify` (GitHub CLI) and passes
only for an image built by this repository's `ci.yml` from `main` on a
GitHub-hosted runner. The output names the source commit; it should be
the one being deployed. Images published before provenance was added
have none and fail the check.

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
us, err := c.StartUnsignedSignIns(ctx)              // test deployments only; POST /v1/signins/unsigned; us.SignIns, us.More
ap, err := c.CreateApproval(ctx, servicevault.ApprovalRequest{
	Action: servicevault.ActionContractTemplateChange, Summary: "Change the member contract",
	Payload: json.RawMessage(`{"template":7}`)})   // POST /v1/approvals
st2, err := c.Approval(ctx, ap.ID)                  // GET /v1/approvals/{id}
rm, err := c.RemindApproval(ctx, ap.ID)             // POST /v1/approvals/{id}/remind (extra args: force these admins)
ad, err := c.Admins(ctx)                            // GET /v1/admins
pg, err := c.Audit(ctx, since, 100)                 // GET /v1/audit
h, err := servicevault.ActionHash(action, summary, payload) // compare with ap.ActionHash
pr, err := c.CreateProposal(ctx, approvalID, input) // POST /v1/proposals; approvalID: an approved ActionProposalCreate approval of input
ex, err := c.ExtendProposal(ctx, proposalID, approvalID, input) // POST /v1/proposals/{id}/extend; an ActionVoteExtend approval
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
`*ApprovalChallengeExpired{ApprovalID, Action, RequestID, ExpiresAt}`,
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
svctl signin -unsigned
svctl approve -action contract_template.change -summary "Change the contract" -payload '{"template":7}' [-wait 30m]
svctl approval <approval id>
svctl remind [-force <connection id>,...] <approval id>
svctl admins
svctl audit [-since <entry id>] [-limit 100]
svctl anchor-key
svctl proposal create -in proposal.json [-wait 30m] [-approval <approval id>]
svctl proposal extend <proposal id> -in extension.json [-wait 30m] [-approval <approval id>]
svctl proposal status|publish|close|results <proposal id>
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
- `signin -unsigned` is for testing only (staging test connections);
  members of a real service must sign in themselves. With
  `SV_TEST_SIGNINS` off the service vault answers `403 test_only` and
  `svctl` says so and exits 1. It sends one sign-in challenge to each eligible
  connection that has never signed in (no pinned credential key), sending
  at most 10 challenges and looking at 100 connections per run (a skipped
  one counts only toward the 100), and prints for each the `signin_id` and match code, or `skipped:` and why
  (`pending`, `declined`, `daily_limit`, `not_sent`, `not_recorded`);
  `more:` says how many connections have not been looked at yet, and
  `stopped:` that an error or the deadline ended the run early. It
  keeps within the member vault's limits for sign-in challenges
  (VAULT-MESSAGING §10.4.1): none to a connection with one pending,
  none within an hour of a decline, at most 10 in 24 h. It does not wait
  for the answers: each `signin_id` is read at `GET /v1/signins/{id}`.
  When the run stopped early (`stopped:`) it exits 1, after printing
  what it did; run it again. The member's app shows the request
  unasked, with "Only approve if you are signing in right now". That is
  why it is for testing only: routine use would teach members to
  approve sign-ins they did not ask for. With test members, tell each
  one first and read out the match code. A decline
  costs that connection a 1-hour cooldown; a challenge lives 5
  minutes, and one that expires unanswered still counts toward the 10
  a day. The service emits `signin.*` webhooks for these
  `signin_id`s, which the application did not start. On a test
  deployment, run it after every new vote-capable connection and
  before creating a proposal.
- `approve` prints the approval's id and action hash, checks the hash
  against `servicevault.ActionHash` of what it sent, and follows it to
  its outcome (the approving admins, `reason`, `applied`). While
  following it also prints `remind needed: <ids> (svctl remind <id>)`
  whenever that list changes.
- `approval ID` prints an approval's status, threshold, approving and
  denying admins and `applied`, and `remind needed: <ids> (svctl remind
  <id>)` (with `after HH:MM:SSZ` while a reminder would still answer
  `too_soon`). It exits 0 whatever the status, unlike `approve`.
- `audit` prints one JSON entry per line; when there are more, stderr
  says which `-since` gives the next page.
- `anchor-key` and `proposal` print the API's JSON answers (see
  "Votes"). `proposal create` first asks the admins to approve the file's
  input (it fills in every field and sends the canonical form; the
  summary the admins read is built by the service and checked here
  against the one svctl builds), waits for them (`-wait`; or uses
  `-approval` for one already approved), then posts the input with the
  approval and is never retried (a retry would make a second proposal,
  and the approval is used up whatever the outcome); `proposal extend ID`
  does the same for an extension (`{closes_at, outage}`). A proposal
  kept but not published (`503 not_published`) is named on stderr, with
  the `proposal publish` command that retries it. When the answer's
  `unsigned` is above 0, `proposal create` also warns on stderr that
  that many eligible connections have never signed in and their vaults will
  refuse to vote until they do (the hint: ask them to sign in to the
  service once; on a test deployment, `svctl signin -unsigned`); the exit status is unchanged.
  `proposal close`
  answers `collecting` until the relay's messages are in: run it again.
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

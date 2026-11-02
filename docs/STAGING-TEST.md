# Staging test: connect, sign in, approve

The Phase 1 gate (MEMBER-SERVICE-PLAN §10): a member's phone connects to
the service vault from a link, signs in by email, and a governance action
waits for an admin's approval on the phone. Two people: an **operator**
with staging AWS access who runs `svctl`, and a **member** with the
staging VettID app on a real phone, a staging account and an enrolled
vault.

Nothing secret goes in tickets, chats that are logged, or GitHub: no API
keys, PINs, passwords or invite links (an invite link is a one-time
credential for 10 minutes). Addresses are written shortened.

## 0. Operator: environment

```sh
export AWS_PROFILE=<staging profile>     # VettIDAdmin on the staging account
make svctl                               # bin/svctl
T=$(aws ecs list-tasks --cluster vettid-service-vault-staging --query 'taskArns[0]' --output text)
ENI=$(aws ecs describe-tasks --cluster vettid-service-vault-staging --tasks "$T" \
  --query "tasks[0].attachments[0].details[?name=='networkInterfaceId'].value" --output text)
IP=$(aws ec2 describe-network-interfaces --network-interface-ids "$ENI" \
  --query 'NetworkInterfaces[0].Association.PublicIp' --output text)
export SVCTL_URL=https://$IP:8080
export SVCTL_API_KEY=$(cat <your staging API key file>)   # never on the command line
alias sv='bin/svctl -pin-param /vettid/service-vault/staging/tls-pin -profile "$AWS_PROFILE"'
sv health && sv admins
```

The task's public IP changes when it restarts; repeat the lookup. The API
port admits only the operator's address (`apiClientCidr`).

## 1. Operator: make the member the first admin

The member's staging account email was verified at signup. Deploy with
it as the bootstrap email (one-shot; it is never used again once an
admin exists):

```sh
cd cdk && npx cdk deploy -c envName=staging -c image=<digest> \
  -c webhookUrl=<url> -c apiClientCidr=<operator ip>/32 \
  -c adminBootstrapEmail=<member email> -c testSignIns=true
```

`testSignIns=true` sets `SV_TEST_SIGNINS`, which "Before a vote" below
needs; the stack accepts it on staging only. CDK context is not
remembered: a staging deploy without `-c testSignIns=true` turns the
route off again.

## 2. Connect

1. Operator: `sv invite -email <member email> -verified`. It prints the
   link and a QR code and waits.
2. Member: scan the QR with the VettID app (or open the link on the
   phone) within 10 minutes. The app shows a connection request from
   **VettID Member Service** with a security code.
3. Operator: `svctl` prints `sas: …` when the handshake completes. Read
   it to the member over a channel you trust (voice); the member checks
   it matches the phone and approves.
4. Operator: `svctl` prints `status: connected` and the connection id.
   Member: the connection is titled **VettID Member Service**.
5. Operator: `sv admins` lists the member's connection.

## 3. Sign in by email

1. Operator: `sv signin -email <member email>`. It prints a two-digit
   match code.
2. Member: the app shows **Authenticate to a connection**, from VettID
   Member Service, with the note *Sign in to VettID Member Service —
   match code NN*. Check the code matches what the operator reads out,
   then Authenticate (the app asks for the password if the credential is
   locked).
3. Operator: `status: approved`.

### Before a vote: every connection signs in once

A member's vault refuses `vote.cast` with `not_signed_in` until it has
signed a sign-in challenge on that connection (VAULT-MESSAGING §10.19.5);
a connection that was made again has to sign in again. After every new
vote-capable connection, and before creating a proposal, run the steps
below. This is for testing only: it needs the `-c testSignIns=true`
deploy above (without it the service vault answers `403 test_only`), and
a real service's members sign in themselves.

1. Operator: `sv signin -unsigned`. It sends one challenge to each
   eligible connection that has never signed in (it sends at most 10
   challenges and looks at 100 connections per run; run it again while
   it prints `more:`, or exits 1 with `stopped:`) and prints each
   match code (or why it skipped one: a challenge already pending, a
   decline within the hour, 10 in 24 h). It does not wait.
2. Operator and member: tell each member to expect it and read out the
   match code. The app shows an unrequested sign-in with "Only approve
   if you are signing in right now"; the member authenticates as in
   step 3 above only if the code matches. A challenge lives 5 minutes.
3. Operator: `sv proposal create` prints a warning on stderr, and
   `unsigned` above 0 in its answer, if a connection is still unsigned;
   run step 1 again and have that member authenticate before the vote
   opens.

## 4. Admin approval

1. Operator:
   `sv approve -action proposal.create -summary "Staging test proposal" -payload '{"test":true}'`
2. Member: the note reads *Approve on VettID Member Service: Staging test
   proposal — ref xxxxxxxx*; the ref matches the first 8 hex digits of the
   `action_hash` `svctl` printed. Authenticate.
3. Operator: `status: approved`; `sv audit` shows the request and the
   signed answer.

On staging an approval lasts at most 1 hour (`SV_CHANNEL=staging`, which
the stack sets; a staging run outside it must set it itself, the default
being production; the stack refuses a longer `approvalTtl`). Deploy with
`-c longApprovalChallenges=true` only once the staging member vault is
on release 26 or later (VAULT-MESSAGING 0.82.0 §10.4). Then an approval
challenge lives as long as the approval (at most 1 hour here), so a
vault held for its daily owner check (§3.6.3) shows it after the owner
check, if that comes within the hour; `sv remind <approval_id>` sends
only to an admin holding no live challenge, and otherwise says there is
nothing to remind. The service vault cannot see a member vault shorten a
challenge, so it sends at most 2 long ones per connection at a time (and
none while 4 are held). A withdraw that reaches a held vault before its
challenge is ignored there, and a challenge the member vault loses for
another reason (a vault restore, a deposit refused for good) is not seen
by the service: the admin stays unremindable until the challenge's
expiry, at most 1 hour here. If the admin reports not seeing the
request, `sv remind -force <connection_id> <approval_id>` withdraws
their live challenge and sends a new one (once per 10 minutes); each
forced re-send spends one of that admin's 5 approval asks per 24 hours.
A force is refused (`ask_budget`) for an admin already sent 5 approval
challenges that still count (each until its expiry plus 24 hours), since
a sixth would come back as a delayed denial. The count starts empty when this
version is first deployed: for a day or so after, challenges sent
before it are not counted. If the withdraw was lost
the member may see two requests for the same approval: approve the
newest (the older one's answer is ignored). Without the flag (older
member vaults) the challenge lives 10 minutes and a held vault misses
it: `sv approval <approval_id>` prints `remind needed: <connection_id>
(svctl remind <approval_id>)` and the service vault sends the
`approval.challenge_expired` webhook. Release the vault, then `sv remind
<approval_id>` sends a new challenge (at most once per 10 minutes).

## 5. Optional

- **Denied sign-in:** run step 3 again and deny on the phone. Do this
  last: a deny starts a 1-hour cooldown on sign-in challenges from this
  connection (member vault release 24 and later; VAULT-MESSAGING 0.65.0
  §10.4.1: at most 2 pending and 10 per 24 hours, 1 hour after a
  decline), so `sv signin -unsigned` skips it (`declined`) for that
  hour.
- **Removal:** the member removes the connection in the app; `sv admins`
  no longer lists it.

## 6. Clean up

- Deploy again without `adminBootstrapEmail` (and without `testSignIns`:
  context is not remembered, so that turns the unsigned sign-in route off).
- Keep the connection only if further tests need it; otherwise the member
  removes it.
- Record the outcome (dates, app version, vault release, pass/fail per
  step) without addresses, codes or links.

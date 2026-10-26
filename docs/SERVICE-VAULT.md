# Service Vault — Architecture

**Status:** outline (Phase 0). Sections fill in as the phases of
MEMBER-SERVICE-PLAN §10 land.

## 1. Role

Three parties: the **member** (VettID app and the member's vault in a
Nitro Enclave), the **service vault** (this daemon), and the
**application** (for example member.vettid.org). The application calls
the service vault through the SDK over a private HTTPS endpoint; the
service vault calls the application back with signed webhooks. The
service vault reaches members only through their vaults over the relay.

## 2. Trust model

- Member secrets live only in the member's vault. Anything signed with
  the member's credential key — sign-in, contract acceptance,
  completions, the voting key — is signed there; the phone approves.
- The service vault holds the service's own keys (envelope-encrypted
  under KMS, readable by the operator at runtime, as any service's own
  keys are), connection records, contracts and its audit log. It runs in
  a plain container for that reason.
- A service cannot push to a phone. Requests go to the member's vault,
  which turns them into feed events on the member's own terms.

## 3. Components

| Package | Responsibility |
|---|---|
| `internal/peer` | Relay mailbox, suite-2 handshake, connection tokens, `connection.removed` |
| `internal/connect` | Invites, connection lifecycle, email index |
| `internal/signin` | Uniform-response lookup, `connection.authenticate` challenges, match codes |
| `internal/approval` | Admin approvals, configurable m-of-n |
| `internal/contract` | Offers, acceptance, completions (Phase 3) |
| `internal/ballot` | Certification, ballot box, publication (Phase 5) |
| `internal/keystore` | KMS envelope; Ed25519, suite-2 KEM, RSA for blind signing |
| `internal/store` | DynamoDB: connections, pending challenges, audit |
| `internal/webhook` | HMAC over `timestamp.body`, retries |
| `internal/api` | Private HTTPS API, API keys |

## 4. Deployment

One ARM64 Fargate task in public subnets with egress-only security
groups, no NAT Gateway, the DynamoDB gateway endpoint only, Spot,
Container Insights off; the API is reachable only from the application.

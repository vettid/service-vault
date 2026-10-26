# VettID Service Vault

The component an application runs to connect with VettID members. It is
a VMS v2 peer on the VettID relay: members connect to it from a link or QR
code, sign in by approving on their phone, and sign what they agree to in
their own vault. The application talks to it through a private HTTPS API
and signed webhooks, and holds no VettID keys and no member secrets.

It is designed to be cheap and ordinary to run: one container, no enclave,
`cdk deploy`.

## Status

**Phase 0: skeleton.** Nothing runs yet beyond `service-vault version`.
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
still authenticated with an API key on every `/v1` route. The stack
exports `ServiceVault-<envName>-{VpcId, PublicSubnetIds, SecurityGroupId,
NamespaceId, NamespaceArn, NamespaceName, ApiUrl, WebhookSecretArn}` for
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
| `SV_SERVICE_NAME` | env | Display name |
| `SV_API_KEY_HASHES` | Secrets Manager | Comma-separated hex SHA-256 of the accepted API keys |
| `SV_WEBHOOK_SECRET` | Secrets Manager | Webhook signing secret (≥ 32 bytes) |

Secret values are never in the repository. The stack generates both: the
webhook secret is usable as is (the application reads it from the
exported ARN), and the API key hashes start as a random 64-hex placeholder
that matches no known key, so no API key works until the operator stores
the real hashes with `aws secretsmanager put-secret-value` and restarts
the task. The container runs `/service-vault serve` and its health check
is `/service-vault healthcheck`, which probes `GET /health` (the image has
no shell).

**Cost** (us-east-1, MEMBER-SERVICE-PLAN §9): the Spot task is about
$3/month (~$8 on-demand); DynamoDB on-demand, the KMS key ($1), two
secrets ($0.80), logs and transfer are a few dollars more at the member
service's scale. No NAT gateway, interface endpoint or load balancer is
billed.

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

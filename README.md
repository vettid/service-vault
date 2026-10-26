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

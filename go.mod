module github.com/vettid/service-vault

go 1.26.0

toolchain go1.26.10

require (
	filippo.io/edwards25519 v1.1.0
	github.com/aws/aws-sdk-go-v2 v1.48.0
	github.com/aws/aws-sdk-go-v2/config v1.33.12
	github.com/aws/aws-sdk-go-v2/credentials v1.20.12
	github.com/aws/aws-sdk-go-v2/service/dynamodb v1.72.2
	github.com/aws/aws-sdk-go-v2/service/kms v1.62.1
	github.com/aws/aws-sdk-go-v2/service/lambda v1.114.4
	github.com/aws/aws-sdk-go-v2/service/ssm v1.81.1
	github.com/digitorus/timestamp v0.0.0-20231217203849-220c5c2851b7
	github.com/sigstore/timestamp-authority/v2 v2.1.3
	github.com/vettid/vettid-relay v0.0.0-20261027144202-528df9b0bf76
	github.com/vettid/vettid-vault v0.0.0-20261112163356-425a5aeaef1b
	rsc.io/qr v0.2.0
)

require (
	github.com/aws/aws-sdk-go-v2/aws/protocol/eventstream v1.7.27 // indirect
	github.com/aws/aws-sdk-go-v2/feature/ec2/imds v1.20.5 // indirect
	github.com/aws/aws-sdk-go-v2/internal/configsources v1.5.12 // indirect
	github.com/aws/aws-sdk-go-v2/internal/endpoints/v2 v2.8.12 // indirect
	github.com/aws/aws-sdk-go-v2/internal/v4a v1.5.8 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/accept-encoding v1.13.23 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/endpoint-discovery v1.13.8 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/presigned-url v1.14.8 // indirect
	github.com/aws/aws-sdk-go-v2/service/signin v1.12.0 // indirect
	github.com/aws/aws-sdk-go-v2/service/sso v1.39.0 // indirect
	github.com/aws/aws-sdk-go-v2/service/ssooidc v1.44.0 // indirect
	github.com/aws/aws-sdk-go-v2/service/sts v1.51.6 // indirect
	github.com/aws/smithy-go v1.28.9 // indirect
	github.com/coder/websocket v1.8.15 // indirect
	github.com/digitorus/pkcs7 v0.0.0-20230818184609-3a137a874352 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	golang.org/x/crypto v0.58.0 // indirect
	golang.org/x/sys v0.49.0 // indirect
	golang.org/x/text v0.43.0 // indirect
)

// The CDK app's node_modules carries Go templates that are not code.
ignore ./cdk/node_modules

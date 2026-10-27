// The CDK app is TypeScript. This file keeps cdk/ (and its node_modules,
// whose aws-cdk package ships Go templates) out of the repository's Go
// module, so `go test ./...` at the root never walks it.
module github.com/vettid/service-vault/cdk

go 1.26

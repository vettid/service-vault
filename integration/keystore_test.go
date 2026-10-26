//go:build integration

// Integration tests against LocalStack (KMS, DynamoDB):
//
//	make integration      # starts LocalStack with compose, runs, tears down
//
// or, with LocalStack already on :4566,
//
//	SV_IT_LOCALSTACK=http://127.0.0.1:4566 go test -count=1 -tags integration ./integration/
package integration

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/kms"

	"github.com/vettid/service-vault/internal/keystore"
	"github.com/vettid/service-vault/internal/peer"
	"github.com/vettid/service-vault/internal/store"
)

func awsConfig(t *testing.T) (aws.Config, string) {
	t.Helper()
	ep := os.Getenv("SV_IT_LOCALSTACK")
	if ep == "" {
		t.Skip("SV_IT_LOCALSTACK not set (make integration)")
	}
	cfg, err := config.LoadDefaultConfig(context.Background(),
		config.WithRegion("us-east-1"),
		config.WithCredentialsProvider(credentials.NewStaticCredentialsProvider("test", "test", "")))
	if err != nil {
		t.Fatal(err)
	}
	return cfg, ep
}

func TestKeystoreOnKMSAndDynamoDB(t *testing.T) {
	cfg, ep := awsConfig(t)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	kc := kms.NewFromConfig(cfg, func(o *kms.Options) { o.BaseEndpoint = aws.String(ep) })
	key, err := kc.CreateKey(ctx, &kms.CreateKeyInput{})
	if err != nil {
		t.Fatalf("CreateKey: %v", err)
	}
	keyID := *key.KeyMetadata.Arn

	tbl := &store.Table{
		Client: dynamodb.NewFromConfig(cfg, func(o *dynamodb.Options) { o.BaseEndpoint = aws.String(ep) }),
		Name:   fmt.Sprintf("sv-it-%d", time.Now().UnixNano()),
	}
	if err := tbl.CreateTable(ctx); err != nil {
		t.Fatalf("CreateTable: %v", err)
	}
	defer tbl.Client.DeleteTable(context.Background(), &dynamodb.DeleteTableInput{TableName: aws.String(tbl.Name)})

	k := &keystore.AWSKMS{Client: kc}
	first, err := keystore.LoadOrCreate(ctx, k, keyID, tbl.Blobs(), keystore.SecretsName, keystore.NewSecrets)
	if err != nil {
		t.Fatalf("first start: %v", err)
	}
	again, err := keystore.LoadOrCreate(ctx, k, keyID, tbl.Blobs(), keystore.SecretsName, func() (*keystore.Secrets, error) {
		t.Fatal("secrets created again on restart")
		return nil, nil
	})
	if err != nil {
		t.Fatalf("restart: %v", err)
	}
	a, _ := peer.KeysFromSeeds(first.Peer)
	b, _ := peer.KeysFromSeeds(again.Peer)
	if a.Mailbox() != b.Mailbox() || !bytes.Equal(first.EmailPepper, again.EmailPepper) {
		t.Fatal("identity changed across restart")
	}

	// A second create of the same name is refused.
	if err := tbl.Blobs().Create(ctx, keystore.SecretsName, []byte("x")); err != keystore.ErrExists {
		t.Fatalf("second create: %v", err)
	}
}

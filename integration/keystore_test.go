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
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"slices"
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

	// The record is sealed with its encryption context, which KMS holds it
	// to: dropped, it doesn't open (key protection, GC #7406 §7).
	raw, err := tbl.Blobs().Get(ctx, keystore.SecretsName)
	if err != nil {
		t.Fatal(err)
	}
	var sealed keystore.Sealed
	if err := json.Unmarshal(raw, &sealed); err != nil || !sealed.Context {
		t.Fatalf("sealed without its context: %v", err)
	}
	dropped := sealed
	dropped.Context = false
	if _, err := keystore.Open(ctx, k, keystore.SecretsName, &dropped); err == nil {
		t.Fatal("opened without its encryption context")
	}

	// List names it; Replace puts only over the exact old bytes.
	if names, err := tbl.Blobs().List(ctx); err != nil || !slices.Contains(names, keystore.SecretsName) {
		t.Fatalf("List: %v %v", names, err)
	}
	if err := tbl.Blobs().Replace(ctx, keystore.SecretsName, []byte("not it"), []byte("x")); !errors.Is(err, keystore.ErrChanged) {
		t.Fatalf("Replace over other bytes: %v", err)
	}
	if err := tbl.Blobs().Replace(ctx, "none-such", raw, []byte("x")); !errors.Is(err, keystore.ErrNotFound) {
		t.Fatalf("Replace of a missing record: %v", err)
	}
	if err := tbl.Blobs().Replace(ctx, keystore.SecretsName, raw, raw); err != nil {
		t.Fatalf("Replace over its own bytes: %v", err)
	}
	// A legacy item (its data key wrapped with no context, as before P1.1)
	// is re-sealed through real KMS, and then opens with its context.
	dk, wrapped, err := k.GenerateDataKey(ctx, keyID, nil)
	if err != nil {
		t.Fatal(err)
	}
	blk, _ := aes.NewCipher(dk)
	g, _ := cipher.NewGCM(blk)
	nonce := make([]byte, g.NonceSize())
	_, _ = rand.Read(nonce)
	legacy, _ := json.Marshal(&keystore.Sealed{Version: 1, KeyID: keyID, WrappedKey: wrapped, Nonce: nonce,
		Ciphertext: g.Seal(nil, nonce, []byte("legacy"), []byte("vettid/service-vault/keystore/v1\x00legacy-item"))})
	if err := tbl.Blobs().Create(ctx, "legacy-item", legacy); err != nil {
		t.Fatal(err)
	}
	rep, err := keystore.Reseal(ctx, k, keyID, tbl.Blobs())
	if err != nil || len(rep.Resealed) != 1 || rep.Resealed[0] != "legacy-item" {
		t.Fatalf("Reseal: %+v %v", rep, err)
	}
	moved, _ := tbl.Blobs().Get(ctx, "legacy-item")
	var ms keystore.Sealed
	_ = json.Unmarshal(moved, &ms)
	if pt, err := keystore.Open(ctx, k, "legacy-item", &ms); err != nil || !ms.Context || string(pt) != "legacy" {
		t.Fatalf("the re-sealed legacy item: %q %v", pt, err)
	}

	// A second create of the same name is refused.
	if err := tbl.Blobs().Create(ctx, keystore.SecretsName, []byte("x")); err != keystore.ErrExists {
		t.Fatalf("second create: %v", err)
	}

	// Delete removes a record; a missing one is not an error.
	for range 2 {
		if err := tbl.Blobs().Delete(ctx, keystore.SecretsName); err != nil {
			t.Fatalf("Delete: %v", err)
		}
	}
	if _, err := tbl.Blobs().Get(ctx, keystore.SecretsName); err != keystore.ErrNotFound {
		t.Fatalf("after Delete: %v", err)
	}
}

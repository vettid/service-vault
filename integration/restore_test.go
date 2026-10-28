//go:build integration

package integration

import (
	"context"
	"fmt"
	"maps"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"

	"github.com/vettid/service-vault/internal/keystore"
	"github.com/vettid/service-vault/internal/peer"
)

// The restore path: after CopyFrom the stack's table holds exactly the
// restored table's items, newer items gone and changed ones put back.
func TestCopyFromOnDynamoDB(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	src, dst := newTable(t, ctx), newTable(t, ctx)

	if _, _, err := src.CopyFrom(ctx, src.Name); err == nil {
		t.Fatal("copied a table to itself")
	}
	if _, _, err := dst.CopyFrom(ctx, src.Name); err == nil {
		t.Fatal("copied from a table without secrets")
	}
	if _, has, err := src.AnyRecord(ctx); err != nil || has {
		t.Fatalf("AnyRecord on an empty table: %v %v", has, err)
	}
	// An expired record doesn't count.
	if err := dst.Peer().Apply(ctx, []peer.Change{{Kind: "signin", ID: "gone", Data: []byte("x"), Expires: time.Now().Add(-time.Hour)}}); err != nil {
		t.Fatal(err)
	}
	if _, has, err := dst.AnyRecord(ctx); err != nil || has {
		t.Fatalf("AnyRecord with only an expired record: %v %v", has, err)
	}

	// More records than one batch, a blob and a non-record item.
	var old []peer.Change
	for i := range 60 {
		old = append(old, peer.Change{Kind: "conn", ID: fmt.Sprintf("c%02d", i), Data: []byte("old")})
	}
	if err := src.Peer().Apply(ctx, old); err != nil {
		t.Fatal(err)
	}
	if err := src.Blobs().Create(ctx, keystore.SecretsName, []byte("secrets")); err != nil {
		t.Fatal(err)
	}
	put(t, ctx, src.Client, src.Name, "ctr#x", "-")
	if d, has, err := src.AnyRecord(ctx); err != nil || !has || string(d) != "old" {
		t.Fatalf("AnyRecord: %q %v %v", d, has, err)
	}

	// The stack's table moved on: changed records, a new one, a new blob.
	newer := []peer.Change{{Kind: "conn", ID: "c00", Data: []byte("new")}, {Kind: "conn", ID: "c99", Data: []byte("new")}}
	if err := dst.Peer().Apply(ctx, newer); err != nil {
		t.Fatal(err)
	}
	if err := dst.Blobs().Create(ctx, keystore.SecretsName, []byte("other")); err != nil {
		t.Fatal(err)
	}
	put(t, ctx, dst.Client, dst.Name, "ctr#y", "-")

	written, deleted, err := dst.CopyFrom(ctx, src.Name)
	if err != nil {
		t.Fatal(err)
	}
	if written != 62 || deleted != 3 {
		t.Fatalf("written %d deleted %d, want 62 and 3", written, deleted)
	}
	want, got := items(t, ctx, src.Client, src.Name), items(t, ctx, dst.Client, dst.Name)
	if !maps.Equal(want, got) {
		t.Fatalf("tables differ after the copy:\n%v\n%v", want, got)
	}
}

func put(t *testing.T, ctx context.Context, c *dynamodb.Client, table, pk, sk string) {
	t.Helper()
	_, err := c.PutItem(ctx, &dynamodb.PutItemInput{TableName: aws.String(table), Item: map[string]types.AttributeValue{
		"pk": &types.AttributeValueMemberS{Value: pk}, "sk": &types.AttributeValueMemberS{Value: sk},
	}})
	if err != nil {
		t.Fatal(err)
	}
}

// items is every item of a table as pk|sk → its data and version.
func items(t *testing.T, ctx context.Context, c *dynamodb.Client, table string) map[string]string {
	t.Helper()
	m := map[string]string{}
	p := dynamodb.NewScanPaginator(c, &dynamodb.ScanInput{TableName: aws.String(table), ConsistentRead: aws.Bool(true)})
	for p.HasMorePages() {
		out, err := p.NextPage(ctx)
		if err != nil {
			t.Fatal(err)
		}
		for _, it := range out.Items {
			var data, version string
			if b, ok := it["data"].(*types.AttributeValueMemberB); ok {
				data = string(b.Value)
			}
			if n, ok := it["version"].(*types.AttributeValueMemberN); ok {
				version = n.Value
			}
			m[it["pk"].(*types.AttributeValueMemberS).Value+"|"+it["sk"].(*types.AttributeValueMemberS).Value] = data + "|" + version
		}
	}
	return m
}

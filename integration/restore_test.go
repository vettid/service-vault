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

	"github.com/vettid/service-vault/internal/peer"
	"github.com/vettid/service-vault/internal/sealstore"
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
		t.Fatal("copied from a table without a record key")
	}
	if has, err := src.HasRecords(ctx); err != nil || has {
		t.Fatalf("HasRecords on an empty table: %v %v", has, err)
	}

	// More records than one batch, a blob and a non-record item.
	var old []peer.Change
	for i := range 60 {
		old = append(old, peer.Change{Kind: "conn", ID: fmt.Sprintf("c%02d", i), Data: []byte("old")})
	}
	if err := src.Peer().Apply(ctx, old); err != nil {
		t.Fatal(err)
	}
	if err := src.Blobs().Create(ctx, sealstore.KeyName, []byte("key")); err != nil {
		t.Fatal(err)
	}
	put(t, ctx, src.Client, src.Name, "ctr#x", "-")
	if has, err := src.HasRecords(ctx); err != nil || !has {
		t.Fatalf("HasRecords: %v %v", has, err)
	}

	// The stack's table moved on: changed records, a new one, a new blob.
	newer := []peer.Change{{Kind: "conn", ID: "c00", Data: []byte("new")}, {Kind: "conn", ID: "c99", Data: []byte("new")}}
	if err := dst.Peer().Apply(ctx, newer); err != nil {
		t.Fatal(err)
	}
	if err := dst.Blobs().Create(ctx, sealstore.KeyName, []byte("other")); err != nil {
		t.Fatal(err)
	}
	put(t, ctx, dst.Client, dst.Name, "ctr#y", "-")

	written, deleted, err := dst.CopyFrom(ctx, src.Name)
	if err != nil {
		t.Fatal(err)
	}
	if written != 62 || deleted != 2 {
		t.Fatalf("written %d deleted %d, want 62 and 2", written, deleted)
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

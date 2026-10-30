//go:build integration

package integration

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"

	"github.com/vettid/service-vault/internal/keystore"
	"github.com/vettid/service-vault/internal/peer"
	"github.com/vettid/service-vault/internal/store"
)

// The restore path: after CopyFrom the stack's table holds exactly the
// restored table's items, newer items gone and changed ones put back.
func TestCopyFromOnDynamoDB(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	src, dst := newTable(t, ctx), newTable(t, ctx)

	if _, _, err := src.CopyFrom(ctx, src.Name, nil); err == nil {
		t.Fatal("copied a table to itself")
	}
	if _, _, err := dst.CopyFrom(ctx, src.Name, nil); err == nil {
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
	if has, err := src.AnyBlob(ctx, "record-key"); err != nil || has {
		t.Fatalf("AnyBlob without a record key: %v %v", has, err)
	}
	if err := src.Blobs().Create(ctx, "record-key.v2", []byte("k")); err != nil {
		t.Fatal(err)
	}
	if has, err := src.AnyBlob(ctx, "record-key"); err != nil || !has {
		t.Fatalf("AnyBlob with a later record key: %v %v", has, err)
	}
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

	// A check before the deletes that fails stops the copy there.
	stop := errors.New("a task started")
	if w, d, err := dst.CopyFrom(ctx, src.Name, func(context.Context) error { return stop }); !errors.Is(err, stop) || w != 63 || d != 0 {
		t.Fatalf("stopped copy: written %d deleted %d, %v", w, d, err)
	}
	written, deleted, err := dst.CopyFrom(ctx, src.Name, nil)
	if err != nil {
		t.Fatal(err)
	}
	if written != 63 || deleted != 3 {
		t.Fatalf("written %d deleted %d, want 63 and 3", written, deleted)
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

// The restore's checks: a plain table is not a restore (a swapped -from
// and -to); a target with other keys or a recent heartbeat is refused;
// the heartbeat is neither copied nor deleted.
func TestRestoreChecksOnDynamoDB(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	src, dst := newTable(t, ctx), newTable(t, ctx)
	now := time.Now()

	if _, err := dst.CheckRestore(ctx, src.Name, false, false, now); err == nil || !strings.Contains(err.Error(), "was not restored") {
		t.Fatalf("CheckRestore from a plain table: %v", err)
	}
	if err := dst.CheckTarget(ctx, src.Name, false, now); err == nil {
		t.Fatal("CheckTarget from a table without keys")
	}
	if err := src.Blobs().Create(ctx, keystore.SecretsName, []byte("secrets")); err != nil {
		t.Fatal(err)
	}
	if err := dst.CheckTarget(ctx, src.Name, false, now); err != nil {
		t.Fatalf("CheckTarget into a table without keys: %v", err)
	}
	if err := dst.Blobs().Create(ctx, keystore.SecretsName, []byte("other")); err != nil {
		t.Fatal(err)
	}
	if err := dst.CheckTarget(ctx, src.Name, false, now); err == nil || !strings.Contains(err.Error(), "other keys") {
		t.Fatalf("CheckTarget into a table with other keys: %v", err)
	}
	if err := dst.CheckTarget(ctx, src.Name, true, now); err != nil {
		t.Fatalf("CheckTarget with -other-keys: %v", err)
	}

	if _, ok, err := dst.LastHeartbeat(ctx); err != nil || ok {
		t.Fatalf("LastHeartbeat without one: %v %v", ok, err)
	}
	if err := dst.Heartbeat(ctx, now.Add(-time.Minute)); err != nil {
		t.Fatal(err)
	}
	if at, ok, err := dst.LastHeartbeat(ctx); err != nil || !ok || at.Unix() != now.Add(-time.Minute).Unix() {
		t.Fatalf("LastHeartbeat: %v %v %v", at, ok, err)
	}
	if err := dst.CheckTarget(ctx, src.Name, true, now); err == nil || !strings.Contains(err.Error(), "running") {
		t.Fatalf("CheckTarget with a heartbeat a minute old: %v", err)
	}
	if err := dst.CheckTarget(ctx, src.Name, true, now.Add(store.HeartbeatStale)); err != nil {
		t.Fatalf("CheckTarget with a stale heartbeat: %v", err)
	}
	if err := src.Heartbeat(ctx, now); err != nil {
		t.Fatal(err)
	}
	if _, _, err := dst.CopyFrom(ctx, src.Name, nil); err != nil {
		t.Fatal(err)
	}
	if at, ok, err := dst.LastHeartbeat(ctx); err != nil || !ok || at.Unix() != now.Add(-time.Minute).Unix() {
		t.Fatalf("the copy touched the target's heartbeat: %v %v %v", at, ok, err)
	}
	// The restores done, remembered for RestoreWindow.
	if rs, err := dst.Restores(ctx); err != nil || len(rs) != 0 {
		t.Fatalf("Restores before any: %v %v", rs, err)
	}
	point := now.Add(-48 * time.Hour)
	if err := dst.RecordRestore(ctx, point, now); err != nil {
		t.Fatal(err)
	}
	if err := dst.RecordRestore(ctx, point, now.Add(store.RestoreWindow)); err != nil {
		t.Fatal(err)
	}
	if rs, err := dst.Restores(ctx); err != nil || len(rs) != 1 || !rs[0].At.Equal(now.Add(store.RestoreWindow).UTC()) {
		t.Fatalf("Restores: %v %v", rs, err)
	}
	// The restore marker: set after the copy, read and cleared at the start.
	if ok, err := dst.Restored(ctx); err != nil || ok {
		t.Fatalf("Restored before the marker: %v %v", ok, err)
	}
	if err := dst.MarkRestored(ctx, now); err != nil {
		t.Fatal(err)
	}
	if ok, err := dst.Restored(ctx); err != nil || !ok {
		t.Fatalf("Restored after MarkRestored: %v %v", ok, err)
	}
	if err := dst.ClearRestored(ctx); err != nil {
		t.Fatal(err)
	}
	if ok, err := dst.Restored(ctx); err != nil || ok {
		t.Fatalf("Restored after ClearRestored: %v %v", ok, err)
	}
	// The ballots' rebuild marker, kept while ballots are off.
	if ok, err := dst.BallotsRebuild(ctx); err != nil || ok {
		t.Fatalf("BallotsRebuild before the marker: %v %v", ok, err)
	}
	if err := dst.MarkBallotsRebuild(ctx, now); err != nil {
		t.Fatal(err)
	}
	if ok, err := dst.BallotsRebuild(ctx); err != nil || !ok {
		t.Fatalf("BallotsRebuild after the marker: %v %v", ok, err)
	}
	if err := dst.ClearBallotsRebuild(ctx); err != nil {
		t.Fatal(err)
	}
	if ok, err := dst.BallotsRebuild(ctx); err != nil || ok {
		t.Fatalf("BallotsRebuild after the clear: %v %v", ok, err)
	}
	if err := dst.ClearHeartbeat(ctx); err != nil {
		t.Fatal(err)
	}
	if _, ok, err := dst.LastHeartbeat(ctx); err != nil || ok {
		t.Fatalf("LastHeartbeat after ClearHeartbeat: %v %v", ok, err)
	}
}

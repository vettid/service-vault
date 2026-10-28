package store

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"

	"github.com/vettid/service-vault/internal/keystore"
)

// The heartbeat: pk "run#heartbeat", the time of the running task's last
// write in "at" (Unix seconds). The daemon writes it every
// HeartbeatInterval and deletes it when it stops; the restore refuses a
// table whose heartbeat is younger than HeartbeatStale, as the service is
// then running.
const (
	pkHeartbeat = "run#heartbeat"
	attrAt      = "at"

	HeartbeatInterval = 30 * time.Second
	HeartbeatStale    = 2 * time.Minute
)

// Heartbeat records that a task is running at now. The item expires
// (TTL) an hour later, so a crashed task leaves nothing for long.
func (t *Table) Heartbeat(ctx context.Context, now time.Time) error {
	item := key(pkHeartbeat, skOne)
	item[attrAt] = &types.AttributeValueMemberN{Value: strconv.FormatInt(now.Unix(), 10)}
	item[attrTTL] = &types.AttributeValueMemberN{Value: strconv.FormatInt(now.Add(time.Hour).Unix(), 10)}
	_, err := t.Client.PutItem(ctx, &dynamodb.PutItemInput{TableName: aws.String(t.Name), Item: item})
	return err
}

// ClearHeartbeat deletes the heartbeat when the daemon stops.
func (t *Table) ClearHeartbeat(ctx context.Context) error {
	_, err := t.Client.DeleteItem(ctx, &dynamodb.DeleteItemInput{TableName: aws.String(t.Name), Key: key(pkHeartbeat, skOne)})
	return err
}

// LastHeartbeat returns the time of the last heartbeat, if there is one.
func (t *Table) LastHeartbeat(ctx context.Context) (time.Time, bool, error) {
	out, err := t.Client.GetItem(ctx, &dynamodb.GetItemInput{
		TableName: aws.String(t.Name), Key: key(pkHeartbeat, skOne), ConsistentRead: aws.Bool(true),
	})
	if err != nil || out.Item == nil {
		return time.Time{}, false, err
	}
	v, ok := out.Item[attrAt].(*types.AttributeValueMemberN)
	if !ok {
		return time.Time{}, false, errors.New("store: heartbeat without a time")
	}
	n, err := strconv.ParseInt(v.Value, 10, 64)
	if err != nil {
		return time.Time{}, false, err
	}
	return time.Unix(n, 0), true, nil
}

// CheckRestore refuses a restore into t from the table src unless src is
// a finished DynamoDB restore of t (from a backup or to a point in time)
// with the same keys, and the service on t is stopped. otherKeys allows
// t to hold keys of its own (a table the daemon started on after the
// original was lost): they are replaced.
func (t *Table) CheckRestore(ctx context.Context, src string, otherKeys bool, now time.Time) error {
	if src == t.Name {
		return errors.New("store: copy from a table to itself")
	}
	from, err := t.Client.DescribeTable(ctx, &dynamodb.DescribeTableInput{TableName: aws.String(src)})
	if err != nil {
		return err
	}
	to, err := t.Client.DescribeTable(ctx, &dynamodb.DescribeTableInput{TableName: aws.String(t.Name)})
	if err != nil {
		return err
	}
	if err := checkRestored(from.Table, to.Table); err != nil {
		return err
	}
	return t.CheckTarget(ctx, src, otherKeys, now)
}

// CheckTarget is CheckRestore's check of the tables' contents: src holds
// a service vault's keys, t the same ones (or none, or other ones with
// otherKeys), and t has no recent heartbeat.
func (t *Table) CheckTarget(ctx context.Context, src string, otherKeys bool, now time.Time) error {
	srcKeys, err := (&Table{Client: t.Client, Name: src}).Blobs().Get(ctx, keystore.SecretsName)
	if err != nil {
		return fmt.Errorf("store: %s is not a service vault table: %w", src, err)
	}
	dstKeys, err := t.Blobs().Get(ctx, keystore.SecretsName)
	switch {
	case errors.Is(err, keystore.ErrNotFound):
	case err != nil:
		return err
	case !bytes.Equal(srcKeys, dstKeys) && !otherKeys:
		return fmt.Errorf("store: %s holds other keys than %s: not the same deployment (-other-keys replaces them)", t.Name, src)
	}
	at, ok, err := t.LastHeartbeat(ctx)
	if err != nil {
		return err
	}
	if ok && now.Sub(at) < HeartbeatStale {
		return fmt.Errorf("store: the service on %s is running (heartbeat %s ago): stop it first", t.Name, now.Sub(at).Round(time.Second))
	}
	return nil
}

// checkRestored refuses unless from is a finished restore whose source is
// to: a swapped -from and -to, or a table of another deployment, fail.
func checkRestored(from, to *types.TableDescription) error {
	if from == nil || to == nil {
		return errors.New("store: table without a description")
	}
	name := aws.ToString(from.TableName)
	rs := from.RestoreSummary
	switch {
	case from.TableStatus != types.TableStatusActive:
		return fmt.Errorf("store: %s is %s, not ACTIVE yet", name, from.TableStatus)
	case rs == nil:
		return fmt.Errorf("store: %s was not restored from a backup or a point in time (swapped -from and -to?)", name)
	case aws.ToBool(rs.RestoreInProgress):
		return fmt.Errorf("store: the restore into %s is still in progress", name)
	case rs.SourceTableArn != nil && aws.ToString(rs.SourceTableArn) != aws.ToString(to.TableArn):
		return fmt.Errorf("store: %s was restored from %s, not %s", name, aws.ToString(rs.SourceTableArn), aws.ToString(to.TableName))
	}
	return nil
}

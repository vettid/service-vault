package store

import (
	"bytes"
	"context"
	"encoding/json"
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
//
// It returns the point in time src holds (the backup's, or the one
// restored to). A restore within the window of an earlier one is refused
// unless newerPoint (see checkRestoreWindow).
func (t *Table) CheckRestore(ctx context.Context, src string, otherKeys, newerPoint bool, now time.Time) (time.Time, error) {
	if src == t.Name {
		return time.Time{}, errors.New("store: copy from a table to itself")
	}
	from, err := t.Client.DescribeTable(ctx, &dynamodb.DescribeTableInput{TableName: aws.String(src)})
	if err != nil {
		return time.Time{}, err
	}
	to, err := t.Client.DescribeTable(ctx, &dynamodb.DescribeTableInput{TableName: aws.String(t.Name)})
	if err != nil {
		return time.Time{}, err
	}
	if err := checkRestored(from.Table, to.Table); err != nil {
		return time.Time{}, err
	}
	point := aws.ToTime(from.Table.RestoreSummary.RestoreDateTime)
	if point.IsZero() {
		return time.Time{}, fmt.Errorf("store: the restore into %s has no point in time", src)
	}
	past, err := t.Restores(ctx)
	if err != nil {
		return time.Time{}, err
	}
	if err := checkRestoreWindow(past, point, now); err != nil && !newerPoint {
		return time.Time{}, err
	}
	return point, t.CheckTarget(ctx, src, otherKeys, now)
}

// RestoreWindow is how long a restore is remembered: members' vaults
// accept the older epoch a restored service names for 35 days after it
// was superseded (VAULT-MESSAGING §6.6, 0.72.0), and keep the epochs it
// replaced as long.
const RestoreWindow = 35 * 24 * time.Hour

// Restore is a restore done into the table: the point in time it put
// back and when.
type Restore struct {
	Point time.Time `json:"point"`
	At    time.Time `json:"at"`
}

// checkRestoreWindow refuses a restore to a point between an earlier
// restore's point and the time that restore was done. The first restore's
// reconnects made the members' vaults set aside the epochs the service
// had after its point; a backup from that span names one of them, and
// members' vaults take it for a second copy of the service (§6.6 "Fork
// detection"): every connection is suspended and must connect again.
// The same point or an older one, or one after the earlier restore, is
// fine.
func checkRestoreWindow(past []Restore, point, now time.Time) error {
	for _, r := range past {
		if now.Sub(r.At) < RestoreWindow && point.After(r.Point) && point.Before(r.At) {
			return fmt.Errorf("store: %s is newer than the backup restored on %s (%s) but older than that restore: members' vaults would take it for a second copy of the service and suspend every connection; restore from %s or older (-newer-point overrides)",
				point.UTC().Format(time.RFC3339), r.At.UTC().Format(time.RFC3339), r.Point.UTC().Format(time.RFC3339), r.Point.UTC().Format(time.RFC3339))
		}
	}
	return nil
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

// The restores done into the table: pk "run#restores", a JSON list in
// "data" of those of the last RestoreWindow. Like every run item, the
// copy neither writes nor deletes it.
const pkRestores = "run#restores"

// Restores returns the restores done into t in the last RestoreWindow.
func (t *Table) Restores(ctx context.Context) ([]Restore, error) {
	out, err := t.Client.GetItem(ctx, &dynamodb.GetItemInput{
		TableName: aws.String(t.Name), Key: key(pkRestores, skOne), ConsistentRead: aws.Bool(true),
	})
	if err != nil || out.Item == nil {
		return nil, err
	}
	d, ok := out.Item[attrData].(*types.AttributeValueMemberB)
	if !ok {
		return nil, errors.New("store: restores without data")
	}
	var rs []Restore
	return rs, json.Unmarshal(d.Value, &rs)
}

// RecordRestore adds a restore to point, done at now, and drops those
// older than RestoreWindow.
func (t *Table) RecordRestore(ctx context.Context, point, now time.Time) error {
	past, err := t.Restores(ctx)
	if err != nil {
		return err
	}
	rs := []Restore{}
	for _, r := range past {
		if now.Sub(r.At) < RestoreWindow {
			rs = append(rs, r)
		}
	}
	rs = append(rs, Restore{Point: point.UTC(), At: now.UTC()})
	data, err := json.Marshal(rs)
	if err != nil {
		return err
	}
	item := key(pkRestores, skOne)
	item[attrData] = &types.AttributeValueMemberB{Value: data}
	_, err = t.Client.PutItem(ctx, &dynamodb.PutItemInput{TableName: aws.String(t.Name), Item: item})
	return err
}

// The restore marker: pk "run#restored", written by the restore after the
// copy. The next start reconnects every connection (peer.Config
// AfterRestore) and then deletes it.
const pkRestored = "run#restored"

// MarkRestored records that the table was restored at now.
func (t *Table) MarkRestored(ctx context.Context, now time.Time) error {
	item := key(pkRestored, skOne)
	item[attrAt] = &types.AttributeValueMemberN{Value: strconv.FormatInt(now.Unix(), 10)}
	_, err := t.Client.PutItem(ctx, &dynamodb.PutItemInput{TableName: aws.String(t.Name), Item: item})
	return err
}

// Restored reports whether the restore marker is present.
func (t *Table) Restored(ctx context.Context) (bool, error) {
	out, err := t.Client.GetItem(ctx, &dynamodb.GetItemInput{
		TableName: aws.String(t.Name), Key: key(pkRestored, skOne), ConsistentRead: aws.Bool(true),
	})
	return err == nil && out.Item != nil, err
}

// ClearRestored deletes the restore marker.
func (t *Table) ClearRestored(ctx context.Context) error {
	_, err := t.Client.DeleteItem(ctx, &dynamodb.DeleteItemInput{TableName: aws.String(t.Name), Key: key(pkRestored, skOne)})
	return err
}

// The ballots' rebuild marker: pk "run#ballots_rebuild", written at a
// start after a restore while ballots are off (the copy's key is
// missing), so that the restore marker can go once the reconnects are
// sent and the ballots the restore lost are still put back from the
// copy once ballots are on again. The start that rebuilds deletes it.
const pkBallotsRebuild = "run#ballots_rebuild"

// MarkBallotsRebuild records that the ballots wait for a rebuild.
func (t *Table) MarkBallotsRebuild(ctx context.Context, now time.Time) error {
	item := key(pkBallotsRebuild, skOne)
	item[attrAt] = &types.AttributeValueMemberN{Value: strconv.FormatInt(now.Unix(), 10)}
	_, err := t.Client.PutItem(ctx, &dynamodb.PutItemInput{TableName: aws.String(t.Name), Item: item})
	return err
}

// BallotsRebuild reports whether the ballots' rebuild marker is present.
func (t *Table) BallotsRebuild(ctx context.Context) (bool, error) {
	out, err := t.Client.GetItem(ctx, &dynamodb.GetItemInput{
		TableName: aws.String(t.Name), Key: key(pkBallotsRebuild, skOne), ConsistentRead: aws.Bool(true),
	})
	return err == nil && out.Item != nil, err
}

// ClearBallotsRebuild deletes the ballots' rebuild marker.
func (t *Table) ClearBallotsRebuild(ctx context.Context) error {
	_, err := t.Client.DeleteItem(ctx, &dynamodb.DeleteItemInput{TableName: aws.String(t.Name), Key: key(pkBallotsRebuild, skOne)})
	return err
}

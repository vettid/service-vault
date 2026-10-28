package store

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"

	"github.com/vettid/service-vault/internal/keystore"
)

// maxBatchWrite bounds one BatchWriteItem call (DynamoDB's limit).
const maxBatchWrite = 25

// AnyRecord returns the stored data of one record of t (pk "rec#…") that
// has not expired, if there is one. The start uses it to refuse making
// new keys over existing records, and to read which version of the
// record key they are under.
func (t *Table) AnyRecord(ctx context.Context) ([]byte, bool, error) {
	return t.anyItem(ctx, "rec#", true)
}

// AnyBlob reports whether the keystore holds a record whose name starts
// with prefix (every version of the record key: sealstore.KeyName).
func (t *Table) AnyBlob(ctx context.Context, prefix string) (bool, error) {
	_, ok, err := t.anyItem(ctx, "blob#"+prefix, false)
	return ok, err
}

// anyItem returns the data of one item whose pk starts with pkPrefix
// (with live, only one that has not expired).
func (t *Table) anyItem(ctx context.Context, pkPrefix string, live bool) ([]byte, bool, error) {
	filter := "begins_with(#pk, :p)"
	names := map[string]string{"#pk": attrPK, "#d": attrData}
	vals := map[string]types.AttributeValue{":p": &types.AttributeValueMemberS{Value: pkPrefix}}
	if live {
		filter += " AND (attribute_not_exists(#ttl) OR #ttl > :now)"
		names["#ttl"] = attrTTL
		vals[":now"] = &types.AttributeValueMemberN{Value: strconv.FormatInt(time.Now().Unix(), 10)}
	}
	p := dynamodb.NewScanPaginator(t.Client, &dynamodb.ScanInput{
		TableName:                 aws.String(t.Name),
		ConsistentRead:            aws.Bool(true),
		ProjectionExpression:      aws.String("#d"),
		FilterExpression:          aws.String(filter),
		ExpressionAttributeNames:  names,
		ExpressionAttributeValues: vals,
	})
	for p.HasMorePages() {
		out, err := p.NextPage(ctx)
		if err != nil {
			return nil, false, err
		}
		for _, item := range out.Items {
			if d, ok := item[attrData].(*types.AttributeValueMemberB); ok {
				return d.Value, true, nil
			}
			return nil, true, nil
		}
	}
	return nil, false, nil
}

// CopyFrom makes t hold exactly the items of the table src: every item of
// src is written to t, then every item of t that src lacks is deleted. It
// is the restore path (README "Restoring the table"): DynamoDB restores a
// backup into a new table, and its items are copied back into the
// stack's table. The service must be stopped while it runs (CheckRestore
// checks first). src must be a service vault table (one with its secrets).
// The run items (pk "run#…": the heartbeat) are neither copied nor
// deleted: they describe a task, not the data.
func (t *Table) CopyFrom(ctx context.Context, src string) (written, deleted int, err error) {
	if src == t.Name {
		return 0, 0, errors.New("store: copy from a table to itself")
	}
	from := &Table{Client: t.Client, Name: src}
	if _, err := from.Blobs().Get(ctx, keystore.SecretsName); err != nil {
		return 0, 0, fmt.Errorf("store: %s is not a service vault table: %w", src, err)
	}
	keep := map[string]bool{}
	var batch []types.WriteRequest
	flush := func() error {
		err := t.batchWrite(ctx, batch)
		batch = batch[:0]
		return err
	}
	if err := scanAll(ctx, from, nil, func(item map[string]types.AttributeValue) error {
		k, err := itemKey(item)
		if err != nil || isRun(item) {
			return err
		}
		keep[k] = true
		batch = append(batch, types.WriteRequest{PutRequest: &types.PutRequest{Item: item}})
		written++
		if len(batch) == maxBatchWrite {
			return flush()
		}
		return nil
	}); err != nil {
		return written, 0, err
	}
	if err := flush(); err != nil {
		return written, 0, err
	}
	if err := scanAll(ctx, t, aws.String("#pk, #sk"), func(item map[string]types.AttributeValue) error {
		k, err := itemKey(item)
		if err != nil {
			return err
		}
		if keep[k] || isRun(item) {
			return nil
		}
		batch = append(batch, types.WriteRequest{DeleteRequest: &types.DeleteRequest{Key: map[string]types.AttributeValue{
			attrPK: item[attrPK], attrSK: item[attrSK],
		}}})
		deleted++
		if len(batch) == maxBatchWrite {
			return flush()
		}
		return nil
	}); err != nil {
		return written, deleted, err
	}
	return written, deleted, flush()
}

// scanAll calls f with every item of t, read consistently; projection
// names attributes as "#pk" and "#sk" (nil: whole items).
func scanAll(ctx context.Context, t *Table, projection *string, f func(map[string]types.AttributeValue) error) error {
	in := &dynamodb.ScanInput{TableName: aws.String(t.Name), ConsistentRead: aws.Bool(true)}
	if projection != nil {
		in.ProjectionExpression = projection
		in.ExpressionAttributeNames = map[string]string{"#pk": attrPK, "#sk": attrSK}
	}
	p := dynamodb.NewScanPaginator(t.Client, in)
	for p.HasMorePages() {
		out, err := p.NextPage(ctx)
		if err != nil {
			return err
		}
		for _, item := range out.Items {
			if err := f(item); err != nil {
				return err
			}
		}
	}
	return nil
}

// isRun reports whether item is a run item (pk "run#…").
func isRun(item map[string]types.AttributeValue) bool {
	pk, ok := item[attrPK].(*types.AttributeValueMemberS)
	return ok && strings.HasPrefix(pk.Value, "run#")
}

// itemKey is an item's pk and sk as one string.
func itemKey(item map[string]types.AttributeValue) (string, error) {
	pk, ok1 := item[attrPK].(*types.AttributeValueMemberS)
	sk, ok2 := item[attrSK].(*types.AttributeValueMemberS)
	if !ok1 || !ok2 {
		return "", errors.New("store: item without a string pk and sk")
	}
	return pk.Value + "\x00" + sk.Value, nil
}

// batchWrite writes reqs (at most maxBatchWrite), retrying what DynamoDB
// leaves unprocessed with a growing pause.
func (t *Table) batchWrite(ctx context.Context, reqs []types.WriteRequest) error {
	pause := 50 * time.Millisecond
	for attempt := 0; len(reqs) > 0; attempt++ {
		if attempt == 10 {
			return fmt.Errorf("store: %d writes still unprocessed", len(reqs))
		}
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(pause):
			}
			pause *= 2
		}
		out, err := t.Client.BatchWriteItem(ctx, &dynamodb.BatchWriteItemInput{
			RequestItems: map[string][]types.WriteRequest{t.Name: reqs},
		})
		if err != nil {
			return err
		}
		reqs = out.UnprocessedItems[t.Name]
	}
	return nil
}

package store

import (
	"context"
	"encoding/hex"
	"errors"
	"strconv"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"

	"github.com/vettid/service-vault/internal/ballot"
)

// Ballots is the write-once copy of accepted ballots (ballot.Copy;
// BALLOT-PROTOCOL §6 "Durability"): a table of its own, pk the
// proposal_id, sk the tag in hex, with the ballot record in "data". The
// task's role may only put, get, query and scan it, so it can't update or
// delete an item; that a put never replaces one is this code's condition
// (attribute_not_exists), which IAM can't require, and point-in-time
// recovery keeps what was there. A restore of the main table doesn't
// touch it.
type Ballots struct {
	Client *dynamodb.Client
	Name   string
	// Main is the main table, where a guarded write's record is checked.
	Main *Table
}

var _ ballot.Copy = (*Ballots)(nil)

// PutOnce implements ballot.Copy. With a guard, one transaction checks
// the guarded record's version in the main table and puts the item.
func (b *Ballots) PutOnce(ctx context.Context, proposalID string, tag, data []byte, g *ballot.Guard) ([]byte, error) {
	item := key(proposalID, hex.EncodeToString(tag))
	item[attrData] = &types.AttributeValueMemberB{Value: data}
	put := &types.Put{
		TableName: aws.String(b.Name), Item: item,
		ConditionExpression: aws.String("attribute_not_exists(pk)"),
	}
	var err error
	if g == nil {
		_, err = b.Client.PutItem(ctx, &dynamodb.PutItemInput{
			TableName: put.TableName, Item: put.Item, ConditionExpression: put.ConditionExpression,
		})
	} else {
		if b.Main == nil {
			return nil, errors.New("store: a guarded ballot write needs the main table")
		}
		_, err = b.Client.TransactWriteItems(ctx, &dynamodb.TransactWriteItemsInput{TransactItems: []types.TransactWriteItem{
			{ConditionCheck: &types.ConditionCheck{
				TableName: aws.String(b.Main.Name), Key: key(recPK(g.Kind), g.ID),
				ConditionExpression:       aws.String("#v = :v"),
				ExpressionAttributeNames:  map[string]string{"#v": attrVersion},
				ExpressionAttributeValues: map[string]types.AttributeValue{":v": &types.AttributeValueMemberN{Value: strconv.FormatUint(g.Version, 10)}},
			}},
			{Put: put},
		}})
	}
	if err == nil {
		return data, nil
	}
	exists := false
	var ccf *types.ConditionalCheckFailedException
	var tc *types.TransactionCanceledException
	switch {
	case errors.As(err, &ccf):
		exists = true
	case g != nil && errors.As(err, &tc):
		// The reasons are in the items' order: the check, then the put.
		// An item already there wins over the guard.
		if len(tc.CancellationReasons) == 2 && aws.ToString(tc.CancellationReasons[1].Code) == "ConditionalCheckFailed" {
			exists = true
		} else if len(tc.CancellationReasons) == 2 {
			// A transaction conflict on the check means the record is being
			// written: the same as a changed version, and the cast reads again.
			switch aws.ToString(tc.CancellationReasons[0].Code) {
			case "ConditionalCheckFailed", "TransactionConflict":
				return nil, ballot.ErrGuard
			}
		}
	}
	if !exists {
		return nil, err
	}
	v, ok, err := b.Get(ctx, proposalID, tag)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, errors.New("store: malformed ballot copy")
	}
	return v, nil
}

// Get implements ballot.Copy.
func (b *Ballots) Get(ctx context.Context, proposalID string, tag []byte) ([]byte, bool, error) {
	out, err := b.Client.GetItem(ctx, &dynamodb.GetItemInput{
		TableName: aws.String(b.Name), Key: key(proposalID, hex.EncodeToString(tag)), ConsistentRead: aws.Bool(true),
	})
	if err != nil {
		return nil, false, err
	}
	if len(out.Item) == 0 {
		return nil, false, nil
	}
	v, ok := out.Item[attrData].(*types.AttributeValueMemberB)
	if !ok {
		return nil, false, errors.New("store: malformed ballot copy")
	}
	return v.Value, true, nil
}

// Any returns one stored ballot of any proposal but skip, if there is
// one (a scan that stops at the first).
func (b *Ballots) Any(ctx context.Context, skip string) (string, ballot.CopyItem, bool, error) {
	p := dynamodb.NewScanPaginator(b.Client, &dynamodb.ScanInput{
		TableName:                 aws.String(b.Name),
		FilterExpression:          aws.String("pk <> :skip"),
		ExpressionAttributeValues: map[string]types.AttributeValue{":skip": &types.AttributeValueMemberS{Value: skip}},
		ConsistentRead:            aws.Bool(true),
	})
	for p.HasMorePages() {
		page, err := p.NextPage(ctx)
		if err != nil {
			return "", ballot.CopyItem{}, false, err
		}
		for _, it := range page.Items {
			pk, ok1 := it[attrPK].(*types.AttributeValueMemberS)
			sk, ok2 := it[attrSK].(*types.AttributeValueMemberS)
			v, ok3 := it[attrData].(*types.AttributeValueMemberB)
			if !ok1 || !ok2 || !ok3 {
				return "", ballot.CopyItem{}, false, errors.New("store: malformed ballot copy")
			}
			tag, err := hex.DecodeString(sk.Value)
			if err != nil {
				return "", ballot.CopyItem{}, false, errors.New("store: malformed ballot copy key")
			}
			return pk.Value, ballot.CopyItem{Tag: tag, Data: v.Value}, true, nil
		}
	}
	return "", ballot.CopyItem{}, false, nil
}

// List implements ballot.Copy.
func (b *Ballots) List(ctx context.Context, proposalID string) ([]ballot.CopyItem, error) {
	var out []ballot.CopyItem
	p := dynamodb.NewQueryPaginator(b.Client, &dynamodb.QueryInput{
		TableName:                 aws.String(b.Name),
		KeyConditionExpression:    aws.String("pk = :pk"),
		ExpressionAttributeValues: map[string]types.AttributeValue{":pk": &types.AttributeValueMemberS{Value: proposalID}},
		ConsistentRead:            aws.Bool(true),
	})
	for p.HasMorePages() {
		page, err := p.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, it := range page.Items {
			v, ok := it[attrData].(*types.AttributeValueMemberB)
			sk, ok2 := it[attrSK].(*types.AttributeValueMemberS)
			if !ok || !ok2 {
				return nil, errors.New("store: malformed ballot copy")
			}
			tag, err := hex.DecodeString(sk.Value)
			if err != nil {
				return nil, errors.New("store: malformed ballot copy key")
			}
			out = append(out, ballot.CopyItem{Tag: tag, Data: v.Value})
		}
	}
	return out, nil
}

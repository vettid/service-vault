package store

import (
	"context"
	"encoding/hex"
	"errors"

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
}

var _ ballot.Copy = (*Ballots)(nil)

// PutOnce implements ballot.Copy.
func (b *Ballots) PutOnce(ctx context.Context, proposalID string, tag, data []byte) ([]byte, error) {
	item := key(proposalID, hex.EncodeToString(tag))
	item[attrData] = &types.AttributeValueMemberB{Value: data}
	_, err := b.Client.PutItem(ctx, &dynamodb.PutItemInput{
		TableName: aws.String(b.Name), Item: item,
		ConditionExpression: aws.String("attribute_not_exists(pk)"),
	})
	var ccf *types.ConditionalCheckFailedException
	if err == nil {
		return data, nil
	}
	if !errors.As(err, &ccf) {
		return nil, err
	}
	out, err := b.Client.GetItem(ctx, &dynamodb.GetItemInput{
		TableName: aws.String(b.Name), Key: key(proposalID, hex.EncodeToString(tag)), ConsistentRead: aws.Bool(true),
	})
	if err != nil {
		return nil, err
	}
	v, ok := out.Item[attrData].(*types.AttributeValueMemberB)
	if !ok {
		return nil, errors.New("store: malformed ballot copy")
	}
	return v.Value, nil
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

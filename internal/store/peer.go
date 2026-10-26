package store

import (
	"context"
	"errors"
	"strconv"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"

	"github.com/vettid/service-vault/internal/peer"
)

// The peer's records (peer.Store): pk "rec#<kind>", sk the record's id,
// with its data, its version and, for records that end, its expiry in
// "ttl" (Unix seconds, the table's TTL attribute). DynamoDB deletes
// expired items within days; reads skip them at once.
const (
	attrVersion = "version"
	attrTTL     = "ttl"

	// maxTransactItems and maxTransactBytes bound one TransactWriteItems
	// call; a larger Apply is written in several, each all or nothing.
	maxTransactItems = 100
	maxTransactBytes = 3 << 20
)

// Peer returns the peer's record store on t.
func (t *Table) Peer() peer.Store { return peerStore{t} }

type peerStore struct{ t *Table }

func recPK(kind string) string { return "rec#" + kind }

func expired(item map[string]types.AttributeValue, now time.Time) bool {
	v, ok := item[attrTTL].(*types.AttributeValueMemberN)
	if !ok {
		return false
	}
	s, err := strconv.ParseInt(v.Value, 10, 64)
	return err == nil && now.Unix() >= s
}

func toRecord(kind string, item map[string]types.AttributeValue) (peer.Record, error) {
	r := peer.Record{Kind: kind}
	sk, ok := item[attrSK].(*types.AttributeValueMemberS)
	d, ok2 := item[attrData].(*types.AttributeValueMemberB)
	v, ok3 := item[attrVersion].(*types.AttributeValueMemberN)
	if !ok || !ok2 || !ok3 {
		return r, errors.New("store: malformed peer record")
	}
	r.ID, r.Data = sk.Value, d.Value
	var err error
	if r.Version, err = strconv.ParseUint(v.Value, 10, 64); err != nil {
		return r, errors.New("store: malformed peer record version")
	}
	if e, ok := item[attrTTL].(*types.AttributeValueMemberN); ok {
		if s, err := strconv.ParseInt(e.Value, 10, 64); err == nil {
			r.Expires = time.Unix(s, 0).UTC()
		}
	}
	return r, nil
}

// Load implements peer.Store.
func (s peerStore) Load(ctx context.Context, kind string) ([]peer.Record, error) {
	now := time.Now()
	var out []peer.Record
	p := dynamodb.NewQueryPaginator(s.t.Client, &dynamodb.QueryInput{
		TableName:                 aws.String(s.t.Name),
		KeyConditionExpression:    aws.String("pk = :pk"),
		ExpressionAttributeValues: map[string]types.AttributeValue{":pk": &types.AttributeValueMemberS{Value: recPK(kind)}},
		ConsistentRead:            aws.Bool(true),
	})
	for p.HasMorePages() {
		page, err := p.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, item := range page.Items {
			if expired(item, now) {
				continue
			}
			r, err := toRecord(kind, item)
			if err != nil {
				return nil, err
			}
			out = append(out, r)
		}
	}
	return out, nil
}

// Get implements peer.Store.
func (s peerStore) Get(ctx context.Context, kind, id string) ([]byte, bool, error) {
	out, err := s.t.Client.GetItem(ctx, &dynamodb.GetItemInput{
		TableName:      aws.String(s.t.Name),
		Key:            key(recPK(kind), id),
		ConsistentRead: aws.Bool(true),
	})
	if err != nil {
		return nil, false, err
	}
	if out.Item == nil || expired(out.Item, time.Now()) {
		return nil, false, nil
	}
	r, err := toRecord(kind, out.Item)
	if err != nil {
		return nil, false, err
	}
	return r.Data, true, nil
}

// Apply implements peer.Store: the changes are written in transactions of
// at most 100 items and 3 MiB each, each conditional as peer.Change says
// (an expired item counts as absent).
func (s peerStore) Apply(ctx context.Context, changes []peer.Change) error {
	now := time.Now()
	var batch []types.TransactWriteItem
	size := 0
	flush := func() error {
		if len(batch) == 0 {
			return nil
		}
		_, err := s.t.Client.TransactWriteItems(ctx, &dynamodb.TransactWriteItemsInput{TransactItems: batch})
		batch, size = nil, 0
		var tc *types.TransactionCanceledException
		if errors.As(err, &tc) {
			for _, r := range tc.CancellationReasons {
				if aws.ToString(r.Code) == "ConditionalCheckFailed" {
					return peer.ErrConflict
				}
			}
		}
		return err
	}
	for _, c := range changes {
		w := s.write(c, now)
		n := len(c.Data) + len(c.ID) + 128
		if len(batch) == maxTransactItems || size+n > maxTransactBytes {
			if err := flush(); err != nil {
				return err
			}
		}
		batch = append(batch, w)
		size += n
	}
	return flush()
}

func (s peerStore) write(c peer.Change, now time.Time) types.TransactWriteItem {
	names := map[string]string{}
	vals := map[string]types.AttributeValue{}
	var cond string
	nowN := &types.AttributeValueMemberN{Value: strconv.FormatInt(now.Unix(), 10)}
	absent := "(attribute_not_exists(pk) OR #ttl <= :now)"
	switch {
	case c.IfAbsent:
		cond = absent
		names["#ttl"], vals[":now"] = attrTTL, nowN
	case c.IfVersion != 0 && c.Data == nil:
		cond = absent + " OR #v = :v"
		names["#ttl"], names["#v"] = attrTTL, attrVersion
		vals[":now"], vals[":v"] = nowN, &types.AttributeValueMemberN{Value: strconv.FormatUint(c.IfVersion, 10)}
	case c.IfVersion != 0:
		cond = "#v = :v"
		names["#v"] = attrVersion
		vals[":v"] = &types.AttributeValueMemberN{Value: strconv.FormatUint(c.IfVersion, 10)}
	}
	var expr *string
	if cond != "" {
		expr = aws.String(cond)
	} else {
		names, vals = nil, nil
	}
	if c.Data == nil {
		return types.TransactWriteItem{Delete: &types.Delete{
			TableName: aws.String(s.t.Name), Key: key(recPK(c.Kind), c.ID),
			ConditionExpression: expr, ExpressionAttributeNames: names, ExpressionAttributeValues: vals,
		}}
	}
	item := key(recPK(c.Kind), c.ID)
	item[attrData] = &types.AttributeValueMemberB{Value: c.Data}
	item[attrVersion] = &types.AttributeValueMemberN{Value: strconv.FormatUint(c.IfVersion+1, 10)}
	if !c.Expires.IsZero() {
		item[attrTTL] = &types.AttributeValueMemberN{Value: strconv.FormatInt(c.Expires.Unix(), 10)}
	}
	return types.TransactWriteItem{Put: &types.Put{
		TableName: aws.String(s.t.Name), Item: item,
		ConditionExpression: expr, ExpressionAttributeNames: names, ExpressionAttributeValues: vals,
	}}
}

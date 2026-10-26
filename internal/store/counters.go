package store

import (
	"context"
	"errors"
	"strconv"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"

	"github.com/vettid/service-vault/internal/signin"
)

// Rate-limit counters (signin.Counters): pk "rl#<key>", sk the window's
// start (Unix seconds), an atomic count "n" and "ttl" at the window's end
// plus a day, so DynamoDB deletes it after the window. Each window is its
// own item, so a counter whose item DynamoDB has not deleted yet never
// counts into the next window. Counters live in the table, so a restart
// or a replaced task does not reset them.
const attrCount = "n"

// counterGrace keeps a counter's item a day past its window before the
// table's TTL may delete it (deletion is lazy in any case).
const counterGrace = 24 * time.Hour

// Counters returns the rate-limit counters on t.
func (t *Table) Counters() signin.Counters { return counters{t} }

type counters struct{ t *Table }

// Incr implements signin.Counters with one UpdateItem: ADD is atomic, so
// concurrent callers each get a distinct count.
func (c counters) Incr(ctx context.Context, name string, window time.Duration, now time.Time) (int64, error) {
	start := signin.WindowStart(now, window)
	out, err := c.t.Client.UpdateItem(ctx, &dynamodb.UpdateItemInput{
		TableName:                aws.String(c.t.Name),
		Key:                      key("rl#"+name, strconv.FormatInt(start.Unix(), 10)),
		UpdateExpression:         aws.String("ADD #n :one SET #ttl = if_not_exists(#ttl, :ttl)"),
		ExpressionAttributeNames: map[string]string{"#n": attrCount, "#ttl": attrTTL},
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":one": &types.AttributeValueMemberN{Value: "1"},
			":ttl": &types.AttributeValueMemberN{Value: strconv.FormatInt(start.Add(window+counterGrace).Unix(), 10)},
		},
		ReturnValues: types.ReturnValueUpdatedNew,
	})
	if err != nil {
		return 0, err
	}
	v, ok := out.Attributes[attrCount].(*types.AttributeValueMemberN)
	if !ok {
		return 0, errors.New("store: counter without count")
	}
	return strconv.ParseInt(v.Value, 10, 64)
}

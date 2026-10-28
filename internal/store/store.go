// Package store keeps the service vault's records in one DynamoDB table:
// partition key "pk" and sort key "sk", both strings. Each kind of record
// has its own pk prefix.
package store

import (
	"context"
	"errors"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"

	"github.com/vettid/service-vault/internal/keystore"
)

// Table is the service vault's DynamoDB table.
type Table struct {
	Client *dynamodb.Client
	Name   string
}

const (
	attrPK   = "pk"
	attrSK   = "sk"
	attrData = "data"
	skOne    = "-" // sort key of records that are alone in their partition
)

func key(pk, sk string) map[string]types.AttributeValue {
	return map[string]types.AttributeValue{
		attrPK: &types.AttributeValueMemberS{Value: pk},
		attrSK: &types.AttributeValueMemberS{Value: sk},
	}
}

// Blobs returns the keystore's record store on t: one item per name,
// pk "blob#<name>".
func (t *Table) Blobs() keystore.Blobs { return blobs{t} }

type blobs struct{ t *Table }

func (b blobs) Get(ctx context.Context, name string) ([]byte, error) {
	out, err := b.t.Client.GetItem(ctx, &dynamodb.GetItemInput{
		TableName:      aws.String(b.t.Name),
		Key:            key("blob#"+name, skOne),
		ConsistentRead: aws.Bool(true),
	})
	if err != nil {
		return nil, err
	}
	if out.Item == nil {
		return nil, keystore.ErrNotFound
	}
	v, ok := out.Item[attrData].(*types.AttributeValueMemberB)
	if !ok {
		return nil, errors.New("store: blob without data")
	}
	return v.Value, nil
}

func (b blobs) Create(ctx context.Context, name string, data []byte) error {
	item := key("blob#"+name, skOne)
	item[attrData] = &types.AttributeValueMemberB{Value: data}
	_, err := b.t.Client.PutItem(ctx, &dynamodb.PutItemInput{
		TableName:           aws.String(b.t.Name),
		Item:                item,
		ConditionExpression: aws.String("attribute_not_exists(pk)"),
	})
	var cf *types.ConditionalCheckFailedException
	if errors.As(err, &cf) {
		return keystore.ErrExists
	}
	return err
}

func (b blobs) Delete(ctx context.Context, name string) error {
	_, err := b.t.Client.DeleteItem(ctx, &dynamodb.DeleteItemInput{
		TableName: aws.String(b.t.Name),
		Key:       key("blob#"+name, skOne),
	})
	return err
}

// CreateTable creates the table with on-demand capacity (for tests and
// local runs; deployed tables come from CDK) and waits until it is active.
func (t *Table) CreateTable(ctx context.Context) error {
	_, err := t.Client.CreateTable(ctx, &dynamodb.CreateTableInput{
		TableName:   aws.String(t.Name),
		BillingMode: types.BillingModePayPerRequest,
		AttributeDefinitions: []types.AttributeDefinition{
			{AttributeName: aws.String(attrPK), AttributeType: types.ScalarAttributeTypeS},
			{AttributeName: aws.String(attrSK), AttributeType: types.ScalarAttributeTypeS},
		},
		KeySchema: []types.KeySchemaElement{
			{AttributeName: aws.String(attrPK), KeyType: types.KeyTypeHash},
			{AttributeName: aws.String(attrSK), KeyType: types.KeyTypeRange},
		},
	})
	if err != nil {
		return err
	}
	w := dynamodb.NewTableExistsWaiter(t.Client)
	return w.Wait(ctx, &dynamodb.DescribeTableInput{TableName: aws.String(t.Name)}, time.Minute)
}

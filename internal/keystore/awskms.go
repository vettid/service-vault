package keystore

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
)

// AWSKMS is KMS on AWS: GenerateDataKey with AES_256 and Decrypt, both
// pinned to the key id so a record cannot be steered to another key.
type AWSKMS struct {
	Client *kms.Client
}

// GenerateDataKey implements KMS.
func (a *AWSKMS) GenerateDataKey(ctx context.Context, keyID string) ([]byte, []byte, error) {
	out, err := a.Client.GenerateDataKey(ctx, &kms.GenerateDataKeyInput{
		KeyId:   aws.String(keyID),
		KeySpec: types.DataKeySpecAes256,
	})
	if err != nil {
		return nil, nil, err
	}
	return out.Plaintext, out.CiphertextBlob, nil
}

// Decrypt implements KMS.
func (a *AWSKMS) Decrypt(ctx context.Context, keyID string, wrapped []byte) ([]byte, error) {
	out, err := a.Client.Decrypt(ctx, &kms.DecryptInput{
		KeyId:          aws.String(keyID),
		CiphertextBlob: wrapped,
	})
	if err != nil {
		return nil, err
	}
	return out.Plaintext, nil
}

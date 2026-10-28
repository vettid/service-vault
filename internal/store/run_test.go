package store

import (
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
)

// Only a finished restore of the target table passes: a plain table (a
// swapped -from and -to), one still restoring, and a restore of another
// table are refused.
func TestCheckRestored(t *testing.T) {
	const arnT = "arn:aws:dynamodb:us-east-1:123456789012:table/T"
	to := &types.TableDescription{TableName: aws.String("T"), TableArn: aws.String(arnT), TableStatus: types.TableStatusActive}
	restored := func(status types.TableStatus, rs *types.RestoreSummary) *types.TableDescription {
		return &types.TableDescription{TableName: aws.String("T-restore"), TableStatus: status, RestoreSummary: rs}
	}
	done := func(src *string) *types.RestoreSummary {
		return &types.RestoreSummary{RestoreInProgress: aws.Bool(false), SourceTableArn: src}
	}
	for _, c := range []struct {
		name string
		from *types.TableDescription
		want string // "" passes
	}{
		{"backup of T", restored(types.TableStatusActive, done(aws.String(arnT))), ""},
		{"no source recorded", restored(types.TableStatusActive, done(nil)), ""},
		{"plain table", restored(types.TableStatusActive, nil), "was not restored"},
		{"creating", restored(types.TableStatusCreating, done(aws.String(arnT))), "not ACTIVE"},
		{"in progress", restored(types.TableStatusActive, &types.RestoreSummary{RestoreInProgress: aws.Bool(true)}), "in progress"},
		{"other table", restored(types.TableStatusActive, done(aws.String(arnT+"-other"))), "not T"},
	} {
		err := checkRestored(c.from, to)
		if c.want == "" && err != nil || c.want != "" && (err == nil || !strings.Contains(err.Error(), c.want)) {
			t.Errorf("%s: %v, want %q", c.name, err, c.want)
		}
	}
}

package store

import (
	"strings"
	"testing"
	"time"

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

// A second restore to a point between an earlier restore's point and
// when that restore was done is refused; the same point, an older one or
// a later one is not, nor one past RestoreWindow.
func TestCheckRestoreWindow(t *testing.T) {
	day := 24 * time.Hour
	b1 := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC) // the first restore's backup
	at := b1.Add(5 * day)                              // when it was restored
	past := []Restore{{Point: b1, At: at}}
	now := at.Add(day)
	for _, c := range []struct {
		name  string
		point time.Time
		now   time.Time
		ok    bool
	}{
		{"same backup", b1, now, true},
		{"older backup", b1.Add(-day), now, true},
		{"newer, before the restore", b1.Add(2 * day), now, false},
		{"after the restore", at.Add(time.Hour), now, true},
		{"newer, window over", b1.Add(2 * day), at.Add(RestoreWindow), true},
	} {
		if err := checkRestoreWindow(past, c.point, c.now); (err == nil) != c.ok {
			t.Errorf("%s: %v", c.name, err)
		}
	}
}

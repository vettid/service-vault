import * as cdk from 'aws-cdk-lib';
import { Template } from 'aws-cdk-lib/assertions';
import { AnchorSignerStack, AnchorSignerStackProps } from '../lib/anchor-signer-stack';
import {
  COUNT_EVALUATION_PERIODS, FORWARD_HEARTBEAT_MINUTES, JOURNAL_COPY_FAILED, ROUTINE_WRITES, SIGNER_ALARMS, SIGNS_PER_HOUR,
  TRAIL_QUIET_MINUTES, WATCHED_SOURCES, signerAuditNames, trailFilters,
} from '../lib/anchor-signer-alarms';
import { FORWARD_QUIET_MINUTES } from '../lib/signer-audit-stack';

const SIGNER_ACCT = '444455556666';
const AUDIT_ACCT = '777788889999';
const TASK_ROLE = 'arn:aws:iam::123456789012:role/task';
const BREAK_GLASS = `arn:aws:iam::${SIGNER_ACCT}:role/break-glass`;
const base: AnchorSignerStackProps = {
  envName: 'staging', taskRoleArn: TASK_ROLE, breakGlassRoleArn: BREAK_GLASS,
  signingRoleArn: BREAK_GLASS, votesBucketName: 'votes-staging-site', alarmEmail: 'owner@example.org',
  signatureValidityDays: 365, auditAccount: AUDIT_ACCT, env: { account: SIGNER_ACCT, region: 'us-east-1' },
};
const synth = (region = 'us-east-1') =>
  Template.fromStack(new AnchorSignerStack(new cdk.App(), 'AS', { ...base, env: { account: SIGNER_ACCT, region } }));
const t = synth();
const names = signerAuditNames('staging');
const s = (x: unknown) => JSON.stringify(x);
// A template string as deployed in the aws partition: Fn::Join resolved, AWS::Partition as aws.
const render = (x: any): string => {
  if (typeof x === 'string') return x;
  if (x?.['Fn::Join']) return x['Fn::Join'][1].map(render).join(x['Fn::Join'][0]);
  if (x?.Ref === 'AWS::Partition') return 'aws';
  return JSON.stringify(x);
};
const allRules = (tpl: Template) => Object.values<any>(tpl.findResources('AWS::Events::Rule'));
const rules = (tpl: Template) => allRules(tpl).filter((r) => r.Properties.EventPattern); // the scheduled heartbeat has none
const alarms = () => Object.values<any>(t.findResources('AWS::CloudWatch::Alarm')).map((a) => a.Properties);
const alarm = (name: string) => alarms().find((a) => a.AlarmName === `vettid-anchor-signer-staging-${name}`);
const topicId = () => Object.keys(t.findResources('AWS::SNS::Topic'))[0];
const BUS = `:events:us-east-1:${AUDIT_ACCT}:event-bus/${names.bus}`;
const signerRoleArn = `arn:aws:iam::${SIGNER_ACCT}:role/vettid-anchor-signer-staging`;
const filters = trailFilters({ breakGlassRoleArn: BREAK_GLASS, signerRoleArn, taskAccount: '123456789012' });

describe('targets and the topic', () => {
  test('every rule reaches the topic and the bus; alarm state changes and the heartbeat, the bus only', () => {
    for (const r of allRules(t)) {
      const tg = r.Properties.Targets;
      const bus = tg.find((x: any) => s(x.Arn).includes(BUS));
      expect(bus).toBeDefined();
      expect(s(bus.RoleArn)).toContain('AlarmForwardRole');
      const busOnly = r.Properties.ScheduleExpression || r.Properties.EventPattern['detail-type']?.[0] === 'CloudWatch Alarm State Change';
      expect(tg.some((x: any) => s(x.Arn).includes(topicId()))).toBe(!busOnly);
    }
  });

  test("the topic's policy: this account's EventBridge rules and CloudWatch alarms (prefix), nothing else", () => {
    const policies = Object.values<any>(t.findResources('AWS::SNS::TopicPolicy'));
    expect(policies).toHaveLength(1);
    const st = policies[0].Properties.PolicyDocument.Statement;
    expect(st.map((x: any) => x.Sid).sort()).toEqual(['AlarmsOfThisAccount', 'RulesOfThisAccount']);
    const ev = st.find((x: any) => x.Sid === 'RulesOfThisAccount');
    expect(ev.Principal).toEqual({ Service: 'events.amazonaws.com' });
    expect(ev.Action).toBe('sns:Publish');
    expect(ev.Condition.StringEquals).toEqual({ 'aws:SourceAccount': SIGNER_ACCT });
    expect(s(ev.Condition.ArnLike['aws:SourceArn'])).toContain(`:events:us-east-1:${SIGNER_ACCT}:rule/*`);
    const cw = st.find((x: any) => x.Sid === 'AlarmsOfThisAccount');
    expect(cw.Principal).toEqual({ Service: 'cloudwatch.amazonaws.com' });
    expect(cw.Action).toBe('sns:Publish');
    expect(cw.Condition.StringEquals).toEqual({ 'aws:SourceAccount': SIGNER_ACCT });
    expect(s(cw.Condition.ArnLike['aws:SourceArn'])).toContain(`:cloudwatch:us-east-1:${SIGNER_ACCT}:alarm:vettid-anchor-signer-staging-*`);
  });

  test('the forwarding role: EventBridge of this account only, PutEvents on that bus only', () => {
    const role = Object.values<any>(t.findResources('AWS::IAM::Role')).find((r) => r.Properties.RoleName === names.forwardRole);
    expect(role.Properties.AssumeRolePolicyDocument.Statement[0].Principal).toEqual({ Service: 'events.amazonaws.com' });
    expect(role.Properties.AssumeRolePolicyDocument.Statement[0].Condition).toEqual({ StringEquals: { 'aws:SourceAccount': SIGNER_ACCT } });
    const st = Object.values<any>(t.findResources('AWS::IAM::Policy')).filter((p) => s(p.Properties.Roles).includes('AlarmForwardRole'))
      .flatMap((p) => p.Properties.PolicyDocument.Statement);
    expect(st).toHaveLength(1);
    expect(st[0].Action).toBe('events:PutEvents');
    expect(s(st[0].Resource)).toContain(BUS);
  });

  test('the heartbeat: every 5 minutes, through the forwarding role, to the bus; the audit side waits for 3 missed', () => {
    expect(FORWARD_HEARTBEAT_MINUTES).toBe(5);
    expect(FORWARD_QUIET_MINUTES).toBe(3 * FORWARD_HEARTBEAT_MINUTES);
    const beat = allRules(t).filter((r) => r.Properties.ScheduleExpression);
    expect(beat).toHaveLength(1);
    expect(beat[0].Properties.ScheduleExpression).toBe(`rate(${FORWARD_HEARTBEAT_MINUTES} minutes)`);
    expect(beat[0].Properties.Targets).toHaveLength(1);
  });

  test('alarm state changes into ALARM, by prefix, are forwarded', () => {
    const out = rules(t).filter((r) => r.Properties.EventPattern['detail-type']?.[0] === 'CloudWatch Alarm State Change');
    expect(out).toHaveLength(1);
    expect(out[0].Properties.EventPattern.detail).toEqual({ alarmName: [{ prefix: 'vettid-anchor-signer-staging-' }], state: { value: ['ALARM'] } });
  });
});

describe('the trail and the copies', () => {
  test('the trail: every region, global events, file validation, into trail/ and a log group', () => {
    t.hasResourceProperties('AWS::CloudTrail::Trail', { TrailName: names.trail, IsMultiRegionTrail: true, IncludeGlobalServiceEvents: true,
      EnableLogFileValidation: true, IsLogging: true, S3KeyPrefix: 'trail' });
    const trail = Object.values<any>(t.findResources('AWS::CloudTrail::Trail'))[0].Properties;
    expect(s(trail.CloudWatchLogsLogGroupArn)).toContain('TrailLogs');
  });

  test('advanced selectors: management events; claim writes; the signer\'s invokes', () => {
    const trail = Object.values<any>(t.findResources('AWS::CloudTrail::Trail'))[0].Properties;
    expect(trail.EventSelectors).toBeUndefined();
    const sel = trail.AdvancedEventSelectors;
    expect(sel).toHaveLength(3);
    expect(sel[0].FieldSelectors).toEqual([{ Field: 'eventCategory', Equals: ['Management'] }]);
    expect(sel[1].FieldSelectors).toContainEqual({ Field: 'resources.type', Equals: ['AWS::DynamoDB::Table'] });
    expect(sel[1].FieldSelectors).toContainEqual({ Field: 'readOnly', Equals: ['false'] });
    expect(s(sel[1].FieldSelectors)).toContain('Claims');
    expect(sel[2].FieldSelectors).toContainEqual({ Field: 'resources.type', Equals: ['AWS::Lambda::Function'] });
    expect(s(sel[2].FieldSelectors)).toContain(`:lambda:us-east-1:${SIGNER_ACCT}:function:vettid-anchor-signer-staging`);
    // The operators: the claim table by Equals; the function by StartsWith
    // (qualified ARNs too); invokes read or write (no readOnly field).
    expect(Object.keys(sel[1].FieldSelectors.find((f: any) => f.Field === 'resources.ARN')).sort()).toEqual(['Equals', 'Field']);
    expect(Object.keys(sel[2].FieldSelectors.find((f: any) => f.Field === 'resources.ARN')).sort()).toEqual(['Field', 'StartsWith']);
    expect(sel[2].FieldSelectors.find((f: any) => f.Field === 'readOnly')).toBeUndefined();
  });

  test("the trail's log role: CloudTrail, for this trail of this account only", () => {
    const role = Object.entries<any>(t.findResources('AWS::IAM::Role')).find(([id]) => id.startsWith('TrailLogsRole'))![1];
    const st = role.Properties.AssumeRolePolicyDocument.Statement[0];
    expect(st.Principal).toEqual({ Service: 'cloudtrail.amazonaws.com' });
    expect(st.Condition.StringEquals).toEqual({ 'aws:SourceAccount': SIGNER_ACCT });
    expect(s(st.Condition.ArnLike['aws:SourceArn'])).toContain(`:cloudtrail:us-east-1:${SIGNER_ACCT}:trail/${names.trail}`);
  });

  test('the audit bucket: fixed name, versioned, lock-enabled with no default retention, replicated, no deletes', () => {
    const b = Object.values<any>(t.findResources('AWS::S3::Bucket')).find((x) => x.Properties.ReplicationConfiguration).Properties;
    expect(b.BucketName).toBe(names.sourceBucket(SIGNER_ACCT));
    expect(b.VersioningConfiguration.Status).toBe('Enabled');
    expect(b.ObjectLockEnabled).toBe(true);
    expect(b.ObjectLockConfiguration).toBeUndefined();
    const r = b.ReplicationConfiguration.Rules;
    expect(r).toHaveLength(1);
    expect(r[0].DeleteMarkerReplication).toEqual({ Status: 'Disabled' });
    expect(r[0].Filter).toEqual({ Prefix: '' });
    expect(r[0].Destination.Account).toBe(AUDIT_ACCT);
    expect(s(r[0].Destination.Bucket)).toContain(`:s3:::${names.bucket(AUDIT_ACCT)}`);
  });

  test('the replication role: S3, this bucket, this account; reads the source; only ReplicateObject on the copy', () => {
    const role = Object.values<any>(t.findResources('AWS::IAM::Role')).find((r) => r.Properties.RoleName === names.replicationRole);
    const trust = role.Properties.AssumeRolePolicyDocument.Statement[0];
    expect(trust.Principal).toEqual({ Service: 's3.amazonaws.com' });
    expect(trust.Condition.StringEquals).toEqual({ 'aws:SourceAccount': SIGNER_ACCT });
    expect(s(trust.Condition.ArnLike['aws:SourceArn'])).toContain(`:s3:::${names.sourceBucket(SIGNER_ACCT)}`);
    const st = Object.values<any>(t.findResources('AWS::IAM::Policy')).filter((p) => s(p.Properties.Roles).includes('AuditReplicationRole'))
      .flatMap((p) => p.Properties.PolicyDocument.Statement);
    const dest = st.filter((x) => s(x.Resource).includes(names.bucket(AUDIT_ACCT)));
    expect(dest).toHaveLength(1);
    expect(dest[0].Action).toBe('s3:ReplicateObject');
    for (const x of st) expect(s(x.Action)).not.toMatch(/ReplicateDelete|DeleteObject|PutObject|s3:\*/);
  });

  test("the journal's copy: Firehose with its own role, which may only add objects under journal/", () => {
    const fh = Object.values<any>(t.findResources('AWS::KinesisFirehose::DeliveryStream'));
    expect(fh).toHaveLength(1);
    expect(fh[0].Properties.DeliveryStreamName).toBe(names.journalCopy);
    const d = fh[0].Properties.ExtendedS3DestinationConfiguration;
    expect(d.Prefix).toBe('journal/');
    expect(d.ErrorOutputPrefix).toBe('journal-errors/');
    expect(s(d.RoleARN)).toContain('JournalCopyRole');
    const role = Object.entries<any>(t.findResources('AWS::IAM::Role')).find(([id]) => id.startsWith('JournalCopyRole'))![1];
    const trust = role.Properties.AssumeRolePolicyDocument.Statement[0];
    expect(trust.Principal).toEqual({ Service: 'firehose.amazonaws.com' });
    expect(s(trust.Condition.ArnLike['aws:SourceArn'])).toContain(`deliverystream/${names.journalCopy}`);
    const st = Object.values<any>(t.findResources('AWS::IAM::Policy')).filter((p) => s(p.Properties.Roles).includes('JournalCopyRole'))
      .flatMap((p) => p.Properties.PolicyDocument.Statement);
    expect(st.flatMap((x) => [x.Action].flat()).sort()).toEqual(
      ['s3:AbortMultipartUpload', 's3:GetBucketLocation', 's3:ListBucket', 's3:ListBucketMultipartUploads', 's3:PutObject']);
    const put = st.find((x) => [x.Action].flat().includes('s3:PutObject'));
    expect(put.Resource.map(render)).toEqual([`arn:aws:s3:::${names.sourceBucket(SIGNER_ACCT)}/journal/*`, `arn:aws:s3:::${names.sourceBucket(SIGNER_ACCT)}/journal-errors/*`]);
    expect(trust.Condition.StringEquals).toEqual({ 'aws:SourceAccount': SIGNER_ACCT });
    const sub = Object.values<any>(t.findResources('AWS::Logs::SubscriptionFilter'));
    expect(sub).toHaveLength(1);
    expect(sub[0].Properties.FilterPattern).toBe('');
    expect(s(sub[0].Properties.LogGroupName)).toContain('Journal');
  });

  test('the journal\'s copy failing to deliver alarms', () => {
    const a = alarm('journal_copy_failed');
    expect(a.Threshold).toBe(1);
    expect(JOURNAL_COPY_FAILED).toBe('IF(records > 0 AND FILL(ok, 1) < 1, 1, 0)');
    expect(a.Metrics.find((m: any) => m.Expression).Expression).toBe(JOURNAL_COPY_FAILED);
    expect(s(a.Metrics)).toContain('DeliveryToS3.Success');
    expect(s(a.AlarmActions)).toContain(topicId());
  });
});

describe('rules', () => {
  test('any management write to each watched service alarms', () => {
    for (const src of WATCHED_SOURCES) {
      const r = rules(t).filter((x) => s(x.Properties.EventPattern.detail?.eventSource) === s([src]));
      expect(r).toHaveLength(1);
      // Management events only: the trail's data events (claim writes,
      // invokes) reach EventBridge as writes too, and must not alarm.
      const want: any = { eventSource: [src], readOnly: [false], eventCategory: ['Management'] };
      if (ROUTINE_WRITES[src]) want.eventName = [{ 'anything-but': ROUTINE_WRITES[src] }];
      expect(r[0].Properties.EventPattern.detail).toEqual(want);
      expect(r[0].Properties.EventPattern['detail-type']).toEqual(['AWS API Call via CloudTrail']);
    }
    expect(WATCHED_SOURCES).toEqual(['lambda', 'signer', 'kms', 'dynamodb', 'logs', 'sns', 'events', 'monitoring', 'guardduty', 's3',
      'firehose', 'cloudtrail', 'cloudformation', 'tagging', 'rolesanywhere', 'account'].map((x) => `${x}.amazonaws.com`));
    expect(ROUTINE_WRITES).toEqual({
      'logs.amazonaws.com': ['CreateLogStream'], 'events.amazonaws.com': ['PutEvents'], 'kms.amazonaws.com': ['Sign', 'Verify', 'GetPublicKey'],
    });
  });

  test('the key\'s use: errors and other principals, read-only events seen', () => {
    const kms = rules(t).filter((r) => r.Properties.EventPattern.source?.[0] === 'aws.kms');
    expect(kms).toHaveLength(2);
    for (const r of kms) {
      expect(r.Properties.State).toBe('ENABLED_WITH_ALL_CLOUDTRAIL_MANAGEMENT_EVENTS');
      expect(r.Properties.EventPattern.detail.eventName).toEqual(['Sign', 'GetPublicKey']);
      expect(s(r.Properties.EventPattern.detail.resources)).toContain('AnchorKey');
    }
    const err = kms.find((r) => r.Properties.EventPattern.detail.errorCode);
    expect(err.Properties.EventPattern.detail.errorCode).toEqual([{ exists: true }]);
    const other = kms.find((r) => r.Properties.EventPattern.detail.$or).Properties.EventPattern.detail.$or;
    expect(other[0].userIdentity).toEqual({ type: [{ 'anything-but': ['AssumedRole'] }] });
    expect(other[1].userIdentity.type).toEqual(['AssumedRole']);
    expect(s(other[1].userIdentity.arn)).toContain('assumed-role/vettid-anchor-signer-staging/');
    // Write rules see write events only (their default state).
    for (const r of rules(t).filter((x) => x.Properties.EventPattern.detail?.readOnly)) expect(r.Properties.State).toBe('ENABLED');
  });

  test('GuardDuty on, its findings alarmed', () => {
    t.hasResourceProperties('AWS::GuardDuty::Detector', { Enable: true });
    expect(rules(t).filter((r) => r.Properties.EventPattern.source?.[0] === 'aws.guardduty')).toHaveLength(1);
  });
});

describe('alarms', () => {
  test('the trail filters, pinned, in any region', () => {
    expect(filters.entry).toBe('{ (($.eventSource = "sts.amazonaws.com") && ($.eventName = "AssumeRole*") && ($.userIdentity.type != "AWSService")) || ($.eventName = "ConsoleLogin") || ($.eventName = "GetFederationToken") || ($.eventName = "GetSessionToken") }');
    expect(filters.root_use).toBe('{ ($.userIdentity.type = "Root") && ($.eventType != "AwsServiceEvent") }');
    expect(filters.iam_change).toBe('{ ($.eventSource = "iam.amazonaws.com") && ($.readOnly IS FALSE) }');
    expect(filters.claims_delete).toBe('{ ($.eventCategory = "Data") && ($.eventSource = "dynamodb.amazonaws.com") && ($.eventName = "DeleteItem") }');
    expect(filters.claims_write_other).toBe(`{ ($.eventCategory = "Data") && ($.eventSource = "dynamodb.amazonaws.com") && (($.userIdentity.type != "AssumedRole") || ($.userIdentity.sessionContext.sessionIssuer.arn != "${signerRoleArn}")) }`);
    expect(filters.invoke_other).toBe('{ ($.eventCategory = "Data") && ($.eventSource = "lambda.amazonaws.com") && (($.userIdentity.accountId != "123456789012") || ($.errorCode EXISTS)) }');
    expect(filters.break_glass).toBe(`{ (($.eventName = "AssumeRole") && ($.requestParameters.roleArn = "${BREAK_GLASS}")) || ($.userIdentity.sessionContext.sessionIssuer.arn = "${BREAK_GLASS}") }`);
    const fs = Object.values<any>(t.findResources('AWS::Logs::MetricFilter')).filter((x) => s(x.Properties.LogGroupName).includes('TrailLogs'));
    for (const [name, pattern] of Object.entries(filters)) {
      expect(render(fs.find((x) => x.Properties.MetricTransformations[0].MetricName === name).Properties.FilterPattern)).toBe(pattern);
    }
    // The same in any region: no region-only rules, and no warning.
    const app = new cdk.App();
    const west = new AnchorSignerStack(app, 'AS', { ...base, env: { account: SIGNER_ACCT, region: 'us-west-2' } });
    const tw = Template.fromStack(west);
    expect(Object.values<any>(tw.findResources('AWS::Logs::MetricFilter')).filter((x) => s(x.Properties.LogGroupName).includes('TrailLogs')))
      .toHaveLength(Object.keys(filters).length + 1);
    expect(app.synth().getStackArtifact(west.artifactId).messages.filter((m) => m.level === 'warning')).toHaveLength(0);
  });

  test('every count alarm: >= its threshold, any 1 of 3 five-minute periods, missing data not breaching, to the topic', () => {
    expect(COUNT_EVALUATION_PERIODS).toBe(3);
    for (const name of [...SIGNER_ALARMS, ...Object.keys(filters), 'rule_target_failed']) {
      const a = alarm(name);
      expect(a).toBeDefined();
      expect(a.Threshold).toBe(1);
      expect(a.ComparisonOperator).toBe('GreaterThanOrEqualToThreshold');
      if (name !== 'rule_target_failed') expect(a.Period).toBe(300);
      expect(a.EvaluationPeriods).toBe(3);
      expect(a.DatapointsToAlarm).toBe(1);
      expect(a.TreatMissingData).toBe('notBreaching');
      expect(s(a.AlarmActions)).toContain(topicId());
    }
  });

  test('more than 20 signs an hour, counted from the journal and from the trail', () => {
    for (const n of ['signs_per_hour', 'kms_signs_per_hour']) {
      const a = alarm(n);
      expect(a.Threshold).toBe(SIGNS_PER_HOUR + 1);
      expect(a.ComparisonOperator).toBe('GreaterThanOrEqualToThreshold');
      expect(a.Period).toBe(3600);
      expect(s(a.AlarmActions)).toContain(topicId());
    }
    const kms = Object.values<any>(t.findResources('AWS::Logs::MetricFilter')).find((f) => f.Properties.MetricTransformations[0].MetricName === 'kms_signs');
    expect(kms.Properties.FilterPattern).toBe('{ ($.eventSource = "kms.amazonaws.com") && ($.eventName = "Sign") }');
    expect(s(kms.Properties.LogGroupName)).toContain('TrailLogs');
  });

  test("the trail's log group going quiet for 30 minutes alarms, missing data breaching", () => {
    const a = alarm('trail_logs_quiet');
    expect(TRAIL_QUIET_MINUTES).toBe(30);
    expect(a.Threshold).toBe(1);
    expect(a.EvaluationPeriods).toBe(6);
    expect(a.Namespace).toBe('AWS/Logs');
    expect(a.MetricName).toBe('IncomingLogEvents');
    expect(a.ComparisonOperator).toBe('LessThanThreshold');
    expect(a.Period * a.EvaluationPeriods).toBe(TRAIL_QUIET_MINUTES * 60);
    expect(a.TreatMissingData).toBe('breaching');
    expect(s(a.AlarmActions)).toContain(topicId());
  });
});

test('auditAccount: the management account, neither this one nor the service account', () => {
  const mk = (auditAccount: string) => () => new AnchorSignerStack(new cdk.App(), 'X', { ...base, auditAccount });
  expect(mk(SIGNER_ACCT)).toThrow(/auditAccount/);
  expect(mk('123456789012')).toThrow(/auditAccount/);
  expect(mk('7777')).toThrow(/auditAccount/);
  expect(mk(AUDIT_ACCT)).not.toThrow();
});

test('no other function in the signer account: without a release, none at all (no custom resources)', () => {
  expect(Object.keys(t.findResources('AWS::Lambda::Function'))).toHaveLength(0);
  expect(Object.keys(t.findResources('AWS::CloudFormation::CustomResource'))).toHaveLength(0);
});

test('a rule failing to deliver to its target alarms (any rule)', () => {
  const a = alarm('rule_target_failed');
  expect(s(a.Metrics)).toContain('FailedInvocations');
  expect(s(a.AlarmActions)).toContain(topicId());
});

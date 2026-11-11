import * as cdk from 'aws-cdk-lib';
import { Template } from 'aws-cdk-lib/assertions';
import { AnchorSignerStack, AnchorSignerStackProps } from '../lib/anchor-signer-stack';
import { ALARM_PATH_CHANGES, AUDIT_CHANGES, FORWARD_HEARTBEAT_MINUTES, SIGNER_ALARMS, SIGNS_PER_HOUR, TRAIL_QUIET_MINUTES, signerAuditNames, trailFilters } from '../lib/anchor-signer-alarms';

const SIGNER_ACCT = '444455556666';
const AUDIT_ACCT = '777788889999';
const base: AnchorSignerStackProps = {
  envName: 'staging', taskRoleArn: 'arn:aws:iam::123456789012:role/task', breakGlassRoleArn: `arn:aws:iam::${SIGNER_ACCT}:role/break-glass`,
  signingRoleArn: `arn:aws:iam::${SIGNER_ACCT}:role/break-glass`, votesBucketName: 'votes-staging-site', alarmEmail: 'owner@example.org',
  signatureValidityDays: 365, auditAccount: AUDIT_ACCT, env: { account: SIGNER_ACCT, region: 'us-east-1' },
};
const synth = (region = 'us-east-1') =>
  Template.fromStack(new AnchorSignerStack(new cdk.App(), 'AS', { ...base, env: { account: SIGNER_ACCT, region } }));
const t = synth();
const allRules = (tpl: Template) => Object.values<any>(tpl.findResources('AWS::Events::Rule'));
const rules = (tpl: Template) => allRules(tpl).filter((r) => r.Properties.EventPattern); // the scheduled heartbeat has none
const ruleFor = (tpl: Template, source: string, name?: string) => rules(tpl).filter((r) => {
  const p = r.Properties.EventPattern;
  return p.source?.includes(source) && (!name || JSON.stringify(p.detail?.eventName ?? []).includes(name));
});
const s = (x: unknown) => JSON.stringify(x);

test('every rule reaches the account topic and the management account\'s bus (alarm state changes: the bus only)', () => {
  const topic = Object.keys(t.findResources('AWS::SNS::Topic'));
  expect(topic).toHaveLength(1);
  const bus = `:events:us-east-1:${AUDIT_ACCT}:event-bus/${signerAuditNames('staging').bus}`;
  for (const r of rules(t)) {
    expect(s(r.Properties.Targets)).toContain(bus);
    if (r.Properties.EventPattern['detail-type']?.[0] === 'CloudWatch Alarm State Change') continue;
    expect(s(r.Properties.Targets)).toContain(topic[0]);
  }
  const out = rules(t).filter((r) => r.Properties.EventPattern['detail-type']?.[0] === 'CloudWatch Alarm State Change');
  expect(out).toHaveLength(1);
  expect(out[0].Properties.EventPattern.detail).toEqual({ alarmName: [{ prefix: 'vettid-anchor-signer-staging-' }], state: { value: ['ALARM'] } });
});

test('the forwarding role: EventBridge of this account only, PutEvents on that bus only', () => {
  const role = Object.values<any>(t.findResources('AWS::IAM::Role')).find((r) => r.Properties.RoleName === signerAuditNames('staging').forwardRole);
  expect(role.Properties.AssumeRolePolicyDocument.Statement[0].Principal).toEqual({ Service: 'events.amazonaws.com' });
  expect(role.Properties.AssumeRolePolicyDocument.Statement[0].Condition).toEqual({ StringEquals: { 'aws:SourceAccount': SIGNER_ACCT } });
  const stmts = Object.values<any>(t.findResources('AWS::IAM::Policy')).filter((p) => s(p.Properties.Roles).includes('AlarmForwardRole'))
    .flatMap((p) => p.Properties.PolicyDocument.Statement);
  expect(stmts.length).toBeGreaterThanOrEqual(1); // ours, and the target's own grant of the same
  for (const st of stmts) {
    expect(st.Action).toBe('events:PutEvents');
    expect(s(st.Resource)).toContain(`:events:us-east-1:${AUDIT_ACCT}:event-bus/${signerAuditNames('staging').bus}`);
  }
});

test('the trail: every region, global events, file validation, into trail/', () => {
  t.hasResourceProperties('AWS::CloudTrail::Trail', { IsMultiRegionTrail: true, IncludeGlobalServiceEvents: true,
    EnableLogFileValidation: true, IsLogging: true, S3KeyPrefix: 'trail' });
  expect(ruleFor(t, 'aws.cloudtrail', 'StopLogging')).toHaveLength(1);
});

test('the audit bucket: versioned, lock-enabled with no default retention, replicated to the management account, no deletes', () => {
  const buckets = Object.values<any>(t.findResources('AWS::S3::Bucket')).filter((b) => b.Properties.ReplicationConfiguration);
  expect(buckets).toHaveLength(1);
  const b = buckets[0].Properties;
  expect(b.VersioningConfiguration.Status).toBe('Enabled');
  expect(b.ObjectLockEnabled).toBe(true);
  expect(b.ObjectLockConfiguration).toBeUndefined(); // no default retention: no Content-MD5 needed to write
  expect(b.OwnershipControls.Rules[0].ObjectOwnership).toBe('BucketOwnerEnforced');
  const rules = b.ReplicationConfiguration.Rules;
  expect(rules).toHaveLength(1);
  expect(rules[0].Status).toBe('Enabled');
  expect(rules[0].DeleteMarkerReplication).toEqual({ Status: 'Disabled' });
  expect(s(rules[0].Destination.Bucket)).toContain(`:s3:::${signerAuditNames('staging').bucket(AUDIT_ACCT)}`);
  expect(rules[0].Destination.Account).toBe(AUDIT_ACCT);
  expect(rules[0].Filter).toEqual({ Prefix: '' }); // everything: trail/, journal/ and journal-errors/
});

test('the replication role: S3 of this account only, reads the source, may only ReplicateObject into the copy', () => {
  const role = Object.values<any>(t.findResources('AWS::IAM::Role')).find((r) => r.Properties.RoleName === signerAuditNames('staging').replicationRole);
  expect(role).toBeDefined();
  const trust = role.Properties.AssumeRolePolicyDocument.Statement;
  expect(trust).toHaveLength(1);
  expect(trust[0].Principal).toEqual({ Service: 's3.amazonaws.com' });
  expect(trust[0].Condition.StringEquals).toEqual({ 'aws:SourceAccount': SIGNER_ACCT });
  expect(s(trust[0].Condition.ArnLike['aws:SourceArn'])).toContain(`:s3:::${signerAuditNames('staging').sourceBucket(SIGNER_ACCT)}`);
  const policies = Object.values<any>(t.findResources('AWS::IAM::Policy'))
    .filter((p) => s(p.Properties.Roles).includes('AuditReplicationRole'));
  const stmts = policies.flatMap((p) => p.Properties.PolicyDocument.Statement);
  const dest = stmts.filter((st) => s(st.Resource).includes(signerAuditNames('staging').bucket(AUDIT_ACCT)));
  expect(dest).toHaveLength(1);
  expect(dest[0].Action).toBe('s3:ReplicateObject');
  for (const st of stmts) {
    expect(s(st.Action)).not.toMatch(/ReplicateDelete|DeleteObject|PutObject"|s3:\*/);
  }
});

test("the journal's copy: every line, through Firehose, into journal/", () => {
  const sub = Object.values<any>(t.findResources('AWS::Logs::SubscriptionFilter'));
  expect(sub).toHaveLength(1);
  expect(sub[0].Properties.FilterPattern).toBe('');
  expect(s(sub[0].Properties.LogGroupName)).toContain('Journal');
  expect(s(sub[0].Properties.DestinationArn)).toContain('JournalCopy');
  const fh = Object.values<any>(t.findResources('AWS::KinesisFirehose::DeliveryStream'));
  expect(fh).toHaveLength(1);
  const dest = fh[0].Properties.ExtendedS3DestinationConfiguration;
  expect(dest.Prefix).toBe('journal/');
  expect(dest.ErrorOutputPrefix).toBe('journal-errors/');
  expect(s(dest.BucketARN)).toContain('AuditBucket');
});

test('a change to the copy path alarms: replication, bucket policy, versioning, lifecycle, the Firehose, the subscription', () => {
  const r = rules(t).filter((x) => s(x.Properties.EventPattern.source) === s(['aws.s3', 'aws.firehose']));
  expect(r).toHaveLength(1);
  expect(r[0].Properties.EventPattern.detail.eventName).toEqual([...AUDIT_CHANGES]);
  for (const n of ['PutBucketReplication', 'DeleteBucketReplication', 'PutBucketPolicy', 'PutBucketVersioning', 'DeleteDeliveryStream',
    'PutBucketEncryption', 'DeleteBucketEncryption', 'PutObjectLockConfiguration', 'PutBucketPublicAccessBlock', 'DeleteBucketPublicAccessBlock']) {
    expect(AUDIT_CHANGES).toContain(n);
  }
  expect(ruleFor(t, 'aws.logs', 'DeleteSubscriptionFilter')).toHaveLength(1);
});

test('GuardDuty on, its findings alarmed', () => {
  t.hasResourceProperties('AWS::GuardDuty::Detector', { Enable: true });
  expect(rules(t).filter((r) => r.Properties.EventPattern.source?.[0] === 'aws.guardduty')).toHaveLength(1);
});

test('the key: errors, another principal, changes, aliases', () => {
  const kms = ruleFor(t, 'aws.kms');
  expect(kms.length).toBe(4);
  const other = kms.find((r) => s(r.Properties.EventPattern).includes('anything-but'));
  expect(s(other.Properties.EventPattern)).toContain(`assumed-role/vettid-anchor-signer-staging/`);
  expect(ruleFor(t, 'aws.kms', 'UpdateAlias').length).toBeGreaterThanOrEqual(1); // the alias rule, and key_change's list
  expect(ruleFor(t, 'aws.kms', 'PutKeyPolicy')).toHaveLength(1);
});

test('Sign and GetPublicKey are read-only events: their rules see them (all management events)', () => {
  const uses = ruleFor(t, 'aws.kms', 'GetPublicKey');
  expect(uses).toHaveLength(2);
  for (const r of uses) expect(r.Properties.State).toBe('ENABLED_WITH_ALL_CLOUDTRAIL_MANAGEMENT_EVENTS');
  // The write-event rules stay as they were.
  for (const r of ruleFor(t, 'aws.kms', 'PutKeyPolicy')) expect(r.Properties.State).toBe('ENABLED');
});

test('another principal: callers that are not role sessions, and role sessions other than the signer', () => {
  const other = ruleFor(t, 'aws.kms', 'GetPublicKey').find((r) => s(r.Properties.EventPattern).includes('$or'));
  const branches = other.Properties.EventPattern.detail.$or;
  expect(branches[0].userIdentity).toEqual({ type: [{ 'anything-but': ['AssumedRole'] }] });
  expect(branches[1].userIdentity.type).toEqual(['AssumedRole']);
  expect(s(branches[1].userIdentity.arn)).toContain('assumed-role/vettid-anchor-signer-staging/');
});

test('the function, the profile, the claims and the journal', () => {
  for (const n of ['UpdateFunctionCode', 'UpdateFunctionConfiguration', 'PutFunctionCodeSigningConfig', 'AddPermission',
    'PutResourcePolicy', 'PutFunctionConcurrency', 'PublishLayerVersion', 'CreateEventSourceMapping', 'UpdateEventSourceMapping',
    'DeleteAlias', 'PutFunctionEventInvokeConfig', 'PutProvisionedConcurrencyConfig', 'PutFunctionRecursionConfig', 'UpdateFunctionUrlConfig']) {
    expect(ruleFor(t, 'aws.lambda', n)).toHaveLength(1);
  }
  expect(ruleFor(t, 'aws.signer', 'RevokeSignature')).toHaveLength(1);
  expect(ruleFor(t, 'aws.dynamodb', 'DeleteTable')).toHaveLength(1);
  expect(ruleFor(t, 'aws.logs', 'PutRetentionPolicy')).toHaveLength(1);
  // Lambda's events carry an API version: matched as prefixes.
  expect(s(ruleFor(t, 'aws.lambda')[0].Properties.EventPattern)).toContain('"prefix":"UpdateFunctionCode"');
});

test('the trail: management events and the claim table\'s writes (advanced selectors), copied to a log group', () => {
  const trail = Object.values<any>(t.findResources('AWS::CloudTrail::Trail'))[0].Properties;
  expect(trail.EventSelectors).toBeUndefined(); // advanced selectors only: the two can't be mixed
  const sel = trail.AdvancedEventSelectors;
  expect(sel).toHaveLength(2);
  expect(sel[0].FieldSelectors).toEqual([{ Field: 'eventCategory', Equals: ['Management'] }]);
  const data = sel[1].FieldSelectors;
  expect(data).toContainEqual({ Field: 'eventCategory', Equals: ['Data'] });
  expect(data).toContainEqual({ Field: 'resources.type', Equals: ['AWS::DynamoDB::Table'] });
  expect(data).toContainEqual({ Field: 'readOnly', Equals: ['false'] });
  expect(s(data.find((f: any) => f.Field === 'resources.ARN').Equals)).toContain('Claims');
  expect(s(trail.CloudWatchLogsLogGroupArn)).toContain('TrailLogs');
});

test('any region: break-glass use, root use, IAM writes, claim writes and deletes, from the trail\'s log group', () => {
  const f = trailFilters(base.breakGlassRoleArn, 'vettid-anchor-signer-staging');
  const filters = Object.values<any>(t.findResources('AWS::Logs::MetricFilter')).filter((x) => s(x.Properties.LogGroupName).includes('TrailLogs'));
  for (const [name, pattern] of Object.entries(f)) {
    const m = filters.find((x) => x.Properties.MetricTransformations[0].MetricName === name);
    expect(m).toBeDefined();
    expect(m.Properties.FilterPattern).toBe(pattern);
    t.hasResourceProperties('AWS::CloudWatch::Alarm', { AlarmName: `vettid-anchor-signer-staging-${name}`, Threshold: 1 });
  }
  expect(f.break_glass).toContain(`$.requestParameters.roleArn = "${base.breakGlassRoleArn}"`);
  expect(f.break_glass).toContain(`$.userIdentity.sessionContext.sessionIssuer.arn = "${base.breakGlassRoleArn}"`);
  expect(f.root_use).toContain('$.userIdentity.type = "Root"');
  expect(f.claims_write_other).toContain('sessionIssuer.userName != "vettid-anchor-signer-staging"');
  // The same in every region: no region-only rules, and no warning.
  const app = new cdk.App();
  const west = new AnchorSignerStack(app, 'AS', { ...base, env: { account: SIGNER_ACCT, region: 'us-west-2' } });
  const tw = Template.fromStack(west);
  expect(Object.values<any>(tw.findResources('AWS::Logs::MetricFilter')).filter((x) => s(x.Properties.LogGroupName).includes('TrailLogs'))).toHaveLength(6);
  expect(rules(tw).filter((r) => ['aws.iam', 'aws.sts', 'aws.signin'].includes(r.Properties.EventPattern.source?.[0]))).toHaveLength(0);
  expect(app.synth().getStackArtifact(west.artifactId).messages.filter((m) => m.level === 'warning')).toHaveLength(0);
});

test('the alarm path itself: rules, targets, the topic, alarms, metric filters and GuardDuty changes alarm', () => {
  for (const [eventSource, eventNames] of Object.entries(ALARM_PATH_CHANGES)) {
    const r = rules(t).filter((x) => s(x.Properties.EventPattern.detail?.eventSource) === s([eventSource]));
    expect(r).toHaveLength(1);
    expect(r[0].Properties.EventPattern.detail.eventName).toEqual(eventNames);
  }
  for (const n of ['DisableRule', 'RemoveTargets', 'DeleteTopic', 'Unsubscribe', 'DeleteAlarms', 'DisableAlarmActions', 'DeleteDetector', 'CreateFilter']) {
    expect(s(ALARM_PATH_CHANGES)).toContain(`"${n}"`);
  }
  expect(ruleFor(t, 'aws.logs', 'DeleteMetricFilter')).toHaveLength(1);
});

test("the signer's own alarms, and more than 20 signs an hour", () => {
  const alarms = Object.values<any>(t.findResources('AWS::CloudWatch::Alarm'));
  for (const name of SIGNER_ALARMS) {
    expect(alarms.some((a) => a.Properties.AlarmName === `vettid-anchor-signer-staging-${name}` && a.Properties.Threshold === 1)).toBe(true);
  }
  for (const n of ['signs_per_hour', 'kms_signs_per_hour']) {
    const a = alarms.find((x) => x.Properties.AlarmName === `vettid-anchor-signer-staging-${n}`);
    expect(a.Properties.Threshold).toBe(SIGNS_PER_HOUR + 1);
    expect(a.Properties.Period).toBe(3600);
  }
  // KMS's own count, from the trail: one the signer's code can't leave out.
  const kms = Object.values<any>(t.findResources('AWS::Logs::MetricFilter')).find((f) => f.Properties.MetricTransformations[0].MetricName === 'kms_signs');
  expect(kms.Properties.FilterPattern).toBe('{ ($.eventSource = "kms.amazonaws.com") && ($.eventName = "Sign") }');
  expect(s(kms.Properties.LogGroupName)).toContain('TrailLogs');
  const filters = Object.values<any>(t.findResources('AWS::Logs::MetricFilter'));
  expect(filters.some((f) => f.Properties.FilterPattern.includes('$.kind') && f.Properties.FilterPattern.includes('sign'))).toBe(true);
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

test('the forwarding heartbeat: every 5 minutes, through the forwarding role, to the bus only', () => {
  const beat = allRules(t).filter((r) => r.Properties.ScheduleExpression);
  expect(beat).toHaveLength(1);
  expect(beat[0].Properties.ScheduleExpression).toBe(`rate(${FORWARD_HEARTBEAT_MINUTES} minutes)`);
  const tg = beat[0].Properties.Targets;
  expect(tg).toHaveLength(1);
  expect(s(tg[0].Arn)).toContain(`event-bus/${signerAuditNames('staging').bus}`);
  expect(s(tg[0].RoleArn)).toContain('AlarmForwardRole');
});

test("the trail's log group going quiet alarms (its delivery broken silences every trail filter)", () => {
  const a = Object.values<any>(t.findResources('AWS::CloudWatch::Alarm')).find((x) => x.Properties.AlarmName === 'vettid-anchor-signer-staging-trail_logs_quiet').Properties;
  expect(a.Namespace).toBe('AWS/Logs');
  expect(a.MetricName).toBe('IncomingLogEvents');
  expect(s(a.Dimensions)).toContain('TrailLogs');
  expect(a.ComparisonOperator).toBe('LessThanThreshold');
  expect(a.Threshold).toBe(1);
  expect(a.Period).toBe(300);
  expect(a.EvaluationPeriods).toBe(TRAIL_QUIET_MINUTES / 5);
  expect(a.TreatMissingData).toBe('breaching');
});

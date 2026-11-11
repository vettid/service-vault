import * as cdk from 'aws-cdk-lib';
import { Template } from 'aws-cdk-lib/assertions';
import { AUDIT_RETENTION_DAYS, AUDIT_STALE_HOURS, FORWARD_QUIET_MINUTES, SignerAuditStack, SignerAuditStackProps } from '../lib/signer-audit-stack';
import { signerAuditNames } from '../lib/anchor-signer-alarms';

const MGMT = '777788889999';
const SIGNER = '444455556666';
const base: SignerAuditStackProps = { envName: 'staging', signerAccount: SIGNER, alarmEmail: 'owner@example.org', env: { account: MGMT, region: 'us-east-1' } };
const t = Template.fromStack(new SignerAuditStack(new cdk.App(), 'SignerAudit-staging', base));
const s = (x: unknown) => JSON.stringify(x);
const names = signerAuditNames('staging');
const replicationRole = `arn:aws:iam::${SIGNER}:role/${names.replicationRole}`;

test('the locked copy: Object Lock in compliance mode for a year, versioned, bucket owner enforced, private, retained', () => {
  const buckets = t.findResources('AWS::S3::Bucket');
  expect(Object.keys(buckets)).toHaveLength(1);
  const b = Object.values<any>(buckets)[0];
  expect(b.Properties.BucketName).toBe(names.bucket(MGMT));
  expect(b.Properties.ObjectLockEnabled).toBe(true);
  expect(b.Properties.ObjectLockConfiguration).toEqual({
    ObjectLockEnabled: 'Enabled', Rule: { DefaultRetention: { Mode: 'COMPLIANCE', Days: AUDIT_RETENTION_DAYS } },
  });
  expect(AUDIT_RETENTION_DAYS).toBe(365);
  expect(b.Properties.VersioningConfiguration.Status).toBe('Enabled');
  expect(b.Properties.OwnershipControls.Rules[0].ObjectOwnership).toBe('BucketOwnerEnforced');
  expect(b.Properties.PublicAccessBlockConfiguration).toEqual({ BlockPublicAcls: true, BlockPublicPolicy: true, IgnorePublicAcls: true, RestrictPublicBuckets: true });
  expect(b.DeletionPolicy).toBe('Retain');
  expect(b.Properties.NotificationConfiguration).toEqual({ EventBridgeConfiguration: { EventBridgeEnabled: true } });
  // No custom-resource Lambda in the management account.
  expect(Object.keys(t.findResources('AWS::Lambda::Function'))).toHaveLength(0);
  expect(Object.keys(t.findResources('Custom::S3BucketNotifications'))).toHaveLength(0);
});

test("the bucket policy: the signer's replication role may only replicate in; nobody in the signer account deletes", () => {
  const stmts = Object.values<any>(t.findResources('AWS::S3::BucketPolicy'))[0].Properties.PolicyDocument.Statement;
  const allows = stmts.filter((st: any) => st.Effect === 'Allow');
  // By the account and aws:PrincipalArn (the role doesn't exist when this deploys).
  for (const a of allows) {
    expect(s(a.Principal)).toContain(`:iam::${SIGNER}:root`);
    expect(s(a.Condition)).toContain('aws:PrincipalArn');
    expect(s(a.Condition)).toContain(replicationRole.replace(/^arn:aws/, ''));
  }
  expect(allows.map((a: any) => a.Sid).sort()).toEqual(['SignerChecksVersioning', 'SignerReplicates']);
  const rep = allows.find((a: any) => a.Sid === 'SignerReplicates');
  expect(rep.Action).toBe('s3:ReplicateObject');
  const deny = stmts.find((st: any) => st.Sid === 'SignerNeverDeletes');
  expect(deny.Effect).toBe('Deny');
  expect(deny.Principal).toEqual({ AWS: '*' });
  expect(deny.Condition).toEqual({ StringEquals: { 'aws:PrincipalAccount': SIGNER } });
  for (const a of ['s3:ReplicateDelete', 's3:DeleteObjectVersion', 's3:PutObjectRetention', 's3:BypassGovernanceRetention', 's3:PutBucketObjectLockConfiguration']) {
    expect(deny.Action).toContain(a);
  }
  // TLS only (enforceSSL).
  expect(stmts.some((st: any) => st.Effect === 'Deny' && s(st.Condition).includes('aws:SecureTransport'))).toBe(true);
});

test(`the staleness watch: every arrival logged, none for ${AUDIT_STALE_HOURS} hours alarms (missing data breaches)`, () => {
  const rule = Object.values<any>(t.findResources('AWS::Events::Rule')).find((r) => r.Properties.EventPattern.source?.[0] === 'aws.s3').Properties;
  expect(rule.EventPattern['detail-type']).toEqual(['Object Created']);
  expect(s(rule.EventPattern.detail.bucket.name)).toContain('LockedCopy');
  // Only the trail's hourly digests feed it: the journal's copy or filler elsewhere can't keep it quiet.
  expect(rule.EventPattern.detail.object.key).toEqual([{ prefix: `trail/AWSLogs/${SIGNER}/CloudTrail-Digest/` }]);
  const alarm = Object.values<any>(t.findResources('AWS::CloudWatch::Alarm')).find((x) => x.Properties.AlarmName.endsWith('-stale')).Properties;
  expect(alarm.AlarmName).toBe('vettid-signer-audit-staging-stale');
  expect(alarm.ComparisonOperator).toBe('LessThanThreshold');
  expect(alarm.Threshold).toBe(1);
  expect(alarm.Period).toBe(3600);
  expect(alarm.EvaluationPeriods).toBe(AUDIT_STALE_HOURS);
  expect(alarm.TreatMissingData).toBe('breaching');
  expect(s(alarm.AlarmActions)).toContain('AlarmTopic');
  t.hasResourceProperties('AWS::SNS::Subscription', { Protocol: 'email', Endpoint: 'owner@example.org' });
});

test("the alarm bus: only the signer account's forwarding role puts on it; everything from that account reaches the owner", () => {
  const bus = Object.values<any>(t.findResources('AWS::Events::EventBus'));
  expect(bus).toHaveLength(1);
  expect(bus[0].Properties.Name).toBe(names.bus);
  const policies = Object.values<any>(t.findResources('AWS::Events::EventBusPolicy'));
  expect(policies).toHaveLength(1);
  const st = policies[0].Properties.Statement;
  expect(st.Action).toBe('events:PutEvents');
  expect(s(st.Principal)).toContain(`:iam::${SIGNER}:root`);
  expect(s(st.Condition)).toContain('aws:PrincipalArn');
  expect(s(st.Condition)).toContain(`:iam::${SIGNER}:role/${names.forwardRole}`);
  const onBus = Object.values<any>(t.findResources('AWS::Events::Rule')).filter((r) => r.Properties.EventBusName).map((r) => r.Properties);
  expect(onBus).toHaveLength(2);
  const alarms = onBus.find((r) => r.Description.includes('alarms'));
  expect(alarms.EventPattern).toEqual({ account: [SIGNER], 'detail-type': [{ 'anything-but': ['Scheduled Event'] }] });
  expect(s(alarms.Targets)).toContain('AlarmTopic');
  const beat = onBus.find((r) => r.Description.includes('heartbeat'));
  expect(beat.EventPattern).toEqual({ account: [SIGNER], source: ['aws.events'], 'detail-type': ['Scheduled Event'] });
  expect(s(beat.Targets)).toContain('Heartbeats');
  // No heartbeat for FORWARD_QUIET_MINUTES alarms, missing data breaching.
  const q = Object.values<any>(t.findResources('AWS::CloudWatch::Alarm')).find((x) => x.Properties.AlarmName === 'vettid-signer-audit-staging-forward_quiet').Properties;
  expect(q.ComparisonOperator).toBe('LessThanThreshold');
  expect(q.EvaluationPeriods).toBe(FORWARD_QUIET_MINUTES / 5);
  expect(q.Period).toBe(300);
  expect(q.TreatMissingData).toBe('breaching');
  expect(s(q.AlarmActions)).toContain('AlarmTopic');
});

test('the names match the signer side', () => {
  expect(names.bucket(MGMT)).toBe(`vettid-signer-audit-staging-${MGMT}`);
  expect(names.replicationRole).toBe('vettid-anchor-audit-replication-staging');
});

test('refuses: no account, the signer account as itself, a bad address', () => {
  expect(() => new SignerAuditStack(new cdk.App(), 'X', { ...base, env: undefined })).toThrow(/env.account/);
  expect(() => new SignerAuditStack(new cdk.App(), 'X', { ...base, signerAccount: MGMT })).toThrow(/signerAccount/);
  expect(() => new SignerAuditStack(new cdk.App(), 'X', { ...base, signerAccount: '1234' })).toThrow(/signerAccount/);
  expect(() => new SignerAuditStack(new cdk.App(), 'X', { ...base, alarmEmail: 'owner' })).toThrow(/alarmEmail/);
});

test("the topic's policy: this account's rules and alarms only; every alarm and the bus rule reach it", () => {
  const st = Object.values<any>(t.findResources('AWS::SNS::TopicPolicy'))[0].Properties.PolicyDocument.Statement;
  expect(st.map((x: any) => x.Sid).sort()).toEqual(['AlarmsOfThisAccount', 'RulesOfThisAccount']);
  const cw = st.find((x: any) => x.Sid === 'AlarmsOfThisAccount');
  expect(cw.Principal).toEqual({ Service: 'cloudwatch.amazonaws.com' });
  expect(cw.Condition.StringEquals).toEqual({ 'aws:SourceAccount': MGMT });
  expect(s(cw.Condition.ArnLike['aws:SourceArn'])).toContain(`:alarm:vettid-signer-audit-staging-*`);
  const ev = st.find((x: any) => x.Sid === 'RulesOfThisAccount');
  expect(ev.Condition).toEqual({ StringEquals: { 'aws:SourceAccount': MGMT } });
  for (const a of Object.values<any>(t.findResources('AWS::CloudWatch::Alarm'))) expect(s(a.Properties.AlarmActions)).toContain('AlarmTopic');
});

test('log groups as targets: their ARN without ":*"', () => {
  for (const r of Object.values<any>(t.findResources('AWS::Events::Rule'))) {
    for (const tg of r.Properties.Targets) {
      if (s(tg.Arn).includes(':logs:')) expect(s(tg.Arn)).not.toContain(':*');
    }
  }
});

test('pinned: the staleness hours, the Deny on bucket and objects, the log policies bound to their rules', () => {
  expect(AUDIT_STALE_HOURS).toBe(2);
  const st = Object.values<any>(t.findResources('AWS::S3::BucketPolicy'))[0].Properties.PolicyDocument.Statement;
  const deny = st.find((x: any) => x.Sid === 'SignerNeverDeletes');
  expect(deny.Resource).toHaveLength(2);
  expect(s(deny.Resource[0])).toContain('LockedCopy');
  expect(s(deny.Resource[1])).toContain('/*');
  const policies = Object.values<any>(t.findResources('AWS::Logs::ResourcePolicy'));
  expect(policies).toHaveLength(2);
  for (const p of policies) {
    const doc = JSON.parse(p.Properties.PolicyDocument['Fn::Join'] ? p.Properties.PolicyDocument['Fn::Join'][1].map((v: any) => typeof v === 'string' ? v : 'X').join('') : p.Properties.PolicyDocument);
    expect(doc.Statement[0].Principal).toEqual({ Service: 'events.amazonaws.com' });
    expect(Object.keys(doc.Statement[0].Condition.ArnEquals)).toEqual(['aws:SourceArn']);
  }
});

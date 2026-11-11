import * as cdk from 'aws-cdk-lib';
import { Template } from 'aws-cdk-lib/assertions';
import { AnchorSignerStack, AnchorSignerStackProps } from '../lib/anchor-signer-stack';
import { AUDIT_CHANGES, SIGNER_ALARMS, SIGNS_PER_HOUR, signerAuditNames } from '../lib/anchor-signer-alarms';

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
const rules = (tpl: Template) => Object.values<any>(tpl.findResources('AWS::Events::Rule'));
const ruleFor = (tpl: Template, source: string, name?: string) => rules(tpl).filter((r) => {
  const p = r.Properties.EventPattern;
  return p.source?.includes(source) && (!name || JSON.stringify(p.detail?.eventName ?? []).includes(name));
});
const s = (x: unknown) => JSON.stringify(x);

test('every rule reaches the account topic', () => {
  const topic = Object.keys(t.findResources('AWS::SNS::Topic'));
  expect(topic).toHaveLength(1);
  for (const r of rules(t)) {
    expect(s(r.Properties.Targets)).toContain(topic[0]);
  }
});

test('the trail: every region, global events, file validation, read and write, into trail/', () => {
  t.hasResourceProperties('AWS::CloudTrail::Trail', { IsMultiRegionTrail: true, IncludeGlobalServiceEvents: true,
    EnableLogFileValidation: true, IsLogging: true, S3KeyPrefix: 'trail' });
  const trail = Object.values<any>(t.findResources('AWS::CloudTrail::Trail'))[0].Properties;
  expect(s(trail.EventSelectors ?? [{ ReadWriteType: 'All' }])).toContain('All');
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
  expect(trust[0].Condition).toEqual({ StringEquals: { 'aws:SourceAccount': SIGNER_ACCT } });
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
  for (const n of ['PutBucketReplication', 'DeleteBucketReplication', 'PutBucketPolicy', 'PutBucketVersioning', 'DeleteDeliveryStream']) {
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
    'PutResourcePolicy', 'PutFunctionConcurrency', 'PublishLayerVersion']) {
    expect(ruleFor(t, 'aws.lambda', n)).toHaveLength(1);
  }
  expect(ruleFor(t, 'aws.signer', 'RevokeSignature')).toHaveLength(1);
  expect(ruleFor(t, 'aws.dynamodb', 'DeleteTable')).toHaveLength(1);
  expect(ruleFor(t, 'aws.logs', 'PutRetentionPolicy')).toHaveLength(1);
  // Lambda's events carry an API version: matched as prefixes.
  expect(s(ruleFor(t, 'aws.lambda')[0].Properties.EventPattern)).toContain('"prefix":"UpdateFunctionCode"');
});

test('us-east-1: the role, break-glass and root sign-in; elsewhere a warning instead', () => {
  expect(ruleFor(t, 'aws.iam', 'PutRolePolicy')).toHaveLength(1);
  expect(s(ruleFor(t, 'aws.sts', 'AssumeRole')[0].Properties.EventPattern)).toContain('break-glass');
  expect(rules(t).filter((r) => r.Properties.EventPattern.source?.[0] === 'aws.signin')).toHaveLength(1);
  const app = new cdk.App();
  const west = new AnchorSignerStack(app, 'AS', { ...base, env: { account: SIGNER_ACCT, region: 'us-west-2' } });
  const tw = Template.fromStack(west);
  expect(ruleFor(tw, 'aws.iam')).toHaveLength(0);
  const warnings = app.synth().getStackArtifact(west.artifactId).messages.filter((m) => m.level === 'warning');
  expect(warnings.some((w) => String(w.entry.data).includes('us-east-1'))).toBe(true);
});

test("the signer's own alarms, and more than 20 signs an hour", () => {
  const alarms = Object.values<any>(t.findResources('AWS::CloudWatch::Alarm'));
  for (const name of SIGNER_ALARMS) {
    expect(alarms.some((a) => a.Properties.AlarmName === `vettid-anchor-signer-staging-${name}` && a.Properties.Threshold === 1)).toBe(true);
  }
  const signs = alarms.find((a) => a.Properties.AlarmName === 'vettid-anchor-signer-staging-signs_per_hour');
  expect(signs.Properties.Threshold).toBe(SIGNS_PER_HOUR + 1);
  expect(signs.Properties.Period).toBe(3600);
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

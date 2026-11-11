import * as cdk from 'aws-cdk-lib';
import { Template } from 'aws-cdk-lib/assertions';
import { AUDIT_RETENTION_DAYS, AUDIT_STALE_HOURS, SignerAuditStack, SignerAuditStackProps } from '../lib/signer-audit-stack';
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
  for (const a of allows) {
    expect(s(a.Principal)).toContain(replicationRole.replace(/^arn:aws/, ''));
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
  const rule = Object.values<any>(t.findResources('AWS::Events::Rule'))[0].Properties;
  expect(rule.EventPattern.source).toEqual(['aws.s3']);
  expect(rule.EventPattern['detail-type']).toEqual(['Object Created']);
  expect(s(rule.EventPattern.detail.bucket.name)).toContain('LockedCopy');
  const alarm = Object.values<any>(t.findResources('AWS::CloudWatch::Alarm'))[0].Properties;
  expect(alarm.AlarmName).toBe('vettid-signer-audit-staging-stale');
  expect(alarm.ComparisonOperator).toBe('LessThanThreshold');
  expect(alarm.Threshold).toBe(1);
  expect(alarm.Period).toBe(3600);
  expect(alarm.EvaluationPeriods).toBe(AUDIT_STALE_HOURS);
  expect(alarm.TreatMissingData).toBe('breaching');
  expect(s(alarm.AlarmActions)).toContain('AlarmTopic');
  t.hasResourceProperties('AWS::SNS::Subscription', { Protocol: 'email', Endpoint: 'owner@example.org' });
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

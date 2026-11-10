import * as crypto from 'crypto';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import * as zlib from 'zlib';
import * as cdk from 'aws-cdk-lib';
import { Match, Template } from 'aws-cdk-lib/assertions';
import { AnchorSignerStack, AnchorSignerStackProps, bootstrapSha256InZip, SIGNER_CONCURRENCY, SIGNER_MEMORY_MIB, SIGNER_TIMEOUT_SECONDS } from '../lib/anchor-signer-stack';
import { ServiceVaultStack, ServiceVaultStackProps } from '../lib/service-vault-stack';

const SIGNER_ACCT = '444455556666';
const SERVICE_ACCT = '123456789012';
const TASK_ROLE = `arn:aws:iam::${SERVICE_ACCT}:role/ServiceVault-staging-TaskRole`;
const BREAK_GLASS = `arn:aws:iam::${SIGNER_ACCT}:role/owner/break-glass`;
const FN_ARN = `arn:aws:lambda:us-east-1:${SIGNER_ACCT}:function:vettid-anchor-signer-staging`;

// A zip with one entry, stored or deflated.
function makeZip(name: string, data: Buffer, deflate: boolean): Buffer {
  const body = deflate ? zlib.deflateRawSync(data) : data;
  const n = Buffer.from(name);
  const local = Buffer.alloc(30);
  local.writeUInt32LE(0x04034b50, 0); local.writeUInt16LE(deflate ? 8 : 0, 8);
  local.writeUInt32LE(body.length, 18); local.writeUInt32LE(data.length, 22); local.writeUInt16LE(n.length, 26);
  const central = Buffer.alloc(46);
  central.writeUInt32LE(0x02014b50, 0); central.writeUInt16LE(deflate ? 8 : 0, 10);
  central.writeUInt32LE(body.length, 20); central.writeUInt32LE(data.length, 24); central.writeUInt16LE(n.length, 28);
  central.writeUInt32LE(0, 42);
  const cdOff = 30 + n.length + body.length;
  const eocd = Buffer.alloc(22);
  eocd.writeUInt32LE(0x06054b50, 0); eocd.writeUInt16LE(1, 8); eocd.writeUInt16LE(1, 10);
  eocd.writeUInt32LE(46 + n.length, 12); eocd.writeUInt32LE(cdOff, 16);
  return Buffer.concat([local, n, body, central, n, eocd]);
}

const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'signer-release-'));
const binary = Buffer.from('the signer, built and signed');
const SHA = crypto.createHash('sha256').update(binary).digest('hex');
const zipPath = path.join(dir, 'signed.zip');
fs.writeFileSync(zipPath, makeZip('bootstrap', binary, true));

const base: AnchorSignerStackProps = {
  envName: 'staging', taskRoleArn: TASK_ROLE, breakGlassRoleArn: BREAK_GLASS, signingRoleArn: BREAK_GLASS,
  votesBucketName: 'votes-staging-site', alarmEmail: 'owner@example.org', signatureValidityDays: 365,
  env: { account: SIGNER_ACCT, region: 'us-east-1' },
};
const release = { zipPath, bootstrapSha256: SHA, objectKey: 'signed/anchor-signer-v1.zip', objectVersion: 'v1version' };
const synth = (props: Partial<AnchorSignerStackProps> = {}) =>
  Template.fromStack(new AnchorSignerStack(new cdk.App(), 'AnchorSigner-staging', { ...base, ...props }));
const asList = (x: any) => (Array.isArray(x) ? x : [x]);
const render = (x: any): string => {
  if (typeof x === 'string') return x;
  if (x?.Ref === 'AWS::Partition') return 'aws';
  if (x?.Ref === 'AWS::Region') return 'us-east-1';
  if (x?.Ref === 'AWS::AccountId') return SIGNER_ACCT;
  if (x?.['Fn::Join']) return x['Fn::Join'][1].map(render).join(x['Fn::Join'][0]);
  return JSON.stringify(x);
};
const t = synth({ release });
const keyPolicy = () => Object.values<any>(t.findResources('AWS::KMS::Key'))[0].Properties.KeyPolicy.Statement;
const roleStatements = (): any[] => Object.values<any>(t.findResources('AWS::IAM::Policy'))
  .filter((p) => JSON.stringify(p.Properties.Roles).includes('Role')).flatMap((p) => p.Properties.PolicyDocument.Statement);

test('the zip reader finds the bootstrap, stored or deflated', () => {
  expect(bootstrapSha256InZip(makeZip('bootstrap', binary, false))).toBe(SHA);
  expect(bootstrapSha256InZip(makeZip('bootstrap', binary, true))).toBe(SHA);
  expect(() => bootstrapSha256InZip(makeZip('other', binary, false))).toThrow(/no bootstrap/);
  expect(() => bootstrapSha256InZip(Buffer.from('not a zip at all, not at all'))).toThrow(/not a zip/);
});

test('the first deploy: everything but the function', () => {
  const first = synth();
  first.resourceCountIs('AWS::Lambda::Function', 0);
  first.resourceCountIs('AWS::KMS::Key', 1);
  first.hasResourceProperties('AWS::Lambda::CodeSigningConfig', { CodeSigningPolicies: { UntrustedArtifactOnDeployment: 'Enforce' } });
  first.hasResourceProperties('AWS::Signer::SigningProfile', { PlatformId: 'AWSLambda-SHA384-ECDSA', SignatureValidityPeriod: { Type: 'DAYS', Value: 365 } });
  first.hasResourceProperties('AWS::S3::Bucket', { VersioningConfiguration: { Status: 'Enabled' } });
  first.hasResourceProperties('AWS::SNS::Subscription', { Protocol: 'email', Endpoint: 'owner@example.org' });
});

test('the key: P-256 signing, retained, its alias; the policy exactly its four statements', () => {
  t.hasResource('AWS::KMS::Key', { Properties: { KeySpec: 'ECC_NIST_P256', KeyUsage: 'SIGN_VERIFY' }, DeletionPolicy: 'Retain' });
  t.hasResourceProperties('AWS::KMS::Alias', { AliasName: 'alias/vettid-anchor-staging' });
  const st = keyPolicy();
  expect(st.map((s: any) => s.Sid).sort()).toEqual(['Administer', 'DenyDisableAndDelete', 'SignerPublicKey', 'SignerSign']);
  expect(JSON.stringify(st)).not.toContain(SERVICE_ACCT); // no principal of another account
  const admins = asList(st.find((s: any) => s.Sid === 'Administer').Principal.AWS).map(render);
  expect(admins.sort()).toEqual([`arn:aws:iam::${SIGNER_ACCT}:root`, BREAK_GLASS,
    `arn:aws:iam::${SIGNER_ACCT}:role/cdk-hnb659fds-cfn-exec-role-${SIGNER_ACCT}-us-east-1`].sort());
  const all = st.flatMap((s: any) => asList(s.Action));
  expect(all).not.toContain('kms:CreateGrant');
  const sign = st.find((s: any) => s.Sid === 'SignerSign');
  expect(sign.Condition).toEqual({ StringEquals: { 'kms:SigningAlgorithm': 'ECDSA_SHA_256', 'kms:MessageType': 'DIGEST',
    'kms:RequestAlias': 'alias/vettid-anchor-staging' } });
  const deny = st.find((s: any) => s.Effect === 'Deny');
  expect(deny.Principal).toEqual({ AWS: '*' });
  expect(deny.Condition).toEqual({ ArnNotEquals: { 'aws:PrincipalArn': BREAK_GLASS } });
});

test('the role: Lambda for this function only; Sign denied from anywhere else; exactly its grants', () => {
  const role = Object.values<any>(t.findResources('AWS::IAM::Role'))[0];
  const trust = role.Properties.AssumeRolePolicyDocument.Statement;
  expect(trust).toHaveLength(1);
  expect(trust[0].Principal).toEqual({ Service: 'lambda.amazonaws.com' });
  expect(trust[0].Condition.StringEquals['aws:SourceAccount']).toBe(SIGNER_ACCT);
  expect(render(trust[0].Condition.ArnLike['aws:SourceArn'])).toBe(FN_ARN);
  expect(role.Properties.ManagedPolicyArns).toBeUndefined();
  const st = roleStatements();
  const denies = st.filter((s) => s.Effect === 'Deny');
  expect(denies).toHaveLength(1);
  expect(denies[0].Resource).toBe('*');
  expect(render(denies[0].Condition.StringNotEquals['lambda:SourceFunctionArn'])).toBe(FN_ARN);
  const actions = st.filter((s) => s.Effect === 'Allow').flatMap((s) => asList(s.Action)).sort();
  expect(actions).toEqual(['dynamodb:GetItem', 'dynamodb:PutItem', 'dynamodb:UpdateItem', 'kms:GetPublicKey', 'kms:Sign',
    'logs:CreateLogStream', 'logs:PutLogEvents', 'logs:PutLogEvents', 's3:GetObject', 's3:ListBucket'].sort());
  const res = (sid: string) => asList(st.find((s) => s.Sid === sid).Resource).map(render);
  expect(res('Journal')).toEqual([`arn:aws:logs:us-east-1:${SIGNER_ACCT}:log-group:/vettid/anchor/staging/journal:log-stream:signs`]);
  expect(res('SiteRead')).toEqual(['arn:aws:s3:::votes-staging-site/v1/*']);
  expect(st.find((s) => s.Sid === 'SiteList').Condition).toEqual({ StringLike: { 's3:prefix': ['v1/*'] } });
});

test('the function: only the signed zip, under the code-signing config, no environment, only the task invokes', () => {
  const fns = Object.values<any>(t.findResources('AWS::Lambda::Function'));
  expect(fns).toHaveLength(1);
  const f = fns[0].Properties;
  expect(f.FunctionName).toBe('vettid-anchor-signer-staging');
  expect(f.Code.S3Key).toBe('signed/anchor-signer-v1.zip');
  expect(f.Code.S3ObjectVersion).toBe('v1version');
  expect(f.CodeSigningConfigArn).toBeDefined();
  expect(f.Environment).toBeUndefined();
  expect(f.KmsKeyArn).toBeUndefined();
  expect(f.VpcConfig).toBeUndefined();
  expect([f.MemorySize, f.Timeout, f.ReservedConcurrentExecutions]).toEqual([SIGNER_MEMORY_MIB, SIGNER_TIMEOUT_SECONDS, SIGNER_CONCURRENCY]);
  const perms = Object.values<any>(t.findResources('AWS::Lambda::Permission'));
  expect(perms).toHaveLength(1);
  expect(perms[0].Properties.Principal).toBe(TASK_ROLE);
  expect(perms[0].Properties.Action).toBe('lambda:InvokeFunction');
  t.hasResourceProperties('AWS::Signer::ProfilePermission', { Principal: BREAK_GLASS, Action: 'signer:StartSigningJob' });
});

test('refused: another binary, no object version, the task in this account, bad inputs', () => {
  expect(() => synth({ release: { ...release, bootstrapSha256: 'b'.repeat(64) } })).toThrow(/not the pinned/);
  expect(() => synth({ release: { ...release, objectVersion: '' } })).toThrow(/objectVersion/);
  expect(() => synth({ taskRoleArn: `arn:aws:iam::${SIGNER_ACCT}:role/x` })).toThrow(/service account/);
  expect(() => synth({ breakGlassRoleArn: 'nope' })).toThrow(/role ARN/);
  expect(() => synth({ signatureValidityDays: 0 })).toThrow(/signatureValidityDays/);
});

describe('the service vault side', () => {
  const sv: ServiceVaultStackProps = {
    envName: 'test', image: `ghcr.io/vettid/service-vault@sha256:${'a'.repeat(64)}`,
    webhookUrl: 'https://member.example.org/webhooks/service-vault', apiClientSecurityGroupId: 'sg-0123456789abcdef0',
    alarmTopicArn: `arn:aws:sns:us-east-1:${SERVICE_ACCT}:alerts`, env: { account: SERVICE_ACCT, region: 'us-east-1' },
  };
  test('the task may invoke the signer, and nothing of it is made here', () => {
    const s = Template.fromStack(new ServiceVaultStack(new cdk.App(), 'SV', { ...sv, anchorSignerFunctionArn: FN_ARN }));
    const st = Object.values<any>(s.findResources('AWS::IAM::Policy')).flatMap((p) => p.Properties.PolicyDocument.Statement);
    const inv = st.filter((x) => asList(x.Action).includes('lambda:InvokeFunction'));
    expect(inv).toHaveLength(1);
    expect(inv[0].Resource).toBe(FN_ARN);
    expect(Object.values<any>(s.findResources('AWS::KMS::Key')).every((k) => k.Properties.KeySpec !== 'ECC_NIST_P256')).toBe(true);
    expect(JSON.stringify(s.toJSON())).not.toContain('anchor-claims');
  });
  test('refused: a signer in this account, or not a function ARN', () => {
    expect(() => new ServiceVaultStack(new cdk.App(), 'SV', { ...sv, anchorSignerFunctionArn: FN_ARN.replace(SIGNER_ACCT, SERVICE_ACCT) })).toThrow(/signer account/);
    expect(() => new ServiceVaultStack(new cdk.App(), 'SV', { ...sv, anchorSignerFunctionArn: 'nope' })).toThrow(/ARN/);
  });
  test('without it, nothing changes', () => {
    const s = Template.fromStack(new ServiceVaultStack(new cdk.App(), 'SV', sv));
    expect(JSON.stringify(s.toJSON())).not.toContain('lambda:InvokeFunction');
  });
});

import * as crypto from 'crypto';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import * as cdk from 'aws-cdk-lib';
import { Match, Template } from 'aws-cdk-lib/assertions';
import { ServiceVaultStack, ServiceVaultStackProps } from '../lib/service-vault-stack';
import { SIGNER_CONCURRENCY, SIGNER_TIMEOUT_SECONDS } from '../lib/anchor-signer';

const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'signer-'));
fs.writeFileSync(path.join(dir, 'bootstrap'), 'not a real binary');
const sha = crypto.createHash('sha256').update('not a real binary').digest('hex');
const SITE_KEY = Buffer.alloc(32, 7).toString('base64');
const BREAK_GLASS = 'arn:aws:iam::123456789012:role/owner-break-glass';
const base: ServiceVaultStackProps = {
  envName: 'test',
  image: `ghcr.io/vettid/service-vault@sha256:${'a'.repeat(64)}`,
  webhookUrl: 'https://member.example.org/webhooks/service-vault',
  apiClientSecurityGroupId: 'sg-0123456789abcdef0',
  alarmTopicArn: 'arn:aws:sns:us-east-1:123456789012:alerts',
  env: { account: '123456789012', region: 'us-east-1' },
};
const signer = {
  codeDir: dir, bootstrapSha256: sha, votesBucketName: 'votes-staging-site', votesApiUrl: 'https://votes.example.org',
  votesSiteKey: SITE_KEY, sigstore: 'staging' as 'staging' | 'production', breakGlassRoleArn: BREAK_GLASS as string | undefined,
};
const synth = (extra: Partial<typeof signer> = {}) => Template.fromStack(
  new ServiceVaultStack(new cdk.App(), 'SV', { ...base, anchorSigner: { ...signer, ...extra } }));
const t = synth();
const keyPolicy = (): any[] => {
  const keys = Object.values<any>(t.findResources('AWS::KMS::Key')).filter((k) => k.Properties.KeySpec === 'ECC_NIST_P256');
  expect(keys).toHaveLength(1);
  return keys[0].Properties.KeyPolicy.Statement;
};
const signerStatements = (): any[] => Object.values<any>(t.findResources('AWS::IAM::Policy'))
  .filter((p) => JSON.stringify(p.Properties.Roles).includes('AnchorSignerRole'))
  .flatMap((p) => p.Properties.PolicyDocument.Statement);
const asList = (x: any) => (Array.isArray(x) ? x : [x]);

test('nothing of it without the prop', () => {
  const plain = Template.fromStack(new ServiceVaultStack(new cdk.App(), 'SV', base));
  expect(JSON.stringify(plain.toJSON())).not.toContain('anchor-signer');
  expect(Object.values<any>(plain.findResources('AWS::KMS::Key')).every((k) => k.Properties.KeySpec !== 'ECC_NIST_P256')).toBe(true);
});

test('the key: P-256 for signing, retained', () => {
  t.hasResource('AWS::KMS::Key', {
    Properties: { KeySpec: 'ECC_NIST_P256', KeyUsage: 'SIGN_VERIFY' },
    DeletionPolicy: 'Retain', UpdateReplacePolicy: 'Retain',
  });
});

test('the key policy: no grants, Sign only for the signer and only digests, no disabling but break-glass', () => {
  const st = keyPolicy();
  const all = st.flatMap((s) => asList(s.Action));
  expect(all).not.toContain('kms:CreateGrant');
  expect(all).not.toContain('kms:*');
  const signs = st.filter((s) => s.Effect === 'Allow' && asList(s.Action).some((a: string) => a === 'kms:Sign' || a === 'kms:Sign*'));
  expect(signs).toHaveLength(1);
  expect(signs[0].Condition).toEqual({ StringEquals: { 'kms:SigningAlgorithm': 'ECDSA_SHA_256', 'kms:MessageType': 'DIGEST' } });
  expect(JSON.stringify(signs[0].Principal)).toContain('AnchorSignerRole');
  const admin = st.find((s) => s.Sid === 'Administer');
  expect(asList(admin.Action).some((a: string) => /^kms:(Sign|Encrypt|Decrypt|Create\*|Generate)/.test(a))).toBe(false);
  const deny = st.find((s) => s.Effect === 'Deny');
  expect(asList(deny.Action).sort()).toEqual(['kms:DisableKey', 'kms:ScheduleKeyDeletion']);
  expect(deny.Principal).toEqual({ AWS: '*' });
  expect(deny.Condition).toEqual({ ArnNotEquals: { 'aws:PrincipalArn': BREAK_GLASS } });
});

test('without a break-glass role, nobody disables or deletes it', () => {
  const st = Object.values<any>(synth({ breakGlassRoleArn: undefined }).findResources('AWS::KMS::Key'))
    .find((k) => k.Properties.KeySpec === 'ECC_NIST_P256').Properties.KeyPolicy.Statement;
  expect(st.find((s: any) => s.Effect === 'Deny').Condition).toBeUndefined();
});

test('the role: Lambda for this function only, and Sign denied from anywhere else', () => {
  const role = Object.values<any>(t.findResources('AWS::IAM::Role')).find((r) => JSON.stringify(r).includes('anchor-signer'));
  const trust = role.Properties.AssumeRolePolicyDocument.Statement[0];
  expect(trust.Principal).toEqual({ Service: 'lambda.amazonaws.com' });
  expect(trust.Condition.StringEquals['aws:SourceAccount']).toBe('123456789012');
  expect(JSON.stringify(trust.Condition.ArnLike['aws:SourceArn'])).toContain('function:vettid-service-vault-test-anchor-signer');
  const deny = signerStatements().find((s) => s.Sid === 'SignOnlyFromTheFunction');
  expect(deny.Effect).toBe('Deny');
  expect(deny.Action).toBe('kms:Sign');
  expect(JSON.stringify(deny.Condition.StringNotEquals['lambda:SourceFunctionArn'])).toContain('function:vettid-service-vault-test-anchor-signer');
  const actions = signerStatements().filter((s) => s.Effect === 'Allow').flatMap((s) => asList(s.Action));
  expect(actions.sort()).toEqual(['dynamodb:GetItem', 'dynamodb:PutItem', 'dynamodb:UpdateItem', 'kms:GetPublicKey', 'kms:Sign',
    'logs:CreateLogStream', 'logs:PutLogEvents', 'logs:PutLogEvents', 's3:GetObject'].sort());
  expect(actions).not.toContain('dynamodb:DeleteItem');
});

test('the function: 120 s, two at once, arm64 custom runtime, its environment', () => {
  t.hasResourceProperties('AWS::Lambda::Function', {
    FunctionName: 'vettid-service-vault-test-anchor-signer', Runtime: 'provided.al2023', Architectures: ['arm64'],
    Timeout: SIGNER_TIMEOUT_SECONDS, ReservedConcurrentExecutions: SIGNER_CONCURRENCY,
    Environment: { Variables: Match.objectLike({ VOTES_API: 'https://votes.example.org', VOTES_SIGSTORE: 'staging',
      VOTES_BUCKET: 'votes-staging-site', VOTES_SITE_KEY: SITE_KEY, SIGNER_JOURNAL_STREAM: 'signs' }) },
  });
});

test('the claims and the journal: retained, the journal a year', () => {
  t.hasResource('AWS::DynamoDB::Table', {
    Properties: Match.objectLike({ TableName: 'vettid-service-vault-test-anchor-claims', DeletionProtectionEnabled: true }),
    DeletionPolicy: 'Retain',
  });
  t.hasResource('AWS::Logs::LogGroup', {
    Properties: { LogGroupName: '/vettid/service-vault/test/anchor-journal', RetentionInDays: 365 }, DeletionPolicy: 'Retain',
  });
});

test('the task invokes it and reads the public key and claims, and never signs', () => {
  const td = Object.values<any>(t.findResources('AWS::ECS::TaskDefinition'))[0].Properties;
  const roleId = td.TaskRoleArn['Fn::GetAtt'][0];
  const st = Object.values<any>(t.findResources('AWS::IAM::Policy'))
    .filter((p) => p.Properties.Roles.some((r: any) => r.Ref === roleId)).flatMap((p) => p.Properties.PolicyDocument.Statement);
  const actions = st.flatMap((s) => asList(s.Action));
  expect(actions).toContain('lambda:InvokeFunction');
  expect(actions).toContain('kms:GetPublicKey');
  expect(actions).not.toContain('kms:Sign');
});

test('refused: another binary, a bad URL, production off prod', () => {
  expect(() => synth({ bootstrapSha256: 'b'.repeat(64) })).toThrow(/not the pinned/);
  expect(() => synth({ votesApiUrl: 'http://votes.example.org' })).toThrow(/https/);
  expect(() => synth({ sigstore: 'production' })).toThrow(/prod/);
  expect(() => synth({ votesSiteKey: 'AAAA' })).toThrow(/Ed25519/);
});

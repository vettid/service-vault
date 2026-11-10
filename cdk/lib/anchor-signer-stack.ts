import * as crypto from 'crypto';
import * as fs from 'fs';
import * as zlib from 'zlib';
import * as cdk from 'aws-cdk-lib';
import * as dynamodb from 'aws-cdk-lib/aws-dynamodb';
import * as iam from 'aws-cdk-lib/aws-iam';
import * as kms from 'aws-cdk-lib/aws-kms';
import * as lambda from 'aws-cdk-lib/aws-lambda';
import * as logs from 'aws-cdk-lib/aws-logs';
import * as s3 from 'aws-cdk-lib/aws-s3';
import * as signer from 'aws-cdk-lib/aws-signer';
import * as sns from 'aws-cdk-lib/aws-sns';
import * as subs from 'aws-cdk-lib/aws-sns-subscriptions';
import { Construct } from 'constructs';
import { KEY_ADMIN_ACTIONS } from './kms-actions';

/** The function's own limits (GC #7406 §1): 120 s, at most two at once, 1,024 MB for results of 15,000 members. */
export const SIGNER_TIMEOUT_SECONDS = 120;
export const SIGNER_CONCURRENCY = 2;
export const SIGNER_MEMORY_MIB = 1024;

/** The claim table's calls (GC #7406 §2): conditional writes, no delete. */
export const CLAIM_ACTIONS = ['GetItem', 'PutItem', 'UpdateItem'] as const;

/**
 * The fixed names the signer's build compiles in (deploy/signer-<env>.conf
 * in votes; GC #7638 item 5), so that one build pass is enough.
 */
export const signerNames = (envName: string) => ({
  functionName: `vettid-anchor-signer-${envName}`,
  roleName: `vettid-anchor-signer-${envName}`,
  keyAlias: `alias/vettid-anchor-${envName}`,
  claimsTable: `vettid-anchor-claims-${envName}`,
  journalGroup: `/vettid/anchor/${envName}/journal`,
  journalStream: 'signs',
  artifactsBucket: (account: string) => `vettid-anchor-signer-${envName}-${account}`,
});

const ROLE_ARN = /^arn:aws[a-z-]*:iam::[0-9]{12}:role\/[A-Za-z0-9+=,.@_\/-]+$/;

/** A signed release of the signer: the owner's signing job's output zip. */
export interface SignerRelease {
  /** The signed zip, downloaded by the owner: synth checks the bootstrap inside it. */
  readonly zipPath: string;
  /** The SHA-256 (hex) of the bootstrap that CI built and the owner rebuilt. */
  readonly bootstrapSha256: string;
  /** The signing job's output object in the artifacts bucket, and its version. */
  readonly objectKey: string;
  readonly objectVersion: string;
}

export interface AnchorSignerStackProps extends cdk.StackProps {
  readonly envName: string;
  /** The service vault task role's exact ARN, in the service account: the only principal that may invoke. */
  readonly taskRoleArn: string;
  /** The owner's break-glass role in this account (the full ARN, path included). */
  readonly breakGlassRoleArn: string;
  /** The owner's role that may run signing jobs under the profile (often the break-glass role). */
  readonly signingRoleArn: string;
  /** The votes site's bucket (in another account), read only. */
  readonly votesBucketName: string;
  /** Where this account's alarms go: the owner. */
  readonly alarmEmail: string;
  /** How long a signature stays valid for deploys (checked at deploy only; rollback is possible only within it). */
  readonly signatureValidityDays: number;
  /** The signed release to run; left out (the first deploy), no function is made. */
  readonly release?: SignerRelease;
  /** CDK's bootstrap qualifier in this account (default hnb659fds): its CloudFormation execution role administers the key. */
  readonly bootstrapQualifier?: string;
}

/**
 * The bootstrap's SHA-256 inside a zip (stored or deflated): the minimal
 * reader synth needs, with no dependency. The zip must hold exactly one
 * `bootstrap`. Synth pins the owner's local copy of the signed zip; the
 * runbook compares that copy's SHA-256 with the deployed object version,
 * and `CodeSha256` after the deploy.
 */
export function bootstrapSha256InZip(zip: Buffer): string {
  let eocd = -1;
  for (let i = zip.length - 22; i >= Math.max(0, zip.length - 22 - 65535); i--) {
    if (zip.readUInt32LE(i) === 0x06054b50) { eocd = i; break; }
  }
  if (eocd < 0) throw new Error('anchorSigner: the release is not a zip');
  const count = zip.readUInt16LE(eocd + 10);
  let p = zip.readUInt32LE(eocd + 16);
  let found: string | undefined;
  for (let n = 0; n < count; n++) {
    if (zip.readUInt32LE(p) !== 0x02014b50) throw new Error('anchorSigner: the release zip is malformed');
    const method = zip.readUInt16LE(p + 10);
    const csize = zip.readUInt32LE(p + 20);
    const nameLen = zip.readUInt16LE(p + 28);
    const extraLen = zip.readUInt16LE(p + 30);
    const commentLen = zip.readUInt16LE(p + 32);
    const local = zip.readUInt32LE(p + 42);
    const name = zip.subarray(p + 46, p + 46 + nameLen).toString('utf8');
    if (name === 'bootstrap') {
      const lnameLen = zip.readUInt16LE(local + 26);
      const lextraLen = zip.readUInt16LE(local + 28);
      const data = zip.subarray(local + 30 + lnameLen + lextraLen, local + 30 + lnameLen + lextraLen + csize);
      const raw = method === 0 ? data : method === 8 ? zlib.inflateRawSync(data) : null;
      if (!raw) throw new Error(`anchorSigner: the release's bootstrap uses compression method ${method}`);
      if (found !== undefined) throw new Error('anchorSigner: the release zip has more than one bootstrap');
      found = crypto.createHash('sha256').update(raw).digest('hex');
    }
    p += 46 + nameLen + extraLen + commentLen;
  }
  if (found === undefined) throw new Error('anchorSigner: the release zip has no bootstrap');
  return found;
}

/**
 * Deployed from the owner's session only; its app entry point and the
 * service stack's `anchorSignerFunctionArn` context are wired by the
 * runbook card (P1.6, #7421), not here, so that nothing in bin/ deploys it.
 *
 * AnchorSigner-<env>: the signer's own account (key protection, phase 1;
 * GC #7406 as amended for the owner's a on #7597 and #7633: #7606, #7611,
 * #7638, #7648), administered by the owner alone and deployed from the
 * owner's session. The anchor key, the function that alone signs with it
 * (only code the owner signed), its claim table and journal, the signing
 * profile and its artifacts bucket, and the account's alarm topic. The
 * service vault's task invokes it across accounts; nothing else of the
 * service account is granted anything here.
 */
export class AnchorSignerStack extends cdk.Stack {
  readonly key: kms.Key;
  readonly role: iam.Role;
  readonly claims: dynamodb.Table;
  readonly journal: logs.LogGroup;
  readonly profile: signer.SigningProfile;
  readonly codeSigning: lambda.CodeSigningConfig;
  readonly artifacts: s3.Bucket;
  readonly topic: sns.Topic;
  readonly fn?: lambda.Function;

  constructor(scope: Construct, id: string, props: AnchorSignerStackProps) {
    super(scope, id, props);
    const envName = props.envName;
    if (!/^[a-z][a-z0-9-]{0,15}$/.test(envName)) {
      throw new Error(`envName must be lowercase letters, digits and hyphens (got "${envName}")`);
    }
    for (const [name, arn] of Object.entries({ taskRoleArn: props.taskRoleArn, breakGlassRoleArn: props.breakGlassRoleArn, signingRoleArn: props.signingRoleArn })) {
      if (!ROLE_ARN.test(arn)) throw new Error(`${name} must be an IAM role ARN (got "${arn}")`);
    }
    if (!/^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$/.test(props.votesBucketName)) {
      throw new Error(`votesBucketName must be a bucket name (got "${props.votesBucketName}")`);
    }
    if (!/^[^@\s]+@[a-z0-9.-]+\.[a-z]+$/.test(props.alarmEmail)) {
      throw new Error(`alarmEmail must be an address (got "${props.alarmEmail}")`);
    }
    if (!Number.isInteger(props.signatureValidityDays) || props.signatureValidityDays < 1 || props.signatureValidityDays > 3650) {
      throw new Error('signatureValidityDays must be an integer from 1 to 3650');
    }
    if (cdk.Token.isUnresolved(this.account) || cdk.Token.isUnresolved(this.region)) {
      throw new Error('AnchorSigner needs env.account and env.region: the signer account is a fixed, standalone account');
    }
    const taskAccount = props.taskRoleArn.split(':')[4];
    if (taskAccount === this.account) {
      throw new Error('the task role must be in the service account, not in the signer account');
    }
    const names = signerNames(envName);
    const fnArn = this.formatArn({ service: 'lambda', resource: 'function', resourceName: names.functionName, arnFormat: cdk.ArnFormat.COLON_RESOURCE_NAME });
    const aliasArn = this.formatArn({ service: 'kms', resource: 'alias', resourceName: names.keyAlias.replace(/^alias\//, '') });
    const qualifier = props.bootstrapQualifier ?? 'hnb659fds';
    const cfnExec = `arn:${this.partition}:iam::${this.account}:role/cdk-${qualifier}-cfn-exec-role-${this.account}-${this.region}`;

    // The account's alarm topic, to the owner.
    this.topic = new sns.Topic(this, 'AlarmTopic', { displayName: `VettID anchor signer alarms (${envName})` });
    this.topic.addSubscription(new subs.EmailSubscription(props.alarmEmail));

    // The role: assumed by Lambda for this function only (verified at the
    // first staging deploy; aws:SourceAccount alone is the fallback).
    this.role = new iam.Role(this, 'Role', {
      roleName: names.roleName,
      description: 'VettID anchor signer: the AnchorSigner function (key protection, GC #7406)',
      assumedBy: new iam.ServicePrincipal('lambda.amazonaws.com', {
        conditions: { StringEquals: { 'aws:SourceAccount': this.account }, ArnLike: { 'aws:SourceArn': fnArn } },
      }),
    });

    // The anchor key: this account (and its CloudFormation execution role)
    // administers it, with no CreateGrant and no Sign; only the signer role
    // signs, only SHA-256 digests and only by the alias; nobody but
    // break-glass disables it or schedules its deletion. No principal of
    // another account is in it.
    this.key = new kms.Key(this, 'AnchorKey', {
      description: 'VettID anchor key (ECDSA P-256), used only by the AnchorSigner',
      keySpec: kms.KeySpec.ECC_NIST_P256,
      keyUsage: kms.KeyUsage.SIGN_VERIFY,
      removalPolicy: cdk.RemovalPolicy.RETAIN,
      policy: new iam.PolicyDocument({
        statements: [
          new iam.PolicyStatement({
            sid: 'Administer',
            principals: [new iam.AccountRootPrincipal(), new iam.ArnPrincipal(cfnExec), new iam.ArnPrincipal(props.breakGlassRoleArn)],
            actions: KEY_ADMIN_ACTIONS,
            resources: ['*'],
          }),
          new iam.PolicyStatement({
            sid: 'SignerSign',
            principals: [new iam.ArnPrincipal(this.role.roleArn)],
            actions: ['kms:Sign'],
            resources: ['*'],
            conditions: {
              StringEquals: { 'kms:SigningAlgorithm': 'ECDSA_SHA_256', 'kms:MessageType': 'DIGEST', 'kms:RequestAlias': names.keyAlias },
            },
          }),
          new iam.PolicyStatement({
            sid: 'SignerPublicKey', principals: [new iam.ArnPrincipal(this.role.roleArn)], actions: ['kms:GetPublicKey'], resources: ['*'],
          }),
          new iam.PolicyStatement({
            sid: 'DenyDisableAndDelete',
            effect: iam.Effect.DENY,
            principals: [new iam.AnyPrincipal()],
            actions: ['kms:ScheduleKeyDeletion', 'kms:DisableKey'],
            resources: ['*'],
            conditions: { ArnNotEquals: { 'aws:PrincipalArn': props.breakGlassRoleArn } },
          }),
        ],
      }),
    });
    new kms.Alias(this, 'AnchorKeyAlias', { aliasName: names.keyAlias, targetKey: this.key, removalPolicy: cdk.RemovalPolicy.RETAIN });

    // The binding of record (GC #7406 §4), on every key.
    this.role.addToPrincipalPolicy(new iam.PolicyStatement({
      sid: 'SignOnlyFromTheFunction', effect: iam.Effect.DENY, actions: ['kms:Sign'], resources: ['*'],
      conditions: { StringNotEquals: { 'lambda:SourceFunctionArn': fnArn } },
    }));
    this.role.addToPrincipalPolicy(new iam.PolicyStatement({
      sid: 'Sign', actions: ['kms:Sign', 'kms:GetPublicKey'], resources: [this.key.keyArn],
    }));

    // The claim table (GC #7406 §2): only the signer writes it.
    this.claims = new dynamodb.Table(this, 'Claims', {
      tableName: names.claimsTable,
      partitionKey: { name: 'slot', type: dynamodb.AttributeType.STRING },
      billingMode: dynamodb.BillingMode.PAY_PER_REQUEST,
      pointInTimeRecoverySpecification: { pointInTimeRecoveryEnabled: true },
      deletionProtection: true,
      removalPolicy: cdk.RemovalPolicy.RETAIN,
    });
    this.role.addToPrincipalPolicy(new iam.PolicyStatement({
      sid: 'Claims', actions: CLAIM_ACTIONS.map((a) => `dynamodb:${a}`), resources: [this.claims.tableArn],
    }));

    // The journal (GC #7406 §3): its own group and stream, a year.
    this.journal = new logs.LogGroup(this, 'Journal', {
      logGroupName: names.journalGroup, retention: logs.RetentionDays.ONE_YEAR, removalPolicy: cdk.RemovalPolicy.RETAIN,
    });
    const stream = new logs.LogStream(this, 'JournalStream', {
      logGroup: this.journal, logStreamName: names.journalStream, removalPolicy: cdk.RemovalPolicy.RETAIN,
    });
    this.role.addToPrincipalPolicy(new iam.PolicyStatement({
      sid: 'Journal',
      actions: ['logs:PutLogEvents'],
      resources: [this.formatArn({
        service: 'logs', resource: 'log-group', arnFormat: cdk.ArnFormat.COLON_RESOURCE_NAME,
        resourceName: `${names.journalGroup}:log-stream:${names.journalStream}`,
      })],
    }));

    // The votes site's bucket, read only, across accounts (its own policy
    // grants this role the same, in the votes stack). ListBucket on v1/ so
    // a missing object is a 404, not a 403.
    this.role.addToPrincipalPolicy(new iam.PolicyStatement({
      sid: 'SiteRead', actions: ['s3:GetObject'],
      resources: [`arn:${this.partition}:s3:::${props.votesBucketName}/v1/*`],
    }));
    this.role.addToPrincipalPolicy(new iam.PolicyStatement({
      sid: 'SiteList', actions: ['s3:ListBucket'], resources: [`arn:${this.partition}:s3:::${props.votesBucketName}`],
      conditions: { StringLike: { 's3:prefix': ['v1/*'] } },
    }));

    // Code signing: a profile, and a configuration that refuses anything
    // not signed under it on deploy. The profile is retained: changing its
    // validity replaces it, and every release must then be signed again
    // under the new one. The permission below grants the owner's signing
    // role StartSigningJob; it restricts nothing by itself (this account's
    // only administrator is the owner). Verified on staging that Signer
    // accepts a same-account role.
    this.profile = new signer.SigningProfile(this, 'Profile', {
      platform: signer.Platform.AWS_LAMBDA_SHA384_ECDSA,
      signatureValidity: cdk.Duration.days(props.signatureValidityDays),
    });
    this.profile.applyRemovalPolicy(cdk.RemovalPolicy.RETAIN);
    new signer.CfnProfilePermission(this, 'ProfileSignOwner', {
      profileName: this.profile.signingProfileName, action: 'signer:StartSigningJob',
      principal: props.signingRoleArn, statementId: 'OwnerSigns',
    });
    this.codeSigning = new lambda.CodeSigningConfig(this, 'CodeSigning', {
      signingProfiles: [this.profile],
      untrustedArtifactOnDeployment: lambda.UntrustedArtifactOnDeployment.ENFORCE,
      description: 'VettID anchor signer: only code the owner signed',
    });

    // The artifacts bucket: the signing jobs' input and output zips,
    // versioned, private, retained.
    this.artifacts = new s3.Bucket(this, 'Artifacts', {
      bucketName: names.artifactsBucket(this.account),
      versioned: true,
      blockPublicAccess: s3.BlockPublicAccess.BLOCK_ALL,
      encryption: s3.BucketEncryption.S3_MANAGED,
      enforceSSL: true,
      removalPolicy: cdk.RemovalPolicy.RETAIN,
    });

    // The function's own log, for its operational lines (never the journal).
    const fnLogs = new logs.LogGroup(this, 'Logs', {
      logGroupName: `/aws/lambda/${names.functionName}`, retention: logs.RetentionDays.ONE_MONTH, removalPolicy: cdk.RemovalPolicy.RETAIN,
    });
    this.role.addToPrincipalPolicy(new iam.PolicyStatement({
      sid: 'OwnLogs', actions: ['logs:CreateLogStream', 'logs:PutLogEvents'], resources: [fnLogs.logGroupArn],
    }));

    if (props.release) {
      const r = props.release;
      if (!/^[0-9a-f]{64}$/.test(r.bootstrapSha256)) throw new Error('release.bootstrapSha256 must be 64 lowercase hex digits');
      if (!r.objectVersion || r.objectVersion === 'null') throw new Error('release.objectVersion is required: the signed object\'s version in the versioned bucket');
      if (!/^[A-Za-z0-9!_.*'()\/-]+\.zip$/.test(r.objectKey)) throw new Error(`release.objectKey must be the signed zip's key (got "${r.objectKey}")`);
      const got = bootstrapSha256InZip(fs.readFileSync(r.zipPath));
      if (got !== r.bootstrapSha256) {
        throw new Error(`anchorSigner: the bootstrap in ${r.zipPath} has SHA-256 ${got}, not the pinned ${r.bootstrapSha256}`);
      }
      this.fn = new lambda.Function(this, 'Function', {
        functionName: names.functionName,
        description: 'VettID anchor signer: anchors and publishes vote documents (key protection, GC #7406)',
        runtime: lambda.Runtime.PROVIDED_AL2023,
        architecture: lambda.Architecture.ARM_64,
        handler: 'bootstrap',
        code: lambda.Code.fromBucket(this.artifacts, r.objectKey, r.objectVersion),
        codeSigningConfig: this.codeSigning,
        role: this.role,
        timeout: cdk.Duration.seconds(SIGNER_TIMEOUT_SECONDS),
        memorySize: SIGNER_MEMORY_MIB,
        reservedConcurrentExecutions: SIGNER_CONCURRENCY,
        logGroup: fnLogs,
        // No environment: the configuration is compiled in.
      });
      this.fn.node.addDependency(stream);
      // Only the service vault's task, by its exact ARN (fails closed if
      // that role is recreated: redeploy with the new ARN).
      this.fn.addPermission('ServiceTaskInvokes', {
        principal: new iam.ArnPrincipal(props.taskRoleArn),
        action: 'lambda:InvokeFunction',
      });
      new cdk.CfnOutput(this, 'FunctionArn', { value: this.fn.functionArn });
    }
    new cdk.CfnOutput(this, 'SignerRoleArn', { value: this.role.roleArn });
    new cdk.CfnOutput(this, 'KeyAliasArn', { value: aliasArn });
    new cdk.CfnOutput(this, 'ArtifactsBucket', { value: this.artifacts.bucketName });
    new cdk.CfnOutput(this, 'SigningProfile', { value: this.profile.signingProfileName });
  }
}

import * as crypto from 'crypto';
import * as fs from 'fs';
import * as path from 'path';
import * as cdk from 'aws-cdk-lib';
import * as dynamodb from 'aws-cdk-lib/aws-dynamodb';
import * as iam from 'aws-cdk-lib/aws-iam';
import * as kms from 'aws-cdk-lib/aws-kms';
import * as lambda from 'aws-cdk-lib/aws-lambda';
import * as logs from 'aws-cdk-lib/aws-logs';
import { Construct } from 'constructs';
import { KEY_ADMIN_ACTIONS } from './service-vault-stack';

/** The function's own limits (GC #7406 §1): 120 s, at most two at once. */
export const SIGNER_TIMEOUT_SECONDS = 120;
export const SIGNER_CONCURRENCY = 2;

/** The claim table's calls (GC #7406 §2): conditional writes, no delete. */
export const CLAIM_ACTIONS = ['GetItem', 'PutItem', 'UpdateItem'] as const;

export interface AnchorSignerProps {
  readonly envName: string;
  /** The stack's name prefix, vettid-service-vault-<env>. */
  readonly prefix: string;
  /**
   * A directory holding the function's `bootstrap`, built by votes'
   * build at a pinned commit (provided.al2023, arm64), and its SHA-256 in
   * hex: synth refuses another binary.
   */
  readonly codeDir: string;
  readonly bootstrapSha256: string;
  /** The votes site's bucket, read only, its API's https:// URL, and the site key (base64 Ed25519). */
  readonly votesBucketName: string;
  readonly votesApiUrl: string;
  readonly votesSiteKey: string;
  /** staging or production: the Sigstore instance. */
  readonly sigstore: 'staging' | 'production';
  /** The service vault's task role: it invokes the function and reads the key's public half and the claims. */
  readonly taskRole: iam.IRole;
  /** The role that deploys this stack: it administers the anchor key with the account root. */
  readonly deployRoleArn?: string;
  /** The owner's break-glass role: the only principal that may disable the anchor key or schedule its deletion. */
  readonly breakGlassRoleArn?: string;
}

/**
 * The AnchorSigner (key protection, phase 1, GC #7406 §1, §2, §4): the
 * anchor key in KMS, the function that alone may sign with it, its claim
 * table and its journal. Its code is votes' cmd/anchor-signer.
 */
export class AnchorSigner extends Construct {
  readonly key: kms.Key;
  readonly fn: lambda.Function;
  readonly claims: dynamodb.Table;
  readonly journal: logs.LogGroup;
  readonly role: iam.Role;

  constructor(scope: Construct, id: string, props: AnchorSignerProps) {
    super(scope, id);
    if (!/^[0-9a-f]{64}$/.test(props.bootstrapSha256)) {
      throw new Error(`anchorSigner.bootstrapSha256 must be 64 lowercase hex digits (got "${props.bootstrapSha256}")`);
    }
    const bootstrap = path.join(props.codeDir, 'bootstrap');
    const got = crypto.createHash('sha256').update(fs.readFileSync(bootstrap)).digest('hex');
    if (got !== props.bootstrapSha256) {
      throw new Error(`anchorSigner: ${bootstrap} has SHA-256 ${got}, not the pinned ${props.bootstrapSha256}`);
    }
    if (!/^https:\/\/[^/]+$/.test(props.votesApiUrl)) {
      throw new Error(`anchorSigner.votesApiUrl must be an https:// origin with no path (got "${props.votesApiUrl}")`);
    }
    if (!/^[A-Za-z0-9+/]{43}=$/.test(props.votesSiteKey)) {
      throw new Error('anchorSigner.votesSiteKey must be a base64 Ed25519 public key');
    }
    if (props.sigstore === 'production' && props.envName !== 'prod') {
      throw new Error(`anchorSigner.sigstore "production" is for envName "prod" only (got "${props.envName}")`);
    }
    for (const [name, arn] of Object.entries({ deployRoleArn: props.deployRoleArn, breakGlassRoleArn: props.breakGlassRoleArn })) {
      if (arn !== undefined && !/^arn:aws[a-z-]*:iam::[0-9]{12}:role\/[A-Za-z0-9+=,.@_\/-]+$/.test(arn)) {
        throw new Error(`anchorSigner.${name} must be an IAM role ARN (got "${arn}")`);
      }
    }
    const stack = cdk.Stack.of(this);
    const fnName = `${props.prefix}-anchor-signer`;
    const fnArn = stack.formatArn({ service: 'lambda', resource: 'function', resourceName: fnName, arnFormat: cdk.ArnFormat.COLON_RESOURCE_NAME });

    // The role: assumed by Lambda for this function only.
    this.role = new iam.Role(this, 'Role', {
      roleName: `${props.prefix}-anchor-signer`,
      description: 'VettID service vault: the AnchorSigner function (key protection, GC #7406)',
      assumedBy: new iam.ServicePrincipal('lambda.amazonaws.com', {
        conditions: {
          StringEquals: { 'aws:SourceAccount': stack.account },
          ArnLike: { 'aws:SourceArn': fnArn },
        },
      }),
    });

    // The anchor key. Its policy replaces the default (root with kms:*):
    // the account (and the deploy role) administer it, with no CreateGrant
    // and no Sign; only the signer role signs, and only SHA-256 digests;
    // the task reads its public half; nobody but break-glass disables it
    // or schedules its deletion.
    const admins: iam.IPrincipal[] = [new iam.AccountRootPrincipal()];
    if (props.deployRoleArn) admins.push(new iam.ArnPrincipal(props.deployRoleArn));
    this.key = new kms.Key(this, 'AnchorKey', {
      alias: `alias/${props.prefix}-anchor`,
      description: 'VettID service vault: the anchor key (ECDSA P-256), used only by the AnchorSigner',
      keySpec: kms.KeySpec.ECC_NIST_P256,
      keyUsage: kms.KeyUsage.SIGN_VERIFY,
      removalPolicy: cdk.RemovalPolicy.RETAIN,
      policy: new iam.PolicyDocument({
        statements: [
          new iam.PolicyStatement({ sid: 'Administer', principals: admins, actions: KEY_ADMIN_ACTIONS, resources: ['*'] }),
          new iam.PolicyStatement({
            sid: 'SignerSign',
            principals: [new iam.ArnPrincipal(this.role.roleArn)],
            actions: ['kms:Sign'],
            resources: ['*'],
            conditions: { StringEquals: { 'kms:SigningAlgorithm': 'ECDSA_SHA_256', 'kms:MessageType': 'DIGEST' } },
          }),
          new iam.PolicyStatement({
            sid: 'PublicKey',
            principals: [new iam.ArnPrincipal(this.role.roleArn), new iam.ArnPrincipal(props.taskRole.roleArn)],
            actions: ['kms:GetPublicKey'],
            resources: ['*'],
          }),
          new iam.PolicyStatement({
            sid: 'DenyDisableAndDelete',
            effect: iam.Effect.DENY,
            principals: [new iam.AnyPrincipal()],
            actions: ['kms:ScheduleKeyDeletion', 'kms:DisableKey'],
            resources: ['*'],
            ...(props.breakGlassRoleArn ? { conditions: { ArnNotEquals: { 'aws:PrincipalArn': props.breakGlassRoleArn } } } : {}),
          }),
        ],
      }),
    });

    // The binding of record (GC #7406 §4): the key policy grants the role
    // directly, so only an explicit Deny in the role's own policy can tie
    // kms:Sign to this function.
    this.role.addToPrincipalPolicy(new iam.PolicyStatement({
      sid: 'SignOnlyFromTheFunction',
      effect: iam.Effect.DENY,
      actions: ['kms:Sign'],
      resources: [this.key.keyArn],
      conditions: { StringNotEquals: { 'lambda:SourceFunctionArn': fnArn } },
    }));
    this.role.addToPrincipalPolicy(new iam.PolicyStatement({
      sid: 'Sign', actions: ['kms:Sign', 'kms:GetPublicKey'], resources: [this.key.keyArn],
    }));

    // The claim table (GC #7406 §2): only the signer writes it.
    this.claims = new dynamodb.Table(this, 'Claims', {
      tableName: `${props.prefix}-anchor-claims`,
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
      logGroupName: `/vettid/service-vault/${props.envName}/anchor-journal`,
      retention: logs.RetentionDays.ONE_YEAR,
      removalPolicy: cdk.RemovalPolicy.RETAIN,
    });
    const stream = new logs.LogStream(this, 'JournalStream', {
      logGroup: this.journal, logStreamName: 'signs', removalPolicy: cdk.RemovalPolicy.RETAIN,
    });
    this.role.addToPrincipalPolicy(new iam.PolicyStatement({
      sid: 'Journal',
      actions: ['logs:PutLogEvents'],
      resources: [`${this.journal.logGroupArn.replace(/:\*$/, '')}:log-stream:signs`],
    }));

    // The site, read from its bucket (documents and the service list).
    this.role.addToPrincipalPolicy(new iam.PolicyStatement({
      sid: 'Site',
      actions: ['s3:GetObject'],
      resources: [stack.formatArn({ service: 's3', region: '', account: '', resource: props.votesBucketName, resourceName: 'v1/*' })],
    }));

    // The function's own log, for its operational lines (never the journal).
    const fnLogs = new logs.LogGroup(this, 'Logs', {
      logGroupName: `/aws/lambda/${fnName}`,
      retention: logs.RetentionDays.ONE_MONTH,
      removalPolicy: cdk.RemovalPolicy.RETAIN,
    });
    this.role.addToPrincipalPolicy(new iam.PolicyStatement({
      sid: 'OwnLogs', actions: ['logs:CreateLogStream', 'logs:PutLogEvents'], resources: [`${fnLogs.logGroupArn}`],
    }));

    this.fn = new lambda.Function(this, 'Function', {
      functionName: fnName,
      description: 'VettID service vault: anchors and publishes vote documents (key protection, GC #7406)',
      runtime: lambda.Runtime.PROVIDED_AL2023,
      architecture: lambda.Architecture.ARM_64,
      handler: 'bootstrap',
      code: lambda.Code.fromAsset(props.codeDir),
      role: this.role,
      timeout: cdk.Duration.seconds(SIGNER_TIMEOUT_SECONDS),
      memorySize: 256,
      reservedConcurrentExecutions: SIGNER_CONCURRENCY,
      logGroup: fnLogs,
      environment: {
        SIGNER_KEY_ID: this.key.keyArn,
        SIGNER_CLAIMS_TABLE: this.claims.tableName,
        SIGNER_JOURNAL_GROUP: this.journal.logGroupName,
        SIGNER_JOURNAL_STREAM: 'signs',
        VOTES_BUCKET: props.votesBucketName,
        VOTES_API: props.votesApiUrl,
        VOTES_SIGSTORE: props.sigstore,
        VOTES_SITE_KEY: props.votesSiteKey,
      },
    });
    this.fn.node.addDependency(stream);

    // The task: invokes the function, reads the key's public half and the
    // claims (to tell a pending document from a lost one).
    props.taskRole.addToPrincipalPolicy(new iam.PolicyStatement({
      sid: 'InvokeAnchorSigner', actions: ['lambda:InvokeFunction'], resources: [this.fn.functionArn],
    }));
    props.taskRole.addToPrincipalPolicy(new iam.PolicyStatement({
      sid: 'AnchorKeyPublic', actions: ['kms:GetPublicKey'], resources: [this.key.keyArn],
    }));
    props.taskRole.addToPrincipalPolicy(new iam.PolicyStatement({
      sid: 'AnchorClaimsRead', actions: ['dynamodb:GetItem'], resources: [this.claims.tableArn],
    }));
  }
}

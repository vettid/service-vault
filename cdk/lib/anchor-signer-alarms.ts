import * as cdk from 'aws-cdk-lib';
import * as cloudtrail from 'aws-cdk-lib/aws-cloudtrail';
import * as cloudwatch from 'aws-cdk-lib/aws-cloudwatch';
import * as cwactions from 'aws-cdk-lib/aws-cloudwatch-actions';
import * as events from 'aws-cdk-lib/aws-events';
import * as targets from 'aws-cdk-lib/aws-events-targets';
import * as guardduty from 'aws-cdk-lib/aws-guardduty';
import * as iam from 'aws-cdk-lib/aws-iam';
import * as firehose from 'aws-cdk-lib/aws-kinesisfirehose';
import * as logs from 'aws-cdk-lib/aws-logs';
import * as destinations from 'aws-cdk-lib/aws-logs-destinations';
import * as s3 from 'aws-cdk-lib/aws-s3';
import * as sns from 'aws-cdk-lib/aws-sns';
import { KEY_CHANGE_EVENTS } from './service-vault-stack';

/**
 * The fixed names the signer account and the management account share
 * (#7646): the locked bucket there, and the role here that alone may
 * replicate into it. Fixed, so neither stack waits for the other's outputs.
 */
export const signerAuditNames = (envName: string) => ({
  bucket: (auditAccount: string) => `vettid-signer-audit-${envName}-${auditAccount}`,
  replicationRole: `vettid-anchor-audit-replication-${envName}`,
});

/** Changes to the audit bucket's copy path: its replication, policy, versioning, lifecycle; the journal's Firehose. */
export const AUDIT_CHANGES = ['PutBucketReplication', 'DeleteBucketReplication', 'PutBucketPolicy', 'DeleteBucketPolicy',
  'PutBucketVersioning', 'PutBucketLifecycle', 'DeleteBucketLifecycle', 'PutBucketOwnershipControls', 'DeleteBucket',
  'DeleteDeliveryStream', 'UpdateDestination', 'StopDeliveryStreamEncryption'] as const;

/** The signer's own alarm codes (its log's `alarm` field). */
export const SIGNER_ALARMS = ['claim_conflict', 'claim_stuck', 'journal_failed', 'key_not_listed', 'key_mismatch'] as const;

/** More Signs than this in an hour alarm (GC #7406 §1). */
export const SIGNS_PER_HOUR = 20;

/** CloudTrail event names (prefixes: Lambda's carry an API version) that change what signs, or who can. */
export const LAMBDA_CHANGES = ['UpdateFunctionCode', 'UpdateFunctionConfiguration', 'PutFunctionCodeSigningConfig',
  'DeleteFunctionCodeSigningConfig', 'UpdateCodeSigningConfig', 'DeleteCodeSigningConfig', 'CreateCodeSigningConfig',
  'AddPermission', 'RemovePermission', 'PutResourcePolicy', 'DeleteResourcePolicy', 'PutFunctionConcurrency',
  'DeleteFunctionConcurrency', 'DeleteFunction', 'CreateFunction', 'PublishLayerVersion', 'PublishVersion',
  'CreateAlias', 'UpdateAlias', 'PutRuntimeManagementConfig'];
export const SIGNER_CHANGES = ['RevokeSignature', 'RevokeSigningProfile', 'CancelSigningProfile', 'PutSigningProfile',
  'AddProfilePermission', 'RemoveProfilePermission'];
export const KMS_ALIAS_CHANGES = ['CreateAlias', 'UpdateAlias', 'DeleteAlias'];
export const TRAIL_CHANGES = ['StopLogging', 'DeleteTrail', 'UpdateTrail', 'PutEventSelectors', 'PutInsightSelectors'];
export const STORE_CHANGES = { 'dynamodb.amazonaws.com': ['DeleteTable', 'UpdateTable', 'DeleteBackup', 'RestoreTableToPointInTime', 'UpdateContinuousBackups'],
  'logs.amazonaws.com': ['DeleteLogGroup', 'DeleteLogStream', 'PutRetentionPolicy', 'DeleteRetentionPolicy', 'DisassociateKmsKey',
    'PutSubscriptionFilter', 'DeleteSubscriptionFilter'] };
export const IAM_CHANGES = ['PutRolePolicy', 'DeleteRolePolicy', 'AttachRolePolicy', 'DetachRolePolicy', 'UpdateAssumeRolePolicy',
  'DeleteRole', 'PutRolePermissionsBoundary', 'DeleteRolePermissionsBoundary', 'UpdateRole'];

export interface SignerAlarmsProps {
  readonly envName: string;
  readonly topic: sns.ITopic;
  readonly keyArn: string;
  readonly signerRoleName: string;
  readonly breakGlassRoleArn: string;
  readonly claimsTable: string;
  readonly journal: logs.ILogGroup;
  readonly functionLogs: logs.ILogGroup;
  /** The management account (#7646), whose SignerAudit-<env> stack holds the locked copy. */
  readonly auditAccount: string;
}

/**
 * The signer account's own trail, GuardDuty and alarms (key protection
 * P1.3, card #7415): everything that could change what signs, or who can,
 * reaches the owner on the account's own topic. IAM, STS (the global
 * endpoint) and console sign-in events arrive in us-east-1 only: those
 * rules are made only there (a warning otherwise). The trail's files and
 * the journal's copy replicate to the management account's Object Lock
 * bucket (SignerAudit-<env>, the owner's a on #7646), which also watches
 * that they keep arriving.
 *
 * To verify on staging (P1.6): S3 replicates into the locked bucket from
 * this lock-enabled one; replicas raise "Object Created" there (else the
 * staleness alarm fires: loud, not quiet); the Sign and GetPublicKey rules
 * see read-only events.
 */
export function addSignerAlarms(stack: cdk.Stack, props: SignerAlarmsProps): void {
  // readOnly: read-only management events (Sign, GetPublicKey) reach a
  // rule only in this state; by default it never sees them.
  const notify = (id: string, description: string, pattern: events.EventPattern, readOnly = false) => {
    const rule = new events.Rule(stack, id, { description, eventPattern: pattern, targets: [new targets.SnsTopic(props.topic)] });
    if (readOnly) (rule.node.defaultChild as events.CfnRule).state = 'ENABLED_WITH_ALL_CLOUDTRAIL_MANAGEMENT_EVENTS';
  };
  const trailEvent = (source: string, names: string[], detail: Record<string, unknown> = {}): events.EventPattern => ({
    source: [source], detailType: ['AWS API Call via CloudTrail'],
    detail: { eventName: names.map((n) => ({ prefix: n })) as any, ...detail },
  });

  // The audit bucket: the trail's files (trail/) and the journal's copy
  // (journal/), versioned, each object replicated as written to the
  // management account's Object Lock bucket (the owner's a on #7646), by a
  // role that may only replicate into it. Deletes here are not replicated.
  const names = signerAuditNames(props.envName);
  const auditBucketArn = `arn:${stack.partition}:s3:::${names.bucket(props.auditAccount)}`;
  const replication = new iam.Role(stack, 'AuditReplicationRole', {
    roleName: names.replicationRole,
    description: 'VettID anchor signer: replicates the audit bucket to the management account\'s locked copy',
    assumedBy: new iam.ServicePrincipal('s3.amazonaws.com', { conditions: { StringEquals: { 'aws:SourceAccount': stack.account } } }),
  });
  // Object Lock is on here too, with no default retention (so the trail's
  // and Firehose's writes need no Content-MD5): S3 replicates into a
  // locked bucket from a lock-enabled one. To verify on staging (P1.6).
  const bucket = new s3.Bucket(stack, 'AuditBucket', {
    versioned: true, objectLockEnabled: true, blockPublicAccess: s3.BlockPublicAccess.BLOCK_ALL,
    encryption: s3.BucketEncryption.S3_MANAGED, enforceSSL: true, removalPolicy: cdk.RemovalPolicy.RETAIN,
    objectOwnership: s3.ObjectOwnership.BUCKET_OWNER_ENFORCED,
  });
  replication.addToPrincipalPolicy(new iam.PolicyStatement({
    sid: 'ReadSource', actions: ['s3:GetReplicationConfiguration', 's3:ListBucket'], resources: [bucket.bucketArn],
  }));
  replication.addToPrincipalPolicy(new iam.PolicyStatement({
    sid: 'ReadSourceObjects', actions: ['s3:GetObjectVersionForReplication', 's3:GetObjectVersionAcl', 's3:GetObjectVersionTagging',
      's3:GetObjectRetention', 's3:GetObjectLegalHold'],
    resources: [bucket.arnForObjects('*')],
  }));
  replication.addToPrincipalPolicy(new iam.PolicyStatement({
    sid: 'ReplicateOnly', actions: ['s3:ReplicateObject'], resources: [`${auditBucketArn}/*`],
  }));
  (bucket.node.defaultChild as s3.CfnBucket).replicationConfiguration = {
    role: replication.roleArn,
    rules: [{
      id: 'LockedCopy', status: 'Enabled', priority: 1, filter: { prefix: '' },
      deleteMarkerReplication: { status: 'Disabled' },
      destination: { bucket: auditBucketArn, account: props.auditAccount },
    }],
  };

  // The trail: management events, read and write, every region, its files
  // validated.
  new cloudtrail.Trail(stack, 'Trail', {
    bucket, s3KeyPrefix: 'trail', isMultiRegionTrail: true, includeGlobalServiceEvents: true, enableFileValidation: true,
    managementEvents: cloudtrail.ReadWriteType.ALL,
  });

  // The journal's copy: every journal line, through Firehose, to journal/
  // (and on to the locked copy).
  const copy = new firehose.DeliveryStream(stack, 'JournalCopy', {
    destination: new firehose.S3Bucket(bucket, {
      dataOutputPrefix: 'journal/', errorOutputPrefix: 'journal-errors/', bufferingInterval: cdk.Duration.seconds(60),
    }),
  });
  new logs.SubscriptionFilter(stack, 'JournalToCopy', {
    logGroup: props.journal, destination: new destinations.FirehoseDestination(copy), filterPattern: logs.FilterPattern.allEvents(),
  });
  notify('AuditChange', 'The audit bucket\'s replication, policy, versioning or lock changed, or the journal\'s copy',
    { source: ['aws.s3', 'aws.firehose'], detailType: ['AWS API Call via CloudTrail'],
      detail: { eventName: [...AUDIT_CHANGES] } });

  // GuardDuty, its findings to the owner.
  new guardduty.CfnDetector(stack, 'GuardDuty', { enable: true });
  notify('GuardDutyFindings', 'GuardDuty findings in the signer account', { source: ['aws.guardduty'], detailType: ['GuardDuty Finding'] });

  // The anchor key: an error on Sign or GetPublicKey, or either from any
  // principal but the signer role; any change to the key or its alias.
  notify('KeyUseError', 'Sign or GetPublicKey on the anchor key failed',
    trailEvent('aws.kms', ['Sign', 'GetPublicKey'], { resources: { ARN: [props.keyArn] }, errorCode: [{ exists: true }] }), true);
  notify('KeyUseOther', 'Sign or GetPublicKey on the anchor key by another principal than the signer',
    // Two branches, as in service-vault-stack: anything-but needs the field
    // present, so callers that aren't role sessions (root, a user, a
    // service) are matched by their type.
    trailEvent('aws.kms', ['Sign', 'GetPublicKey'], {
      resources: { ARN: [props.keyArn] },
      $or: [
        { userIdentity: { type: [{ 'anything-but': ['AssumedRole'] }] } },
        { userIdentity: { type: ['AssumedRole'], arn: [{ 'anything-but': { prefix: `arn:${stack.partition}:sts::${stack.account}:assumed-role/${props.signerRoleName}/` } }] } },
      ],
    }), true);
  notify('KeyChange', 'The anchor key, its policy, grants or state changed',
    trailEvent('aws.kms', KEY_CHANGE_EVENTS, { resources: { ARN: [props.keyArn] } }));
  notify('KeyAliasChange', 'A KMS alias changed in the signer account', trailEvent('aws.kms', KMS_ALIAS_CHANGES));

  // The function, its code signing, its resource policy and concurrency;
  // the signing profile; the trail; the claims and the journal.
  notify('FunctionChange', 'The signer function, its code, code signing, policy or concurrency changed', trailEvent('aws.lambda', LAMBDA_CHANGES));
  notify('SigningChange', 'The signing profile or a signature changed', trailEvent('aws.signer', SIGNER_CHANGES));
  notify('TrailChange', 'The trail was stopped or changed', trailEvent('aws.cloudtrail', TRAIL_CHANGES));
  notify('ClaimsChange', 'The claim table was deleted, changed or restored', trailEvent('aws.dynamodb', STORE_CHANGES['dynamodb.amazonaws.com']));
  notify('JournalChange', 'A log group (the journal) was deleted or its retention changed', trailEvent('aws.logs', STORE_CHANGES['logs.amazonaws.com']));

  // IAM, STS and console sign-in: us-east-1 only.
  if (cdk.Token.isUnresolved(stack.region)) {
    cdk.Annotations.of(stack).addWarning('The region is not known at synth: the IAM, break-glass and root sign-in rules (us-east-1 only) are omitted.');
  } else if (stack.region === 'us-east-1') {
    notify('RoleChange', 'The signer role or its policies changed',
      trailEvent('aws.iam', IAM_CHANGES, { requestParameters: { roleName: [props.signerRoleName] } }));
    notify('BreakGlassUsed', 'The break-glass role was assumed',
      trailEvent('aws.sts', ['AssumeRole'], { requestParameters: { roleArn: [props.breakGlassRoleArn] } }));
    notify('RootSignIn', 'The root user signed in', {
      source: ['aws.signin'], detailType: ['AWS Console Sign In via CloudTrail'], detail: { userIdentity: { type: ['Root'] } },
    });
  } else {
    cdk.Annotations.of(stack).addWarning(`The IAM, break-glass and root sign-in rules need us-east-1 (this stack is in ${stack.region}): deploy them there.`);
  }

  // The signer's own alarms, from its log; more than SIGNS_PER_HOUR signs
  // an hour, from the journal's sign entries.
  const alarm = (id: string, description: string, metric: cloudwatch.IMetric, threshold: number) => {
    new cloudwatch.Alarm(stack, id, {
      alarmName: `vettid-anchor-signer-${props.envName}-${id}`, alarmDescription: description, metric, threshold,
      evaluationPeriods: 1, comparisonOperator: cloudwatch.ComparisonOperator.GREATER_THAN_OR_EQUAL_TO_THRESHOLD,
      treatMissingData: cloudwatch.TreatMissingData.NOT_BREACHING,
    }).addAlarmAction(new cwactions.SnsAction(props.topic));
  };
  for (const name of SIGNER_ALARMS) {
    const m = new logs.MetricFilter(stack, `Filter-${name}`, {
      logGroup: props.functionLogs, filterPattern: logs.FilterPattern.stringValue('$.alarm', '=', name),
      metricNamespace: `VettID/AnchorSigner/${props.envName}`, metricName: name, metricValue: '1',
    }).metric({ statistic: 'Sum', period: cdk.Duration.minutes(5) });
    alarm(name, `The signer logged ${name}`, m, 1);
  }
  const signs = new logs.MetricFilter(stack, 'Filter-signs', {
    logGroup: props.journal, filterPattern: logs.FilterPattern.stringValue('$.kind', '=', 'sign'),
    metricNamespace: `VettID/AnchorSigner/${props.envName}`, metricName: 'signs', metricValue: '1',
  }).metric({ statistic: 'Sum', period: cdk.Duration.hours(1) });
  alarm('signs_per_hour', `More than ${SIGNS_PER_HOUR} signs in an hour`, signs, SIGNS_PER_HOUR + 1);
}

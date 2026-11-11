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
 * (#7646), so neither stack waits for the other's outputs: the locked
 * bucket and the alarm bus there; the roles here that alone may replicate
 * into the one and put events on the other; and this account's audit
 * bucket.
 */
export const signerAuditNames = (envName: string) => ({
  bucket: (auditAccount: string) => `vettid-signer-audit-${envName}-${auditAccount}`,
  bus: `vettid-signer-alarms-${envName}`,
  replicationRole: `vettid-anchor-audit-replication-${envName}`,
  forwardRole: `vettid-anchor-alarm-forward-${envName}`,
  sourceBucket: (signerAccount: string) => `vettid-anchor-audit-${envName}-${signerAccount}`,
});

/** Changes to the audit bucket's copy path: its replication, policy, versioning, lifecycle, encryption, lock, public access; the journal's Firehose. */
export const AUDIT_CHANGES = ['PutBucketReplication', 'DeleteBucketReplication', 'PutBucketPolicy', 'DeleteBucketPolicy',
  'PutBucketVersioning', 'PutBucketLifecycle', 'DeleteBucketLifecycle', 'PutBucketOwnershipControls', 'DeleteBucket',
  'PutBucketEncryption', 'DeleteBucketEncryption', 'PutObjectLockConfiguration', 'PutBucketObjectLockConfiguration',
  'PutBucketPublicAccessBlock', 'DeleteBucketPublicAccessBlock', 'PutBucketAcl',
  'DeleteDeliveryStream', 'UpdateDestination', 'StopDeliveryStreamEncryption'] as const;

/** The signer account's heartbeat to the management account's bus, every this many minutes. */
export const FORWARD_HEARTBEAT_MINUTES = 5;

/** The trail's log group receiving nothing for this long alarms (a multiple of 5). */
export const TRAIL_QUIET_MINUTES = 15;

/** The signer's own alarm codes (its log's `alarm` field). */
export const SIGNER_ALARMS = ['claim_conflict', 'claim_stuck', 'journal_failed', 'key_not_listed', 'key_mismatch'] as const;

/** More Signs than this in an hour alarm (GC #7406 §1), counted twice: from the journal and from KMS's own record. */
export const SIGNS_PER_HOUR = 20;

/**
 * CloudTrail event names (prefixes: Lambda's carry an API version) that
 * change what signs, who can, or what invokes it: code, configuration,
 * code signing, the resource policy, concurrency, aliases and versions,
 * function URLs, event source mappings (a queue the role can read would
 * otherwise invoke it with no AddPermission), async invoke configuration.
 */
export const LAMBDA_CHANGES = ['UpdateFunctionCode', 'UpdateFunctionConfiguration', 'PutFunctionCodeSigningConfig',
  'DeleteFunctionCodeSigningConfig', 'UpdateCodeSigningConfig', 'DeleteCodeSigningConfig', 'CreateCodeSigningConfig',
  'AddPermission', 'RemovePermission', 'PutResourcePolicy', 'DeleteResourcePolicy', 'PutFunctionConcurrency',
  'DeleteFunctionConcurrency', 'DeleteFunction', 'CreateFunction', 'PublishLayerVersion', 'PublishVersion',
  'CreateAlias', 'UpdateAlias', 'DeleteAlias', 'PutRuntimeManagementConfig',
  'CreateEventSourceMapping', 'UpdateEventSourceMapping', 'DeleteEventSourceMapping',
  'PutFunctionEventInvokeConfig', 'UpdateFunctionEventInvokeConfig', 'DeleteFunctionEventInvokeConfig',
  'PutProvisionedConcurrencyConfig', 'PutFunctionRecursionConfig', 'UpdateFunctionUrlConfig', 'DeleteFunctionUrlConfig'];
export const SIGNER_CHANGES = ['RevokeSignature', 'RevokeSigningProfile', 'CancelSigningProfile', 'PutSigningProfile',
  'AddProfilePermission', 'RemoveProfilePermission'];
export const KMS_ALIAS_CHANGES = ['CreateAlias', 'UpdateAlias', 'DeleteAlias'];
export const TRAIL_CHANGES = ['StopLogging', 'DeleteTrail', 'UpdateTrail', 'PutEventSelectors', 'PutInsightSelectors'];
export const STORE_CHANGES = { 'dynamodb.amazonaws.com': ['DeleteTable', 'UpdateTable', 'DeleteBackup', 'RestoreTableToPointInTime', 'UpdateContinuousBackups'],
  'logs.amazonaws.com': ['DeleteLogGroup', 'DeleteLogStream', 'PutRetentionPolicy', 'DeleteRetentionPolicy', 'DisassociateKmsKey',
    'PutSubscriptionFilter', 'DeleteSubscriptionFilter', 'PutMetricFilter', 'DeleteMetricFilter'] };

/**
 * The alarm path itself (by CloudTrail eventSource): its rules and their
 * targets, the topic and its subscriptions, the alarms, GuardDuty. Each is
 * also forwarded to the management account, so quieting the path here is
 * seen from outside.
 */
export const ALARM_PATH_CHANGES: Record<string, string[]> = {
  'events.amazonaws.com': ['DisableRule', 'DeleteRule', 'PutRule', 'PutTargets', 'RemoveTargets', 'PutPermission', 'RemovePermission'],
  'sns.amazonaws.com': ['DeleteTopic', 'Unsubscribe', 'Subscribe', 'SetTopicAttributes', 'SetSubscriptionAttributes', 'AddPermission', 'RemovePermission'],
  'monitoring.amazonaws.com': ['DeleteAlarms', 'DisableAlarmActions', 'PutMetricAlarm', 'PutCompositeAlarm', 'SetAlarmState'],
  'guardduty.amazonaws.com': ['DeleteDetector', 'UpdateDetector', 'CreateFilter', 'UpdateFilter', 'CreateIPSet', 'UpdateIPSet', 'DeleteMembers'],
};

/**
 * Alarms on the trail's own log group, which receives every region's
 * events: IAM, STS and sign-in events reach EventBridge only in their
 * region (us-east-1, or the regional endpoint called), so these can't be
 * EventBridge rules in one region. Each is a CloudWatch Logs JSON filter.
 */
export const trailFilters = (breakGlassRoleArn: string, signerRoleName: string) => ({
  // Every use of the break-glass role: its AssumeRole (any region, any
  // route) and every call its sessions make.
  break_glass: `{ (($.eventName = "AssumeRole") && ($.requestParameters.roleArn = "${breakGlassRoleArn}")) || ($.userIdentity.sessionContext.sessionIssuer.arn = "${breakGlassRoleArn}") }`,
  // The root user, doing anything (console sign-in included).
  root_use: '{ ($.userIdentity.type = "Root") && ($.eventType != "AwsServiceEvent") }',
  // Any IAM write in this account (only the owner administers it).
  iam_change: '{ ($.eventSource = "iam.amazonaws.com") && ($.readOnly IS FALSE) }',
  // A write to the claim table (a data event) by anyone but the signer role.
  claims_write_other: `{ ($.eventCategory = "Data") && ($.eventSource = "dynamodb.amazonaws.com") && (($.userIdentity.type != "AssumedRole") || ($.userIdentity.sessionContext.sessionIssuer.userName != "${signerRoleName}")) }`,
  // A delete in the claim table, by anyone (the signer is never allowed one).
  claims_delete: '{ ($.eventCategory = "Data") && ($.eventSource = "dynamodb.amazonaws.com") && ($.eventName = "DeleteItem") }',
});

export interface SignerAlarmsProps {
  readonly envName: string;
  readonly topic: sns.ITopic;
  readonly keyArn: string;
  readonly signerRoleName: string;
  readonly breakGlassRoleArn: string;
  readonly claimsTableArn: string;
  readonly journal: logs.ILogGroup;
  readonly functionLogs: logs.ILogGroup;
  /** The management account (#7646), whose SignerAudit-<env> stack holds the locked copy and the alarm bus. */
  readonly auditAccount: string;
  /** Its region (default: this stack's). */
  readonly auditRegion?: string;
}

/**
 * The signer account's own trail, GuardDuty and alarms (key protection
 * P1.3, card #7415). Everything that could change what signs, who can, or
 * whether it is seen, alarms to the owner on this account's topic and is
 * forwarded to the management account's alarm bus (SignerAudit-<env>),
 * where its own topic tells the owner again: an attacker here who silences
 * the path here is still seen from there. Entry to this account (the
 * break-glass role, the root user) alarms before anything else can be
 * changed. The trail's files and the journal's copy replicate to the
 * management account's Object Lock bucket, which watches that the trail's
 * hourly digests keep arriving.
 *
 * To verify on staging (P1.6): S3 replicates into the locked bucket from
 * this lock-enabled one; replicas raise "Object Created" there (else the
 * staleness alarm fires: loud, not quiet); the Sign and GetPublicKey rules
 * see read-only events; the trail's log filters match break-glass and
 * root use from another region; cross-account PutEvents to the bus.
 */
export function addSignerAlarms(stack: cdk.Stack, props: SignerAlarmsProps): void {
  const names = signerAuditNames(props.envName);
  const auditRegion = props.auditRegion ?? stack.region;

  // The management account's alarm bus, and the role that alone may put on it.
  const busArn = `arn:${stack.partition}:events:${auditRegion}:${props.auditAccount}:event-bus/${names.bus}`;
  const forward = new iam.Role(stack, 'AlarmForwardRole', {
    roleName: names.forwardRole,
    description: 'VettID anchor signer: forwards this account\'s alarms to the management account\'s bus',
    assumedBy: new iam.ServicePrincipal('events.amazonaws.com', { conditions: { StringEquals: { 'aws:SourceAccount': stack.account } } }),
  });
  forward.addToPrincipalPolicy(new iam.PolicyStatement({ sid: 'PutOnTheBus', actions: ['events:PutEvents'], resources: [busArn] }));
  const outside = new targets.EventBus(events.EventBus.fromEventBusArn(stack, 'ManagementBus', busArn), { role: forward });

  // readOnly: read-only management events (Sign, GetPublicKey) reach a
  // rule only in this state; by default it never sees them.
  const notify = (id: string, description: string, pattern: events.EventPattern, readOnly = false) => {
    const rule = new events.Rule(stack, id, { description, eventPattern: pattern, targets: [new targets.SnsTopic(props.topic), outside] });
    if (readOnly) (rule.node.defaultChild as events.CfnRule).state = 'ENABLED_WITH_ALL_CLOUDTRAIL_MANAGEMENT_EVENTS';
  };
  const trailEvent = (source: string, eventNames: string[], detail: Record<string, unknown> = {}): events.EventPattern => ({
    source: [source], detailType: ['AWS API Call via CloudTrail'],
    detail: { eventName: eventNames.map((n) => ({ prefix: n })) as any, ...detail },
  });
  // By eventSource, so no EventBridge source name has to be guessed.
  const sourceEvent = (eventSource: string, eventNames: string[]): events.EventPattern => ({
    detailType: ['AWS API Call via CloudTrail'], detail: { eventSource: [eventSource], eventName: eventNames },
  });

  // The audit bucket: the trail's files (trail/) and the journal's copy
  // (journal/), versioned, each object replicated as written to the
  // management account's Object Lock bucket (the owner's a on #7646), by a
  // role that may only replicate into it. Deletes here are not replicated.
  const sourceBucketName = names.sourceBucket(stack.account);
  const sourceBucketArn = `arn:${stack.partition}:s3:::${sourceBucketName}`;
  const auditBucketArn = `arn:${stack.partition}:s3:::${names.bucket(props.auditAccount)}`;
  const replication = new iam.Role(stack, 'AuditReplicationRole', {
    roleName: names.replicationRole,
    description: 'VettID anchor signer: replicates the audit bucket to the management account\'s locked copy',
    assumedBy: new iam.ServicePrincipal('s3.amazonaws.com', { conditions: {
      StringEquals: { 'aws:SourceAccount': stack.account }, ArnLike: { 'aws:SourceArn': sourceBucketArn },
    } }),
  });
  // Object Lock is on here too, with no default retention (so the trail's
  // and Firehose's writes need no Content-MD5): S3 replicates into a
  // locked bucket from a lock-enabled one. To verify on staging (P1.6).
  const bucket = new s3.Bucket(stack, 'AuditBucket', {
    bucketName: sourceBucketName,
    versioned: true, objectLockEnabled: true, blockPublicAccess: s3.BlockPublicAccess.BLOCK_ALL,
    encryption: s3.BucketEncryption.S3_MANAGED, enforceSSL: true, removalPolicy: cdk.RemovalPolicy.RETAIN,
    objectOwnership: s3.ObjectOwnership.BUCKET_OWNER_ENFORCED,
  });
  replication.addToPrincipalPolicy(new iam.PolicyStatement({
    sid: 'ReadSource', actions: ['s3:GetReplicationConfiguration', 's3:ListBucket'], resources: [sourceBucketArn],
  }));
  replication.addToPrincipalPolicy(new iam.PolicyStatement({
    sid: 'ReadSourceObjects', actions: ['s3:GetObjectVersionForReplication', 's3:GetObjectVersionAcl', 's3:GetObjectVersionTagging',
      's3:GetObjectRetention', 's3:GetObjectLegalHold'],
    resources: [`${sourceBucketArn}/*`],
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

  // The trail: every region; management events, read and write; the claim
  // table's writes as data events (a deleted claim would let a slot be
  // signed again); files validated; and a copy into a log group here,
  // which the region-independent alarms below read.
  const trailLogs = new logs.LogGroup(stack, 'TrailLogs', {
    logGroupName: `/vettid/anchor/${props.envName}/trail`, retention: logs.RetentionDays.ONE_YEAR, removalPolicy: cdk.RemovalPolicy.RETAIN,
  });
  const trail = new cloudtrail.Trail(stack, 'Trail', {
    bucket, s3KeyPrefix: 'trail', isMultiRegionTrail: true, includeGlobalServiceEvents: true, enableFileValidation: true,
    sendToCloudWatchLogs: true, cloudWatchLogGroup: trailLogs,
  });
  // Advanced selectors only: the trail may not carry both kinds.
  (trail.node.defaultChild as cloudtrail.CfnTrail).addPropertyDeletionOverride('EventSelectors');
  (trail.node.defaultChild as cloudtrail.CfnTrail).advancedEventSelectors = [
    { name: 'Management events, read and write', fieldSelectors: [{ field: 'eventCategory', equalTo: ['Management'] }] },
    { name: 'Claim table writes', fieldSelectors: [
      { field: 'eventCategory', equalTo: ['Data'] },
      { field: 'resources.type', equalTo: ['AWS::DynamoDB::Table'] },
      { field: 'resources.ARN', equalTo: [props.claimsTableArn] },
      { field: 'readOnly', equalTo: ['false'] },
    ] },
  ];

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
  notify('AuditChange', 'The audit bucket\'s replication, policy, versioning, encryption or lock changed, or the journal\'s copy',
    { source: ['aws.s3', 'aws.firehose'], detailType: ['AWS API Call via CloudTrail'],
      detail: { eventName: [...AUDIT_CHANGES] } });

  // GuardDuty, its findings to the owner (this region: the account's only one).
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

  // The function and what may invoke it; the signing profile; the trail;
  // the claims and the journal; the alarm path itself.
  notify('FunctionChange', 'The signer function, its code, code signing, policy, triggers or concurrency changed', trailEvent('aws.lambda', LAMBDA_CHANGES));
  notify('SigningChange', 'The signing profile or a signature changed', trailEvent('aws.signer', SIGNER_CHANGES));
  notify('TrailChange', 'The trail was stopped or changed', trailEvent('aws.cloudtrail', TRAIL_CHANGES));
  notify('ClaimsChange', 'The claim table was deleted, changed or restored', trailEvent('aws.dynamodb', STORE_CHANGES['dynamodb.amazonaws.com']));
  notify('JournalChange', 'A log group (the journal, the trail\'s copy) was deleted, its retention, subscription or metric filters changed',
    trailEvent('aws.logs', STORE_CHANGES['logs.amazonaws.com']));
  for (const [eventSource, eventNames] of Object.entries(ALARM_PATH_CHANGES)) {
    const id = eventSource.split('.')[0];
    notify(`AlarmPathChange-${id}`, `The alarm path changed (${eventSource})`, sourceEvent(eventSource, eventNames));
  }

  // Alarms: this account's topic, and each state change into ALARM
  // forwarded to the management account's bus.
  const prefix = `vettid-anchor-signer-${props.envName}-`;
  const alarm = (id: string, description: string, metric: cloudwatch.IMetric, threshold: number) => {
    new cloudwatch.Alarm(stack, id, {
      alarmName: `${prefix}${id}`, alarmDescription: description, metric, threshold,
      evaluationPeriods: 1, comparisonOperator: cloudwatch.ComparisonOperator.GREATER_THAN_OR_EQUAL_TO_THRESHOLD,
      treatMissingData: cloudwatch.TreatMissingData.NOT_BREACHING,
    }).addAlarmAction(new cwactions.SnsAction(props.topic));
  };
  new events.Rule(stack, 'AlarmsOutside', {
    description: 'Each signer-account alarm going into ALARM, forwarded to the management account',
    eventPattern: { source: ['aws.cloudwatch'], detailType: ['CloudWatch Alarm State Change'],
      detail: { alarmName: [{ prefix }], state: { value: ['ALARM'] } } },
    targets: [outside],
  });
  // The forwarding's heartbeat: every FORWARD_HEARTBEAT_MINUTES, through
  // the same role, to the same bus. The management account alarms when
  // they stop (a role denied or recreated, the bus policy, this rule), so
  // breaking the way out is itself seen from outside.
  new events.Rule(stack, 'ForwardHeartbeat', {
    description: 'The signer account\'s heartbeat to the management account\'s alarm bus',
    schedule: events.Schedule.rate(cdk.Duration.minutes(FORWARD_HEARTBEAT_MINUTES)),
    targets: [outside],
  });
  const ns = `VettID/AnchorSigner/${props.envName}`;

  // The signer's own alarms, from its log.
  for (const name of SIGNER_ALARMS) {
    const m = new logs.MetricFilter(stack, `Filter-${name}`, {
      logGroup: props.functionLogs, filterPattern: logs.FilterPattern.stringValue('$.alarm', '=', name),
      metricNamespace: ns, metricName: name, metricValue: '1',
    }).metric({ statistic: 'Sum', period: cdk.Duration.minutes(5) });
    alarm(name, `The signer logged ${name}`, m, 1);
  }
  // From the trail's log group, every region.
  const filters = trailFilters(props.breakGlassRoleArn, props.signerRoleName);
  const describe: Record<keyof typeof filters, string> = {
    break_glass: 'The break-glass role was assumed or used (any region)',
    root_use: 'The root user did something in the signer account (any region; console sign-in included)',
    iam_change: 'An IAM write in the signer account (roles, policies, users)',
    claims_write_other: 'The claim table was written by someone other than the signer',
    claims_delete: 'An item of the claim table was deleted',
  };
  for (const [name, pattern] of Object.entries(filters) as [keyof typeof filters, string][]) {
    const m = new logs.MetricFilter(stack, `Trail-${name}`, {
      logGroup: trailLogs, filterPattern: logs.FilterPattern.literal(pattern), metricNamespace: ns, metricName: name, metricValue: '1',
    }).metric({ statistic: 'Sum', period: cdk.Duration.minutes(5) });
    alarm(name, describe[name], m, 1);
  }
  // More than SIGNS_PER_HOUR signs an hour, counted twice: the journal's
  // sign entries, and KMS's own Sign calls (which the signer's code can't
  // leave out).
  const signs = new logs.MetricFilter(stack, 'Filter-signs', {
    logGroup: props.journal, filterPattern: logs.FilterPattern.stringValue('$.kind', '=', 'sign'),
    metricNamespace: ns, metricName: 'signs', metricValue: '1',
  }).metric({ statistic: 'Sum', period: cdk.Duration.hours(1) });
  alarm('signs_per_hour', `More than ${SIGNS_PER_HOUR} signs in an hour (the journal)`, signs, SIGNS_PER_HOUR + 1);
  const kmsSigns = new logs.MetricFilter(stack, 'Trail-kms_signs', {
    logGroup: trailLogs, filterPattern: logs.FilterPattern.literal('{ ($.eventSource = "kms.amazonaws.com") && ($.eventName = "Sign") }'),
    metricNamespace: ns, metricName: 'kms_signs', metricValue: '1',
  }).metric({ statistic: 'Sum', period: cdk.Duration.hours(1) });
  alarm('kms_signs_per_hour', `More than ${SIGNS_PER_HOUR} KMS Sign calls in an hour (the trail)`, kmsSigns, SIGNS_PER_HOUR + 1);

  // The trail's log group must keep receiving (the account's read events
  // are steady): if its delivery breaks, every filter above goes quiet, so
  // a gap alarms, missing data breaching.
  new cloudwatch.Alarm(stack, 'trail_logs_quiet', {
    alarmName: `${prefix}trail_logs_quiet`,
    alarmDescription: `The trail's log group received nothing for ${TRAIL_QUIET_MINUTES} minutes: its delivery is broken, and the trail alarms with it`,
    metric: new cloudwatch.Metric({
      namespace: 'AWS/Logs', metricName: 'IncomingLogEvents', dimensionsMap: { LogGroupName: trailLogs.logGroupName },
      statistic: 'Sum', period: cdk.Duration.minutes(5),
    }),
    threshold: 1, evaluationPeriods: TRAIL_QUIET_MINUTES / 5,
    comparisonOperator: cloudwatch.ComparisonOperator.LESS_THAN_THRESHOLD,
    treatMissingData: cloudwatch.TreatMissingData.BREACHING,
  }).addAlarmAction(new cwactions.SnsAction(props.topic));
}

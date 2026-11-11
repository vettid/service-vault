import * as cdk from 'aws-cdk-lib';
import * as cloudtrail from 'aws-cdk-lib/aws-cloudtrail';
import * as cloudwatch from 'aws-cdk-lib/aws-cloudwatch';
import * as cwactions from 'aws-cdk-lib/aws-cloudwatch-actions';
import * as events from 'aws-cdk-lib/aws-events';
import * as guardduty from 'aws-cdk-lib/aws-guardduty';
import * as iam from 'aws-cdk-lib/aws-iam';
import * as firehose from 'aws-cdk-lib/aws-kinesisfirehose';
import * as logs from 'aws-cdk-lib/aws-logs';
import * as s3 from 'aws-cdk-lib/aws-s3';
import * as sns from 'aws-cdk-lib/aws-sns';

/**
 * The fixed names the signer account and the management account share
 * (#7646), so neither stack waits for the other's outputs: the locked
 * bucket and the alarm bus there; the roles here that alone may replicate
 * into the one and put events on the other; and this account's audit
 * bucket, trail and journal copy.
 */
export const signerAuditNames = (envName: string) => ({
  bucket: (auditAccount: string) => `vettid-signer-audit-${envName}-${auditAccount}`,
  bus: `vettid-signer-alarms-${envName}`,
  replicationRole: `vettid-anchor-audit-replication-${envName}`,
  forwardRole: `vettid-anchor-alarm-forward-${envName}`,
  sourceBucket: (signerAccount: string) => `vettid-anchor-audit-${envName}-${signerAccount}`,
  trail: `vettid-anchor-${envName}`,
  journalCopy: `vettid-anchor-journal-copy-${envName}`,
});

/**
 * The services whose every management write alarms (by CloudTrail
 * eventSource, readOnly false, eventCategory Management): in this account,
 * administered by the owner alone, a write is a deploy or an intrusion,
 * never routine. The trail's data events (the signer's claim writes and
 * invokes) also reach EventBridge as writes, so the category is required:
 * without it every sign alarms. IAM and STS are read from the trail's log
 * group instead (any region); these rules see this region only.
 */
export const WATCHED_SOURCES = ['lambda', 'signer', 'kms', 'dynamodb', 'logs', 'sns', 'events', 'monitoring',
  'guardduty', 's3', 'firehose', 'cloudtrail', 'cloudformation', 'tagging', 'rolesanywhere', 'account']
  .map((s) => `${s}.amazonaws.com`);

/**
 * Routine management writes, left out: a Lambda cold start's log stream
 * (the signer's and CloudTrail's own), the forwarding's PutEvents, and the
 * anchor key's use (its own rules watch it).
 */
export const ROUTINE_WRITES: Record<string, string[]> = {
  'logs.amazonaws.com': ['CreateLogStream'],
  'events.amazonaws.com': ['PutEvents'],
  'kms.amazonaws.com': ['Sign', 'Verify', 'GetPublicKey'],
};

/** The signer's own alarm codes (its log's `alarm` field). */
export const SIGNER_ALARMS = ['claim_conflict', 'claim_stuck', 'journal_failed', 'key_not_listed', 'key_mismatch'] as const;

/** More Signs than this in an hour alarm (GC #7406 §1), counted twice: from the journal and from KMS's own record. */
export const SIGNS_PER_HOUR = 20;

/** The signer account's heartbeat to the management account's bus, every this many minutes. */
export const FORWARD_HEARTBEAT_MINUTES = 5;

/** The trail's log group receiving nothing for this long alarms (a multiple of 5). */
export const TRAIL_QUIET_MINUTES = 30;

/**
 * Count alarms look at this many 5-minute periods and alarm on any one
 * breaching: CloudTrail's delivery to the log group lags 5–15 minutes, so
 * a datapoint can land in a period already evaluated.
 */
export const COUNT_EVALUATION_PERIODS = 3;

/** The journal copy's delivery failing: records came in and delivery didn't succeed (a missing success datapoint counts as none failed). */
export const JOURNAL_COPY_FAILED = 'IF(records > 0 AND FILL(ok, 1) < 1, 1, 0)';

/**
 * Alarms on the trail's log group, which receives every region's events:
 * IAM, STS and sign-in events reach EventBridge only in their region, so
 * these can't be EventBridge rules in one region. Each is a CloudWatch
 * Logs JSON filter.
 */
export const trailFilters = (p: { breakGlassRoleArn: string; signerRoleArn: string; taskAccount: string }) => ({
  // Every use of the break-glass role: its AssumeRole (any region, any
  // route) and every call its sessions make.
  break_glass: `{ (($.eventName = "AssumeRole") && ($.requestParameters.roleArn = "${p.breakGlassRoleArn}")) || ($.userIdentity.sessionContext.sessionIssuer.arn = "${p.breakGlassRoleArn}") }`,
  // Entry by anyone: a role assumed by anything but an AWS service (the
  // CDK roles, an SSO or organization role, any role there is), a console
  // sign-in, or user session tokens.
  entry: '{ (($.eventSource = "sts.amazonaws.com") && ($.eventName = "AssumeRole*") && ($.userIdentity.type != "AWSService")) || ($.eventName = "ConsoleLogin") || ($.eventName = "GetFederationToken") || ($.eventName = "GetSessionToken") }',
  // The root user, doing anything (console sign-in included).
  root_use: '{ ($.userIdentity.type = "Root") && ($.eventType != "AwsServiceEvent") }',
  // Any IAM write in this account (only the owner administers it).
  iam_change: '{ ($.eventSource = "iam.amazonaws.com") && ($.readOnly IS FALSE) }',
  // A write to the claim table (a data event) by anyone but the signer role.
  claims_write_other: `{ ($.eventCategory = "Data") && ($.eventSource = "dynamodb.amazonaws.com") && (($.userIdentity.type != "AssumedRole") || ($.userIdentity.sessionContext.sessionIssuer.arn != "${p.signerRoleArn}")) }`,
  // A delete in the claim table, by anyone (the signer is never allowed one).
  claims_delete: '{ ($.eventCategory = "Data") && ($.eventSource = "dynamodb.amazonaws.com") && ($.eventName = "DeleteItem") }',
  // An invoke of the signer (a data event) from any account but the
  // service's, or one refused: a cross-account caller's record may carry
  // no session issuer, so it's keyed on the account (the function's
  // resource policy admits the task role alone).
  invoke_other: `{ ($.eventCategory = "Data") && ($.eventSource = "lambda.amazonaws.com") && (($.userIdentity.accountId != "${p.taskAccount}") || ($.errorCode EXISTS)) }`,
});

export interface SignerAlarmsProps {
  readonly envName: string;
  readonly topic: sns.Topic;
  readonly keyArn: string;
  readonly signerRoleName: string;
  readonly breakGlassRoleArn: string;
  /** The service vault task's role (the only invoker). */
  readonly taskRoleArn: string;
  /** The signer function's name. */
  readonly functionName: string;
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
 * where its own topic tells the owner again, with a heartbeat that alarms
 * there when it stops. The trail's files and the journal's copy replicate
 * to the management account's Object Lock bucket, which watches that the
 * trail's hourly digests keep arriving.
 *
 * What this part does not hold against: an admin inside this account
 * removing the targets of individual rules before their events arrive.
 * Entry alarms come from the trail's log group, minutes behind. The
 * reconciler (part b) and its audit mode, which reads the locked copy from
 * the management account (P1.3d), are the controls that do.
 *
 * To verify on staging (P1.6): see the PR's list.
 */
export function addSignerAlarms(stack: cdk.Stack, props: SignerAlarmsProps): void {
  const names = signerAuditNames(props.envName);
  const auditRegion = props.auditRegion ?? stack.region;
  const prefix = `vettid-anchor-signer-${props.envName}-`;
  const arn = (service: string, resource: string) => `arn:${stack.partition}:${service}:${stack.region}:${stack.account}:${resource}`;
  const signerRoleArn = `arn:${stack.partition}:iam::${stack.account}:role/${props.signerRoleName}`;
  const fnArn = arn('lambda', `function:${props.functionName}`);

  // The management account's alarm bus, and the role that alone may put on it.
  const busArn = `arn:${stack.partition}:events:${auditRegion}:${props.auditAccount}:event-bus/${names.bus}`;
  const forward = new iam.Role(stack, 'AlarmForwardRole', {
    roleName: names.forwardRole,
    description: 'VettID anchor signer: forwards this account\'s alarms to the management account\'s bus',
    assumedBy: new iam.ServicePrincipal('events.amazonaws.com', { conditions: { StringEquals: { 'aws:SourceAccount': stack.account } } }),
  });
  forward.addToPrincipalPolicy(new iam.PolicyStatement({ sid: 'PutOnTheBus', actions: ['events:PutEvents'], resources: [busArn] }));

  // The topic's policy, written out: EventBridge rules and CloudWatch
  // alarms of this account only (a topic policy replaces the default, so
  // without the CloudWatch statement no alarm could publish).
  const rules: events.Rule[] = [];
  props.topic.addToResourcePolicy(new iam.PolicyStatement({
    sid: 'RulesOfThisAccount', principals: [new iam.ServicePrincipal('events.amazonaws.com')], actions: ['sns:Publish'],
    resources: [props.topic.topicArn], conditions: {
      StringEquals: { 'aws:SourceAccount': stack.account }, ArnLike: { 'aws:SourceArn': arn('events', 'rule/*') },
    },
  }));
  props.topic.addToResourcePolicy(new iam.PolicyStatement({
    sid: 'AlarmsOfThisAccount', principals: [new iam.ServicePrincipal('cloudwatch.amazonaws.com')], actions: ['sns:Publish'],
    resources: [props.topic.topicArn], conditions: {
      StringEquals: { 'aws:SourceAccount': stack.account }, ArnLike: { 'aws:SourceArn': arn('cloudwatch', `alarm:${prefix}*`) },
    },
  }));

  // Targets written out: the topic (its policy above) and the bus.
  const rule = (id: string, description: string, opts: { pattern?: events.EventPattern; schedule?: events.Schedule },
    toTopic: boolean, readOnly = false) => {
    const r = new events.Rule(stack, id, { description, eventPattern: opts.pattern, schedule: opts.schedule });
    const cfn = r.node.defaultChild as events.CfnRule;
    cfn.targets = [
      ...(toTopic ? [{ id: 'Topic', arn: props.topic.topicArn }] : []),
      { id: 'Outside', arn: busArn, roleArn: forward.roleArn },
    ];
    // Read-only management events (Sign, GetPublicKey) reach a rule only
    // in this state; by default it never sees them.
    if (readOnly) cfn.state = 'ENABLED_WITH_ALL_CLOUDTRAIL_MANAGEMENT_EVENTS';
    rules.push(r);
  };
  const notify = (id: string, description: string, pattern: events.EventPattern, readOnly = false) =>
    rule(id, description, { pattern }, true, readOnly);

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
  // table's writes and the signer's invokes as data events; files
  // validated; and a copy into a log group here, which the
  // region-independent alarms below read.
  const trailLogs = new logs.LogGroup(stack, 'TrailLogs', {
    logGroupName: `/vettid/anchor/${props.envName}/trail`, retention: logs.RetentionDays.ONE_YEAR, removalPolicy: cdk.RemovalPolicy.RETAIN,
  });
  const trail = new cloudtrail.Trail(stack, 'Trail', {
    trailName: names.trail, bucket, s3KeyPrefix: 'trail', isMultiRegionTrail: true, includeGlobalServiceEvents: true,
    enableFileValidation: true, sendToCloudWatchLogs: true, cloudWatchLogGroup: trailLogs,
  });
  const cfnTrail = trail.node.defaultChild as cloudtrail.CfnTrail;
  cfnTrail.addPropertyDeletionOverride('EventSelectors'); // advanced selectors only: the trail may not carry both
  cfnTrail.advancedEventSelectors = [
    { name: 'Management events, read and write', fieldSelectors: [{ field: 'eventCategory', equalTo: ['Management'] }] },
    { name: 'Claim table writes', fieldSelectors: [
      { field: 'eventCategory', equalTo: ['Data'] },
      { field: 'resources.type', equalTo: ['AWS::DynamoDB::Table'] },
      { field: 'resources.ARN', equalTo: [props.claimsTableArn] },
      { field: 'readOnly', equalTo: ['false'] },
    ] },
    { name: 'Signer invokes', fieldSelectors: [
      { field: 'eventCategory', equalTo: ['Data'] },
      { field: 'resources.type', equalTo: ['AWS::Lambda::Function'] },
      { field: 'resources.ARN', startsWith: [fnArn] },
    ] },
  ];
  // The trail's log role: CloudTrail for this trail only.
  const logsRole = trail.node.tryFindChild('LogsRole') as iam.Role | undefined;
  if (!logsRole) throw new Error('anchorSigner: the trail has no logs role to condition');
  (logsRole.node.defaultChild as iam.CfnRole).addPropertyOverride('AssumeRolePolicyDocument.Statement.0.Condition', {
    StringEquals: { 'aws:SourceAccount': stack.account }, ArnLike: { 'aws:SourceArn': arn('cloudtrail', `trail/${names.trail}`) },
  });

  // The journal's copy: every journal line, through Firehose, to journal/
  // (and on to the locked copy). Written out: the L2 grants its role
  // read-write, deletes and retention included. This role may only add
  // objects under journal/, for this stream.
  const copyRole = new iam.Role(stack, 'JournalCopyRole', {
    description: 'VettID anchor signer: Firehose writes the journal\'s copy',
    assumedBy: new iam.ServicePrincipal('firehose.amazonaws.com', { conditions: {
      StringEquals: { 'aws:SourceAccount': stack.account }, ArnLike: { 'aws:SourceArn': arn('firehose', `deliverystream/${names.journalCopy}`) },
    } }),
  });
  copyRole.addToPrincipalPolicy(new iam.PolicyStatement({
    sid: 'AddObjects', actions: ['s3:PutObject', 's3:AbortMultipartUpload'],
    resources: [`${sourceBucketArn}/journal/*`, `${sourceBucketArn}/journal-errors/*`],
  }));
  copyRole.addToPrincipalPolicy(new iam.PolicyStatement({
    sid: 'TheBucket', actions: ['s3:GetBucketLocation', 's3:ListBucket', 's3:ListBucketMultipartUploads'], resources: [sourceBucketArn],
  }));
  const copy = new firehose.CfnDeliveryStream(stack, 'JournalCopy', {
    deliveryStreamName: names.journalCopy, deliveryStreamType: 'DirectPut',
    extendedS3DestinationConfiguration: {
      bucketArn: sourceBucketArn, roleArn: copyRole.roleArn, prefix: 'journal/', errorOutputPrefix: 'journal-errors/',
      bufferingHints: { intervalInSeconds: 60, sizeInMBs: 5 },
    },
  });
  copy.node.addDependency(copyRole);
  const subRole = new iam.Role(stack, 'JournalSubscriptionRole', {
    description: 'VettID anchor signer: CloudWatch Logs sends the journal to its copy',
    assumedBy: new iam.ServicePrincipal('logs.amazonaws.com', { conditions: {
      StringEquals: { 'aws:SourceAccount': stack.account }, ArnLike: { 'aws:SourceArn': arn('logs', 'log-group:*') },
    } }),
  });
  subRole.addToPrincipalPolicy(new iam.PolicyStatement({ sid: 'ToTheCopy', actions: ['firehose:PutRecord', 'firehose:PutRecordBatch'], resources: [copy.attrArn] }));
  new logs.CfnSubscriptionFilter(stack, 'JournalToCopy', {
    logGroupName: props.journal.logGroupName, filterPattern: '', destinationArn: copy.attrArn, roleArn: subRole.roleArn,
  }).node.addDependency(subRole);

  // GuardDuty, its findings to the owner (this region: the account's only one).
  new guardduty.CfnDetector(stack, 'GuardDuty', { enable: true });
  notify('GuardDutyFindings', 'GuardDuty findings in the signer account', { source: ['aws.guardduty'], detailType: ['GuardDuty Finding'] });

  // The anchor key's use: an error on Sign or GetPublicKey, or either from
  // any principal but the signer role (read-only events).
  const keyUse = (detail: Record<string, unknown>): events.EventPattern => ({
    source: ['aws.kms'], detailType: ['AWS API Call via CloudTrail'],
    detail: { eventName: ['Sign', 'GetPublicKey'], resources: { ARN: [props.keyArn] }, ...detail },
  });
  notify('KeyUseError', 'Sign or GetPublicKey on the anchor key failed', keyUse({ errorCode: [{ exists: true }] }), true);
  // Two branches, as in service-vault-stack: anything-but needs the field
  // present, so callers that aren't role sessions (root, a user, a
  // service) are matched by their type.
  notify('KeyUseOther', 'Sign or GetPublicKey on the anchor key by another principal than the signer', keyUse({ $or: [
    { userIdentity: { type: [{ 'anything-but': ['AssumedRole'] }] } },
    { userIdentity: { type: ['AssumedRole'], arn: [{ 'anything-but': { prefix: `arn:${stack.partition}:sts::${stack.account}:assumed-role/${props.signerRoleName}/` } }] } },
  ] }), true);

  // Any management write to the watched services: the function, its code
  // signing and triggers, the signing profile, the key, the claims, the
  // log groups, the topic, the rules, the alarms, GuardDuty, the buckets,
  // the Firehose, the trail.
  for (const source of WATCHED_SOURCES) {
    const id = source.split('.')[0];
    const routine = ROUTINE_WRITES[source];
    notify(`Write-${id}`, `A write in the signer account (${source})`, { detailType: ['AWS API Call via CloudTrail'], detail: {
      eventSource: [source], readOnly: [false], eventCategory: ['Management'],
      ...(routine ? { eventName: [{ 'anything-but': routine }] } : {}),
    } });
  }

  // Alarms: this account's topic, and each state change into ALARM
  // forwarded to the management account's bus.
  rule('AlarmsOutside', 'Each signer-account alarm going into ALARM, forwarded to the management account', { pattern: {
    source: ['aws.cloudwatch'], detailType: ['CloudWatch Alarm State Change'],
    detail: { alarmName: [{ prefix }], state: { value: ['ALARM'] } },
  } }, false);
  // The forwarding's heartbeat, through the same role, to the same bus.
  // The management account alarms when it stops (the forwarding role
  // denied, the bus policy, this rule), so breaking the way out is seen
  // from outside.
  rule('ForwardHeartbeat', 'The signer account\'s heartbeat to the management account\'s alarm bus',
    { schedule: events.Schedule.rate(cdk.Duration.minutes(FORWARD_HEARTBEAT_MINUTES)) }, false);

  const ns = `VettID/AnchorSigner/${props.envName}`;
  const countAlarm = (id: string, description: string, metric: cloudwatch.IMetric, threshold: number, periods = COUNT_EVALUATION_PERIODS) => {
    new cloudwatch.Alarm(stack, id, {
      alarmName: `${prefix}${id}`, alarmDescription: description, metric, threshold,
      evaluationPeriods: periods, datapointsToAlarm: 1, comparisonOperator: cloudwatch.ComparisonOperator.GREATER_THAN_OR_EQUAL_TO_THRESHOLD,
      treatMissingData: cloudwatch.TreatMissingData.NOT_BREACHING,
    }).addAlarmAction(new cwactions.SnsAction(props.topic));
  };
  const quietAlarm = (id: string, description: string, metric: cloudwatch.IMetric, periods: number) => {
    new cloudwatch.Alarm(stack, id, {
      alarmName: `${prefix}${id}`, alarmDescription: description, metric, threshold: 1, evaluationPeriods: periods,
      comparisonOperator: cloudwatch.ComparisonOperator.LESS_THAN_THRESHOLD, treatMissingData: cloudwatch.TreatMissingData.BREACHING,
    }).addAlarmAction(new cwactions.SnsAction(props.topic));
  };

  // The signer's own alarms, from its log.
  for (const name of SIGNER_ALARMS) {
    const m = new logs.MetricFilter(stack, `Filter-${name}`, {
      logGroup: props.functionLogs, filterPattern: logs.FilterPattern.stringValue('$.alarm', '=', name),
      metricNamespace: ns, metricName: name, metricValue: '1',
    }).metric({ statistic: 'Sum', period: cdk.Duration.minutes(5) });
    countAlarm(name, `The signer logged ${name}`, m, 1);
  }
  // From the trail's log group, every region.
  const filters = trailFilters({ breakGlassRoleArn: props.breakGlassRoleArn, signerRoleArn, taskAccount: props.taskRoleArn.split(':')[4] });
  const describe: Record<keyof typeof filters, string> = {
    break_glass: 'The break-glass role was assumed or used (any region)',
    entry: 'A role was assumed by other than an AWS service, or someone signed in (any region): an admin entering the signer account',
    root_use: 'The root user did something in the signer account (any region; console sign-in included)',
    iam_change: 'An IAM write in the signer account (roles, policies, users)',
    claims_write_other: 'The claim table was written by someone other than the signer',
    claims_delete: 'An item of the claim table was deleted',
    invoke_other: 'The signer was invoked from another account than the service\'s, or an invoke was refused',
  };
  for (const [name, pattern] of Object.entries(filters) as [keyof typeof filters, string][]) {
    const m = new logs.MetricFilter(stack, `Trail-${name}`, {
      logGroup: trailLogs, filterPattern: logs.FilterPattern.literal(pattern), metricNamespace: ns, metricName: name, metricValue: '1',
    }).metric({ statistic: 'Sum', period: cdk.Duration.minutes(5) });
    countAlarm(name, describe[name], m, 1);
  }
  // More than SIGNS_PER_HOUR signs an hour, counted twice: the journal's
  // sign entries, and KMS's own Sign calls (which the signer's code can't
  // leave out). Clock-hour buckets: a burst split across two hours can
  // pass here; the reconciler compares every KMS Sign with the journal,
  // at any rate.
  const signs = new logs.MetricFilter(stack, 'Filter-signs', {
    logGroup: props.journal, filterPattern: logs.FilterPattern.stringValue('$.kind', '=', 'sign'),
    metricNamespace: ns, metricName: 'signs', metricValue: '1',
  }).metric({ statistic: 'Sum', period: cdk.Duration.hours(1) });
  countAlarm('signs_per_hour', `More than ${SIGNS_PER_HOUR} signs in an hour (the journal)`, signs, SIGNS_PER_HOUR + 1, 1);
  const kmsSigns = new logs.MetricFilter(stack, 'Trail-kms_signs', {
    logGroup: trailLogs, filterPattern: logs.FilterPattern.literal('{ ($.eventSource = "kms.amazonaws.com") && ($.eventName = "Sign") }'),
    metricNamespace: ns, metricName: 'kms_signs', metricValue: '1',
  }).metric({ statistic: 'Sum', period: cdk.Duration.hours(1) });
  countAlarm('kms_signs_per_hour', `More than ${SIGNS_PER_HOUR} KMS Sign calls in an hour (the trail)`, kmsSigns, SIGNS_PER_HOUR + 1, 1);

  // The journal's copy failing to deliver (no data: nothing to deliver).
  countAlarm('journal_copy_failed', 'The journal\'s copy failed to reach the audit bucket', new cloudwatch.MathExpression({
    expression: JOURNAL_COPY_FAILED, period: cdk.Duration.minutes(5),
    usingMetrics: {
      records: new cloudwatch.Metric({ namespace: 'AWS/Firehose', metricName: 'IncomingRecords', dimensionsMap: { DeliveryStreamName: names.journalCopy }, statistic: 'Sum' }),
      ok: new cloudwatch.Metric({ namespace: 'AWS/Firehose', metricName: 'DeliveryToS3.Success', dimensionsMap: { DeliveryStreamName: names.journalCopy }, statistic: 'Average' }),
    },
  }), 1);

  // A rule's target failing (the topic's policy, the bus's), any rule.
  countAlarm('rule_target_failed', 'An EventBridge rule could not deliver to its target (the topic or the management account\'s bus)',
    new cloudwatch.MathExpression({
      expression: `SUM(SEARCH('{AWS/Events,RuleName} MetricName="FailedInvocations"', 'Sum', 300))`, period: cdk.Duration.minutes(5),
    }), 1);

  // The trail's log group must keep receiving (the account's read events
  // are steady): if its delivery breaks, every filter above goes quiet.
  quietAlarm('trail_logs_quiet', `The trail's log group received nothing for ${TRAIL_QUIET_MINUTES} minutes: its delivery is broken, and the trail alarms with it`,
    new cloudwatch.Metric({ namespace: 'AWS/Logs', metricName: 'IncomingLogEvents', dimensionsMap: { LogGroupName: trailLogs.logGroupName },
      statistic: 'Sum', period: cdk.Duration.minutes(5) }), TRAIL_QUIET_MINUTES / 5);
}

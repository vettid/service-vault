import * as cdk from 'aws-cdk-lib';
import * as cloudwatch from 'aws-cdk-lib/aws-cloudwatch';
import * as cwactions from 'aws-cdk-lib/aws-cloudwatch-actions';
import * as events from 'aws-cdk-lib/aws-events';
import * as iam from 'aws-cdk-lib/aws-iam';
import * as logs from 'aws-cdk-lib/aws-logs';
import * as s3 from 'aws-cdk-lib/aws-s3';
import * as sns from 'aws-cdk-lib/aws-sns';
import * as subs from 'aws-cdk-lib/aws-sns-subscriptions';
import { Construct } from 'constructs';
import { signerAuditNames } from './anchor-signer-alarms';

/** The locked copy is kept this long, in compliance mode (#7646). */
export const AUDIT_RETENTION_DAYS = 365;

/** With no trail digest arriving for this many hours, the copy is stale and alarms (#7653). */
export const AUDIT_STALE_HOURS = 2;

/** No heartbeat from the signer account's forwarding for this long alarms (a multiple of 5). */
export const FORWARD_QUIET_MINUTES = 15;

/** Where the signer's trail writes (its s3KeyPrefix "trail"), before <account>/CloudTrail-Digest/. */
export const AUDIT_DIGEST_PREFIX = 'trail/AWSLogs/';

export interface SignerAuditStackProps extends cdk.StackProps {
  readonly envName: string;
  /** The signer account (AnchorSigner-<env>), whose replication role alone may write here. */
  readonly signerAccount: string;
  /** Where the staleness alarm goes: the owner. */
  readonly alarmEmail: string;
}

/**
 * SignerAudit-<env>: in the management account (the owner's a on #7646),
 * outside the signer account, so that a compromise of that account alone
 * can't both sign and hide it. It holds:
 *  - an Object Lock bucket (compliance mode, one year, versioned, bucket
 *    owner enforced) into which the signer account's audit bucket (its
 *    trail and its journal's copy) replicates. Only the signer account's
 *    replication role may write, and only replicas: no delete, no delete
 *    markers, no reads;
 *  - a staleness watch on the trail's digest files, which CloudTrail
 *    writes every hour even when nothing happens: none arriving for
 *    AUDIT_STALE_HOURS alarms to the owner. With none arriving (the trail
 *    stopped or changed, replication broken, this watch broken itself) the
 *    alarm fires: it fails loud, never quiet. Other objects (the journal's
 *    copy, or filler written elsewhere) don't feed it;
 *  - the alarm bus: the signer account's alarm rules and alarm state
 *    changes are forwarded here by its forwarding role alone, and each
 *    reaches the owner on this account's topic, so that quieting the
 *    path inside the signer account is still seen from here.
 *
 * Deployed from the owner's session, before AnchorSigner-<env> (whose
 * replication needs the bucket). Nothing in bin/ deploys it (P1.6 wires it).
 */
export class SignerAuditStack extends cdk.Stack {
  readonly bucket: s3.Bucket;
  readonly topic: sns.Topic;

  constructor(scope: Construct, id: string, props: SignerAuditStackProps) {
    super(scope, id, props);
    const envName = props.envName;
    if (!/^[a-z][a-z0-9-]{0,15}$/.test(envName)) {
      throw new Error(`envName must be lowercase letters, digits and hyphens (got "${envName}")`);
    }
    if (cdk.Token.isUnresolved(this.account) || cdk.Token.isUnresolved(this.region)) {
      throw new Error('SignerAudit needs env.account and env.region: it is the management account');
    }
    if (!/^[0-9]{12}$/.test(props.signerAccount) || props.signerAccount === this.account) {
      throw new Error(`signerAccount must be the signer's own account, not this one (got "${props.signerAccount}")`);
    }
    if (!/^[^@\s]+@[a-z0-9.-]+\.[a-z]+$/.test(props.alarmEmail)) {
      throw new Error(`alarmEmail must be an address (got "${props.alarmEmail}")`);
    }
    const names = signerAuditNames(envName);
    // A log group as an EventBridge target: its ARN without the ":*".
    const logGroupArn = (g: logs.LogGroup) => this.formatArn({ service: 'logs', resource: 'log-group', resourceName: g.logGroupName,
      arnFormat: cdk.ArnFormat.COLON_RESOURCE_NAME });
    const replicationRole = `arn:${this.partition}:iam::${props.signerAccount}:role/${names.replicationRole}`;

    this.topic = new sns.Topic(this, 'AlarmTopic', { displayName: `VettID signer audit (${envName})` });
    this.topic.addSubscription(new subs.EmailSubscription(props.alarmEmail));

    this.bucket = new s3.Bucket(this, 'LockedCopy', {
      bucketName: names.bucket(this.account),
      versioned: true,
      objectLockEnabled: true,
      objectLockDefaultRetention: s3.ObjectLockRetention.compliance(cdk.Duration.days(AUDIT_RETENTION_DAYS)),
      objectOwnership: s3.ObjectOwnership.BUCKET_OWNER_ENFORCED,
      blockPublicAccess: s3.BlockPublicAccess.BLOCK_ALL,
      encryption: s3.BucketEncryption.S3_MANAGED,
      enforceSSL: true,
      removalPolicy: cdk.RemovalPolicy.RETAIN,
    });
    // EventBridge notifications, set on the bucket itself: the L2's
    // eventBridgeEnabled adds a custom-resource Lambda to this account.
    (this.bucket.node.defaultChild as s3.CfnBucket).notificationConfiguration = { eventBridgeConfiguration: { eventBridgeEnabled: true } };
    // The signer account's replication role: replicas in, nothing else.
    // Named by the account and aws:PrincipalArn, not as a principal: this
    // stack deploys before the role exists, and S3 refuses a principal
    // that doesn't.
    const theRole = (roleArn: string) => ({ ArnEquals: { 'aws:PrincipalArn': roleArn } });
    this.bucket.addToResourcePolicy(new iam.PolicyStatement({
      sid: 'SignerReplicates', principals: [new iam.AccountPrincipal(props.signerAccount)],
      actions: ['s3:ReplicateObject'], resources: [this.bucket.arnForObjects('*')], conditions: theRole(replicationRole),
    }));
    this.bucket.addToResourcePolicy(new iam.PolicyStatement({
      sid: 'SignerChecksVersioning', principals: [new iam.AccountPrincipal(props.signerAccount)],
      actions: ['s3:GetBucketVersioning', 's3:ListBucket'], resources: [this.bucket.bucketArn], conditions: theRole(replicationRole),
    }));
    // No principal of the signer account deletes, or replicates a delete,
    // whatever its own policies say.
    this.bucket.addToResourcePolicy(new iam.PolicyStatement({
      sid: 'SignerNeverDeletes', effect: iam.Effect.DENY, principals: [new iam.AnyPrincipal()],
      actions: ['s3:ReplicateDelete', 's3:DeleteObject', 's3:DeleteObjectVersion', 's3:PutObjectRetention', 's3:PutObjectLegalHold',
        's3:BypassGovernanceRetention', 's3:PutBucketObjectLockConfiguration'],
      resources: [this.bucket.bucketArn, this.bucket.arnForObjects('*')],
      conditions: { StringEquals: { 'aws:PrincipalAccount': props.signerAccount } },
    }));

    // The staleness watch: each arrival logged; none for AUDIT_STALE_HOURS alarms.
    const arrivals = new logs.LogGroup(this, 'Arrivals', {
      retention: logs.RetentionDays.ONE_MONTH, removalPolicy: cdk.RemovalPolicy.RETAIN,
    });
    // The target and its log resource policy are written out, as in
    // service-vault-stack, so that no custom-resource Lambda is added here.
    const arrivedRule = new events.Rule(this, 'Arrived', {
      description: `A trail digest file arrived in the signer's locked copy (${envName})`,
      eventPattern: { source: ['aws.s3'], detailType: ['Object Created'], detail: {
        bucket: { name: [this.bucket.bucketName] },
        object: { key: [{ prefix: `${AUDIT_DIGEST_PREFIX}${props.signerAccount}/CloudTrail-Digest/` }] },
      } },
    });
    (arrivedRule.node.defaultChild as events.CfnRule).targets = [{ id: 'Target0', arn: logGroupArn(arrivals) }];
    new logs.ResourcePolicy(this, 'ArrivalsPolicy', {
      resourcePolicyName: `vettid-signer-audit-${envName}-arrivals`,
      policyStatements: [new iam.PolicyStatement({
        principals: [new iam.ServicePrincipal('events.amazonaws.com')],
        actions: ['logs:CreateLogStream', 'logs:PutLogEvents'],
        resources: [arrivals.logGroupArn],
        conditions: { ArnEquals: { 'aws:SourceArn': arrivedRule.ruleArn } },
      })],
    });
    const arrived = new logs.MetricFilter(this, 'ArrivedCount', {
      logGroup: arrivals, filterPattern: logs.FilterPattern.allEvents(),
      metricNamespace: `VettID/SignerAudit/${envName}`, metricName: 'arrived', metricValue: '1',
    }).metric({ statistic: 'Sum', period: cdk.Duration.hours(1) });
    new cloudwatch.Alarm(this, 'Stale', {
      alarmName: `vettid-signer-audit-${envName}-stale`,
      alarmDescription: `No trail digest reached the signer's locked copy for ${AUDIT_STALE_HOURS} hours: the signer account's trail or replication has stopped or changed (or this watch has). Expected until AnchorSigner-${envName} is deployed.`,
      metric: arrived, threshold: 1, evaluationPeriods: AUDIT_STALE_HOURS,
      comparisonOperator: cloudwatch.ComparisonOperator.LESS_THAN_THRESHOLD,
      treatMissingData: cloudwatch.TreatMissingData.BREACHING,
    }).addAlarmAction(new cwactions.SnsAction(this.topic));

    // The alarm bus: only the signer account's forwarding role puts on it,
    // and everything from that account reaches the owner.
    const forwardRole = `arn:${this.partition}:iam::${props.signerAccount}:role/${names.forwardRole}`;
    const bus = new events.EventBus(this, 'AlarmBus', { eventBusName: names.bus });
    bus.addToResourcePolicy(new iam.PolicyStatement({
      sid: 'SignerForwards', principals: [new iam.AccountPrincipal(props.signerAccount)], actions: ['events:PutEvents'],
      resources: [bus.eventBusArn], conditions: theRole(forwardRole),
    }));
    const signerAlarms = new events.Rule(this, 'SignerAlarms', {
      description: `The signer account's alarms (${envName}), forwarded from it`,
      eventBus: bus,
      // Everything but its heartbeat, which is watched below.
      eventPattern: { account: [props.signerAccount], detailType: [{ 'anything-but': ['Scheduled Event'] }] as any },
    });
    (signerAlarms.node.defaultChild as events.CfnRule).targets = [{ id: 'Topic', arn: this.topic.topicArn }];
    // The topic's policy, written out: this account's rules and alarms
    // only (a topic policy replaces the default, so without the
    // CloudWatch statement no alarm could publish).
    this.topic.addToResourcePolicy(new iam.PolicyStatement({
      sid: 'RulesOfThisAccount', principals: [new iam.ServicePrincipal('events.amazonaws.com')], actions: ['sns:Publish'],
      resources: [this.topic.topicArn], conditions: { StringEquals: { 'aws:SourceAccount': this.account } },
    }));
    this.topic.addToResourcePolicy(new iam.PolicyStatement({
      sid: 'AlarmsOfThisAccount', principals: [new iam.ServicePrincipal('cloudwatch.amazonaws.com')], actions: ['sns:Publish'],
      resources: [this.topic.topicArn], conditions: {
        StringEquals: { 'aws:SourceAccount': this.account },
        ArnLike: { 'aws:SourceArn': `arn:${this.partition}:cloudwatch:${this.region}:${this.account}:alarm:vettid-signer-audit-${envName}-*` },
      },
    }));
    // The forwarding's heartbeat: logged as it arrives; none for
    // FORWARD_QUIET_MINUTES alarms, missing data breaching. The forwarding
    // role denied, the bus policy changed, or the signer's heartbeat rule
    // removed: each stops it, and each is seen here.
    const heartbeats = new logs.LogGroup(this, 'Heartbeats', {
      retention: logs.RetentionDays.ONE_MONTH, removalPolicy: cdk.RemovalPolicy.RETAIN,
    });
    const heartbeatRule = new events.Rule(this, 'SignerHeartbeat', {
      description: `The signer account's heartbeat (${envName})`,
      eventBus: bus,
      eventPattern: { account: [props.signerAccount], source: ['aws.events'], detailType: ['Scheduled Event'] },
    });
    (heartbeatRule.node.defaultChild as events.CfnRule).targets = [{ id: 'Target0', arn: logGroupArn(heartbeats) }];
    new logs.ResourcePolicy(this, 'HeartbeatsPolicy', {
      resourcePolicyName: `vettid-signer-audit-${envName}-heartbeats`,
      policyStatements: [new iam.PolicyStatement({
        principals: [new iam.ServicePrincipal('events.amazonaws.com')],
        actions: ['logs:CreateLogStream', 'logs:PutLogEvents'],
        resources: [heartbeats.logGroupArn],
        conditions: { ArnEquals: { 'aws:SourceArn': heartbeatRule.ruleArn } },
      })],
    });
    const beats = new logs.MetricFilter(this, 'HeartbeatCount', {
      logGroup: heartbeats, filterPattern: logs.FilterPattern.allEvents(),
      metricNamespace: `VettID/SignerAudit/${envName}`, metricName: 'heartbeats', metricValue: '1',
    }).metric({ statistic: 'Sum', period: cdk.Duration.minutes(5) });
    new cloudwatch.Alarm(this, 'ForwardQuiet', {
      alarmName: `vettid-signer-audit-${envName}-forward_quiet`,
      alarmDescription: `No heartbeat from the signer account for ${FORWARD_QUIET_MINUTES} minutes: its alarms can't reach this account (the forwarding role, the bus policy or its rules changed). Expected until AnchorSigner-${envName} is deployed.`,
      metric: beats, threshold: 1, evaluationPeriods: FORWARD_QUIET_MINUTES / 5,
      comparisonOperator: cloudwatch.ComparisonOperator.LESS_THAN_THRESHOLD,
      treatMissingData: cloudwatch.TreatMissingData.BREACHING,
    }).addAlarmAction(new cwactions.SnsAction(this.topic));

    new cdk.CfnOutput(this, 'LockedCopyBucket', { value: this.bucket.bucketName });
    new cdk.CfnOutput(this, 'AlarmBusArn', { value: bus.eventBusArn });
  }
}

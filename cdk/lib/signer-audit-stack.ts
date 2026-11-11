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

/** With nothing new arriving for this many hours, the copy is stale and alarms (#7653). */
export const AUDIT_STALE_HOURS = 2;

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
 *  - a staleness watch: every object that arrives is logged here, and no
 *    arrival for AUDIT_STALE_HOURS alarms to the owner. With nothing
 *    arriving (the trail stopped, replication broken, this watch broken
 *    itself) the alarm fires: it fails loud, never quiet.
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
    this.bucket.addToResourcePolicy(new iam.PolicyStatement({
      sid: 'SignerReplicates', principals: [new iam.ArnPrincipal(replicationRole)],
      actions: ['s3:ReplicateObject'], resources: [this.bucket.arnForObjects('*')],
    }));
    this.bucket.addToResourcePolicy(new iam.PolicyStatement({
      sid: 'SignerChecksVersioning', principals: [new iam.ArnPrincipal(replicationRole)],
      actions: ['s3:GetBucketVersioning', 's3:List*'], resources: [this.bucket.bucketArn],
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
      description: `An object arrived in the signer's locked copy (${envName})`,
      eventPattern: { source: ['aws.s3'], detailType: ['Object Created'], detail: { bucket: { name: [this.bucket.bucketName] } } },
    });
    (arrivedRule.node.defaultChild as events.CfnRule).targets = [{ id: 'Target0', arn: arrivals.logGroupArn }];
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
      alarmDescription: `Nothing reached the signer's locked copy for ${AUDIT_STALE_HOURS} hours: the signer account's trail, its journal copy or replication has stopped (or this watch has)`,
      metric: arrived, threshold: 1, evaluationPeriods: AUDIT_STALE_HOURS,
      comparisonOperator: cloudwatch.ComparisonOperator.LESS_THAN_THRESHOLD,
      treatMissingData: cloudwatch.TreatMissingData.BREACHING,
    }).addAlarmAction(new cwactions.SnsAction(this.topic));

    new cdk.CfnOutput(this, 'LockedCopyBucket', { value: this.bucket.bucketName });
  }
}

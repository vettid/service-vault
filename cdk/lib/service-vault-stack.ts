import * as cdk from 'aws-cdk-lib';
import * as cloudwatch from 'aws-cdk-lib/aws-cloudwatch';
import * as cwactions from 'aws-cdk-lib/aws-cloudwatch-actions';
import * as dynamodb from 'aws-cdk-lib/aws-dynamodb';
import * as ec2 from 'aws-cdk-lib/aws-ec2';
import * as ecr from 'aws-cdk-lib/aws-ecr';
import * as ecs from 'aws-cdk-lib/aws-ecs';
import * as events from 'aws-cdk-lib/aws-events';
import * as eventTargets from 'aws-cdk-lib/aws-events-targets';
import * as iam from 'aws-cdk-lib/aws-iam';
import * as kms from 'aws-cdk-lib/aws-kms';
import * as logs from 'aws-cdk-lib/aws-logs';
import * as secretsmanager from 'aws-cdk-lib/aws-secretsmanager';
import * as servicediscovery from 'aws-cdk-lib/aws-servicediscovery';
import * as sns from 'aws-cdk-lib/aws-sns';
import * as subs from 'aws-cdk-lib/aws-sns-subscriptions';
import * as ssm from 'aws-cdk-lib/aws-ssm';
import { Construct } from 'constructs';

/** The port the daemon's private API listens on (SV_LISTEN). */
export const API_PORT = 8080;

/** The Cloud Map service name: the API is at <name>.<namespace>:API_PORT. */
export const DISCOVERY_NAME = 'service-vault';

/** Task size (MEMBER-SERVICE-PLAN §9): 0.25 vCPU / 512 MB. */
export const TASK_CPU = 256;
export const TASK_MEMORY_MIB = 512;

export const DEFAULT_RELAY_URL = 'https://relay.vettid.org';
export const DEFAULT_SERVICE_NAME = 'VettID Member Service';
export const DEFAULT_VPC_CIDR = '10.60.0.0/24';

/**
 * KMS calls on the keystore key that change who may use it, or whether it
 * works: each one raises the key_change alarm (CloudTrail via EventBridge).
 */
export const KEY_CHANGE_EVENTS = [
  'CreateGrant', 'RetireGrant', 'RevokeGrant', 'PutKeyPolicy', 'DisableKey', 'EnableKey', 'ScheduleKeyDeletion',
  'CancelKeyDeletion', 'DisableKeyRotation', 'EnableKeyRotation', 'RotateKeyOnDemand', 'UpdateKeyDescription',
  'CreateAlias', 'DeleteAlias', 'UpdateAlias', 'TagResource', 'UntagResource', 'ImportKeyMaterial', 'ReplicateKey',
];

/**
 * What the account may do with the keystore key: administer it, never
 * encrypt or decrypt with it. PutKeyPolicy stays, so the policy can be
 * corrected without AWS support.
 */
export const KEY_ADMIN_ACTIONS = [
  // CreateAlias only: kms:Create* would include CreateGrant, with which
  // any principal the account allows it could grant itself Decrypt.
  'kms:CreateAlias', 'kms:Describe*', 'kms:Enable*', 'kms:List*', 'kms:Put*', 'kms:Update*',
  'kms:Revoke*', 'kms:Disable*', 'kms:Get*', 'kms:Delete*', 'kms:TagResource', 'kms:UntagResource',
  'kms:ScheduleKeyDeletion', 'kms:CancelKeyDeletion', 'kms:RotateKeyOnDemand',
];

/**
 * Where the stack publishes what its API client's stack needs, in SSM
 * Parameter Store: `<ssmPrefix(env)>/<name>`. A client reads them at
 * deploy time, which (unlike Fn::ImportValue) never locks this stack's
 * values. The TLS pin is `<ssmPrefix(env)>/tls-pin`.
 */
export const ssmPrefix = (envName: string) => `/vettid/service-vault/${envName}`;

/** The parameters published for the API client (besides tls-pin). */
export const CLIENT_PARAMS = [
  'vpc-id',
  'public-subnet-ids',
  'security-group-id',
  'namespace-id',
  'namespace-arn',
  'namespace-name',
  'api-url',
  'webhook-secret-arn',
] as const;

/** Log lines the daemon marks for an alarm (`"alarm": <name>`). */
export const ALARMS = {
  /** A member's identity key got two successors; the connection is suspended (internal/peer/rotation.go). */
  rotate_conflict: 'A member identity rotation conflict suspended a connection (two vaults rotating, or a replayed copy; a member can also cause it on purpose, so it may be noise)',
  /** A webhook was given up after the outbox's MaxAge (internal/webhook/outbox.go): the application missed an event. */
  webhook_dropped: 'A webhook was dropped as undeliverable after 24 h: the application missed an event',
} as const;

/** The widest IPv4 prefix allowed for apiClientCidr. */
export const MIN_API_CIDR_PREFIX = 16;

/** An image reference pinned by digest, with no tag: <repository>@sha256:<64 hex>. */
const DIGEST_IMAGE = /^([a-z0-9.-]+(?::[0-9]+)?\/[a-z0-9._\/-]+)@(sha256:[0-9a-f]{64})$/;
/** A private ECR repository URI: <account>.dkr.ecr.<region>.amazonaws.com/<name>. */
const ECR_REPO = /^([0-9]{12})\.dkr\.ecr\.([a-z0-9-]+)\.amazonaws\.com\/(.+)$/;

export interface ServiceVaultStackProps extends cdk.StackProps {
  /** Environment name (e.g. `prod`, `staging`): part of every resource name and export. */
  readonly envName: string;
  /** Container image pinned by digest, never by tag (ECR or GHCR). */
  readonly image: string;
  /** Where the application receives signed webhooks (SV_WEBHOOK_URL). */
  readonly webhookUrl: string;
  /** The relay the service vault uses (SV_RELAY_URL). */
  readonly relayUrl?: string;
  /** The service's display name, shown to members (SV_SERVICE_NAME). */
  readonly serviceName?: string;
  /** Security group of the API's client (the member API task); allowed on API_PORT. */
  readonly apiClientSecurityGroupId?: string;
  /** Or an IPv4 CIDR allowed on API_PORT, /16 or narrower (MIN_API_CIDR_PREFIX). */
  readonly apiClientCidr?: string;
  /** The VPC's CIDR (two /26 public subnets are carved from it). */
  readonly vpcCidr?: string;
  /**
   * The first admin's email (SV_ADMIN_BOOTSTRAP_EMAIL): the connection bound
   * to it (from an invitation with a verified email) becomes the first
   * admin, once; the bootstrap is one-shot and recorded in the table
   * (README "Admin approvals"). Plain text in the task definition, kept in
   * its revisions after a redeploy without it.
   */
  readonly adminBootstrapEmail?: string;
  /** How many distinct admins must approve (SV_ADMIN_THRESHOLD; default 1). */
  readonly adminThreshold?: number;
  /** How long an approval stays open, a Go duration such as `24h` (SV_APPROVAL_TTL). */
  readonly approvalTtl?: string;
  /**
   * Where the alarms go; exactly one is required, so that an alarm always
   * reaches a person: an existing SNS topic (staging: vettid.org's vault
   * alerts topic, /vettid-org/staging/vault/alerts-topic-arn), or an
   * address for a topic of this stack's own (confirm the subscription
   * from the email AWS sends).
   */
  readonly alarmTopicArn?: string;
  readonly alarmEmail?: string;
  /**
   * The one deploy that upgrades a deployment from before records were
   * sealed: SV_RECORD_SEAL_MIGRATE=1 seals the existing records in place
   * at start (README "Records at rest"). Deploy again without it after.
   */
  readonly recordSealMigrate?: boolean;
}

/**
 * The VettID service vault on one ARM64 Fargate Spot task
 * (MEMBER-SERVICE-PLAN §9).
 *
 *  - Network: public subnets in two AZs, no NAT gateway, the free DynamoDB
 *    gateway endpoint and no interface endpoints. The task has a public IP
 *    for its outbound calls (relay, KMS, Secrets Manager, logs, image pull)
 *    and a security group that admits nothing from the internet.
 *  - API: private. No load balancer: the API's client (the member API, a
 *    task in this VPC) finds the task through Cloud Map private DNS and is
 *    the only security group allowed on the API port. Every /v1 route
 *    also requires an API key.
 *  - Data: one DynamoDB table (pk/sk) and one KMS key for the keystore's
 *    envelope encryption, both retained when the stack is deleted.
 */
export class ServiceVaultStack extends cdk.Stack {
  readonly vpc: ec2.Vpc;
  readonly securityGroup: ec2.SecurityGroup;
  readonly namespace: servicediscovery.PrivateDnsNamespace;
  readonly table: dynamodb.Table;
  readonly key: kms.Key;
  readonly service: ecs.FargateService;

  constructor(scope: Construct, id: string, props: ServiceVaultStackProps) {
    super(scope, id, props);
    const envName = props.envName;
    if (!/^[a-z][a-z0-9-]{0,15}$/.test(envName)) {
      throw new Error(`envName must be lowercase letters, digits and hyphens (got "${envName}")`);
    }
    const image = DIGEST_IMAGE.exec(props.image);
    if (!image) {
      throw new Error(`image must be <repository>@sha256:<digest> with no tag (got "${props.image}")`);
    }
    if (!/^https:\/\//.test(props.webhookUrl)) {
      throw new Error(`webhookUrl must be an https:// URL (got "${props.webhookUrl}")`);
    }
    const relayUrl = props.relayUrl ?? DEFAULT_RELAY_URL;
    if (!/^https:\/\//.test(relayUrl)) {
      throw new Error(`relayUrl must be an https:// URL (got "${relayUrl}")`);
    }
    if (props.apiClientCidr !== undefined) {
      const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\/(\d{1,2})$/.exec(props.apiClientCidr);
      if (!m || m.slice(1, 5).some((o) => Number(o) > 255) || Number(m[5]) > 32) {
        throw new Error(`apiClientCidr must be an IPv4 CIDR such as 203.0.113.7/32 (got "${props.apiClientCidr}")`);
      }
      if (Number(m[5]) < MIN_API_CIDR_PREFIX) {
        throw new Error(`apiClientCidr must not be open to the internet: a prefix of /${MIN_API_CIDR_PREFIX} or longer (got "${props.apiClientCidr}")`);
      }
      // The task has a public IP: a public range would reach the API port
      // from the internet. Private ranges only (RFC 1918).
      const [a, b] = [Number(m[1]), Number(m[2])];
      if (!(a === 10 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168))) {
        throw new Error(`apiClientCidr must be a private (RFC 1918) range: the task has a public IP (got "${props.apiClientCidr}")`);
      }
    }
    if (props.adminThreshold !== undefined && !(Number.isInteger(props.adminThreshold) && props.adminThreshold >= 1 && props.adminThreshold <= 64)) {
      throw new Error(`adminThreshold must be an integer from 1 to 64 (got ${props.adminThreshold})`);
    }
    if (props.approvalTtl !== undefined && !/^([0-9]+(h|m|s))+$/.test(props.approvalTtl)) {
      throw new Error(`approvalTtl must be a duration such as 24h (got "${props.approvalTtl}")`);
    }
    if (!props.alarmTopicArn === !props.alarmEmail) {
      throw new Error('set exactly one of alarmTopicArn and alarmEmail: the alarms must reach a person');
    }
    if (props.alarmTopicArn && !/^arn:aws[a-z-]*:sns:[a-z0-9-]+:[0-9]{12}:[A-Za-z0-9_-]+$/.test(props.alarmTopicArn)) {
      throw new Error(`alarmTopicArn must be an SNS topic ARN (got "${props.alarmTopicArn}")`);
    }
    if (props.alarmEmail && !/^[^@\s]+@[a-z0-9.-]+\.[a-z]+$/.test(props.alarmEmail)) {
      throw new Error(`alarmEmail must be an address (got "${props.alarmEmail}")`);
    }
    const approvalEnv: Record<string, string> = {};
    if (props.adminBootstrapEmail) approvalEnv.SV_ADMIN_BOOTSTRAP_EMAIL = props.adminBootstrapEmail;
    if (props.adminThreshold !== undefined) approvalEnv.SV_ADMIN_THRESHOLD = String(props.adminThreshold);
    if (props.approvalTtl) approvalEnv.SV_APPROVAL_TTL = props.approvalTtl;
    const prefix = `vettid-service-vault-${envName}`;
    const exportPrefix = `ServiceVault-${envName}`;

    // ---- Network ---------------------------------------------------------
    this.vpc = new ec2.Vpc(this, 'Vpc', {
      ipAddresses: ec2.IpAddresses.cidr(props.vpcCidr ?? DEFAULT_VPC_CIDR),
      maxAzs: 2,
      natGateways: 0,
      subnetConfiguration: [{ name: 'public', subnetType: ec2.SubnetType.PUBLIC, cidrMask: 26 }],
      gatewayEndpoints: {
        DynamoDB: { service: ec2.GatewayVpcEndpointAwsService.DYNAMODB },
      },
    });

    // Egress only, and only HTTPS: everything the task calls (relay, AWS
    // APIs, the image registry, the webhook URL) is on 443. DNS uses the
    // VPC resolver, which security groups do not filter.
    this.securityGroup = new ec2.SecurityGroup(this, 'TaskSg', {
      vpc: this.vpc,
      description: 'service vault task: HTTPS out; API only from its client',
      allowAllOutbound: false,
    });
    this.securityGroup.addEgressRule(ec2.Peer.anyIpv4(), ec2.Port.tcp(443), 'HTTPS out');
    if (props.apiClientSecurityGroupId) {
      this.securityGroup.addIngressRule(
        ec2.Peer.securityGroupId(props.apiClientSecurityGroupId),
        ec2.Port.tcp(API_PORT),
        'private API from its client',
      );
    }
    if (props.apiClientCidr) {
      this.securityGroup.addIngressRule(ec2.Peer.ipv4(props.apiClientCidr), ec2.Port.tcp(API_PORT), 'private API from its client');
    }

    this.namespace = new servicediscovery.PrivateDnsNamespace(this, 'Namespace', {
      name: `${envName}.vettid.internal`,
      vpc: this.vpc,
      description: 'VettID service vault: private service discovery',
    });

    // ---- Data ------------------------------------------------------------
    this.table = new dynamodb.Table(this, 'Table', {
      tableName: prefix,
      partitionKey: { name: 'pk', type: dynamodb.AttributeType.STRING },
      sortKey: { name: 'sk', type: dynamodb.AttributeType.STRING },
      billingMode: dynamodb.BillingMode.PAY_PER_REQUEST,
      // Records that end (dedupe markers, cached responses, finished
      // invitations and sign-ins, spent tokens) carry their expiry here.
      timeToLiveAttribute: 'ttl',
      pointInTimeRecoverySpecification: { pointInTimeRecoveryEnabled: true },
      deletionProtection: true,
      removalPolicy: cdk.RemovalPolicy.RETAIN,
    });

    // The keystore's envelope key: GenerateDataKey wraps each stored
    // private key's data key, Decrypt unwraps it. Its policy replaces the
    // default (the account root with kms:*, which lets any principal the
    // account grants kms:Decrypt on * unwrap the keystore): the account
    // administers the key, and only the task role (below) uses it.
    this.key = new kms.Key(this, 'KeystoreKey', {
      alias: `alias/${prefix}-keystore`,
      description: 'VettID service vault: keystore envelope encryption',
      enableKeyRotation: true,
      removalPolicy: cdk.RemovalPolicy.RETAIN,
      policy: new iam.PolicyDocument({
        statements: [
          new iam.PolicyStatement({
            sid: 'Administer',
            principals: [new iam.AccountRootPrincipal()],
            actions: KEY_ADMIN_ACTIONS,
            resources: ['*'],
          }),
        ],
      }),
    });

    // Values are never in code: generated here, replaced by the operator
    // (README "Deployment"). A 64-hex placeholder for the API key hashes
    // has no known preimage, so no key is accepted until it is replaced.
    const apiKeyHashes = new secretsmanager.Secret(this, 'ApiKeyHashes', {
      secretName: `${prefix}/api-key-hashes`,
      description: 'Comma-separated hex SHA-256 of the accepted API keys (SV_API_KEY_HASHES)',
      generateSecretString: {
        passwordLength: 64,
        excludePunctuation: true,
        excludeUppercase: true,
        excludeCharacters: 'ghijklmnopqrstuvwxyz',
        includeSpace: false,
        requireEachIncludedType: false,
      },
      removalPolicy: cdk.RemovalPolicy.RETAIN,
    });
    const webhookSecret = new secretsmanager.Secret(this, 'WebhookSecret', {
      secretName: `${prefix}/webhook-secret`,
      description: 'Webhook signing secret shared with the application (SV_WEBHOOK_SECRET)',
      generateSecretString: { passwordLength: 64, excludePunctuation: true, includeSpace: false },
      removalPolicy: cdk.RemovalPolicy.RETAIN,
    });

    // The private API's TLS key pin ("sha256/…" of its SubjectPublicKeyInfo).
    // The daemon writes it at start from the key in its keystore; the
    // application's client reads it and accepts only that key. "unset" until
    // the first start.
    const tlsPin = new ssm.StringParameter(this, 'TlsPin', {
      parameterName: `${ssmPrefix(envName)}/tls-pin`,
      description: 'SHA-256 SPKI pin of the service vault private API key (SV_TLS_PIN_PARAM)',
      stringValue: 'unset',
      tier: ssm.ParameterTier.STANDARD,
    });

    // ---- Compute ---------------------------------------------------------
    const cluster = new ecs.Cluster(this, 'Cluster', {
      clusterName: prefix,
      vpc: this.vpc,
      containerInsightsV2: ecs.ContainerInsights.DISABLED,
      enableFargateCapacityProviders: true,
    });

    const taskDef = new ecs.FargateTaskDefinition(this, 'Task', {
      cpu: TASK_CPU,
      memoryLimitMiB: TASK_MEMORY_MIB,
      runtimePlatform: { cpuArchitecture: ecs.CpuArchitecture.ARM64, operatingSystemFamily: ecs.OperatingSystemFamily.LINUX },
    });
    this.table.grantReadWriteData(taskDef.taskRole);
    taskDef.taskRole.addToPrincipalPolicy(
      new iam.PolicyStatement({
        sid: 'KeystoreKey',
        actions: ['kms:GenerateDataKey', 'kms:Decrypt'],
        resources: [this.key.keyArn],
      }),
    );
    this.key.addToResourcePolicy(
      new iam.PolicyStatement({
        sid: 'TaskUse',
        principals: [new iam.ArnPrincipal(taskDef.taskRole.roleArn)],
        actions: ['kms:GenerateDataKey', 'kms:Decrypt'],
        resources: ['*'],
      }),
    );
    taskDef.taskRole.addToPrincipalPolicy(
      new iam.PolicyStatement({
        sid: 'PublishTlsPin',
        actions: ['ssm:PutParameter'],
        resources: [tlsPin.parameterArn],
      }),
    );

    const logGroup = new logs.LogGroup(this, 'Logs', {
      logGroupName: `/vettid/service-vault/${envName}`,
      retention: logs.RetentionDays.ONE_MONTH,
      removalPolicy: cdk.RemovalPolicy.RETAIN,
    });

    const [, repository, digest] = image;
    const ecrRepo = ECR_REPO.exec(repository);
    const containerImage = ecrRepo
      ? ecs.ContainerImage.fromEcrRepository(
          ecr.Repository.fromRepositoryAttributes(this, 'Repository', {
            repositoryName: ecrRepo[3],
            repositoryArn: `arn:${this.partition}:ecr:${ecrRepo[2]}:${ecrRepo[1]}:repository/${ecrRepo[3]}`,
          }),
          digest,
        )
      : ecs.ContainerImage.fromRegistry(props.image);

    // No Linux capabilities: the daemon needs none (an unprivileged port,
    // a non-root user).
    const linuxParameters = new ecs.LinuxParameters(this, 'Linux');
    linuxParameters.dropCapabilities(ecs.Capability.ALL);
    taskDef.addContainer('ServiceVault', {
      image: containerImage,
      essential: true,
      linuxParameters,
      portMappings: [{ containerPort: API_PORT }],
      readonlyRootFilesystem: true,
      environment: {
        SV_RELAY_URL: relayUrl,
        SV_TABLE: this.table.tableName,
        SV_KMS_KEY_ID: this.key.keyArn,
        SV_LISTEN: `:${API_PORT}`,
        SV_WEBHOOK_URL: props.webhookUrl,
        SV_SERVICE_NAME: props.serviceName ?? DEFAULT_SERVICE_NAME,
        SV_TLS_PIN_PARAM: tlsPin.parameterName,
        SV_TLS_NAME: `${DISCOVERY_NAME}.${this.namespace.namespaceName}`,
        AWS_REGION: this.region,
        ...approvalEnv,
        ...(props.recordSealMigrate ? { SV_RECORD_SEAL_MIGRATE: '1' } : {}),
      },
      secrets: {
        SV_API_KEY_HASHES: ecs.Secret.fromSecretsManager(apiKeyHashes),
        SV_WEBHOOK_SECRET: ecs.Secret.fromSecretsManager(webhookSecret),
      },
      logging: ecs.LogDrivers.awsLogs({ logGroup, streamPrefix: 'service-vault' }),
      stopTimeout: cdk.Duration.seconds(30),
      // The image has no shell: the binary probes its own GET /health.
      healthCheck: {
        command: ['CMD', '/service-vault', 'healthcheck'],
        interval: cdk.Duration.seconds(30),
        timeout: cdk.Duration.seconds(5),
        retries: 3,
        startPeriod: cdk.Duration.seconds(30),
      },
    });

    // One Spot task. ECS does not fall back from FARGATE_SPOT to FARGATE
    // on its own, so the strategy is Spot only: a reclaimed task is
    // replaced by a new Spot task (its state is all in DynamoDB). Deploys
    // stop the old task before starting the new one (min 0 / max 100).
    // That is best effort: a task that is stopping (SIGTERM, up to
    // stopTimeout) can overlap its replacement, as can a Spot
    // reclamation. The daemon tolerates it: SIGTERM stops its loops at
    // once; the peer's writes are conditional on the version it read, so
    // a second writer's change makes a flush fail and that peer exit
    // rather than overwrite (ECS then starts it again from the table);
    // relay messages are deduplicated by id; webhooks are at least once.
    this.service = new ecs.FargateService(this, 'Service', {
      serviceName: prefix,
      cluster,
      taskDefinition: taskDef,
      desiredCount: 1,
      minHealthyPercent: 0,
      maxHealthyPercent: 100,
      circuitBreaker: { enable: true, rollback: true },
      capacityProviderStrategies: [{ capacityProvider: 'FARGATE_SPOT', weight: 1 }],
      assignPublicIp: true,
      securityGroups: [this.securityGroup],
      vpcSubnets: { subnetType: ec2.SubnetType.PUBLIC },
      enableExecuteCommand: false,
      cloudMapOptions: {
        name: DISCOVERY_NAME,
        cloudMapNamespace: this.namespace,
        dnsRecordType: servicediscovery.DnsRecordType.A,
        dnsTtl: cdk.Duration.seconds(10),
      },
    });

    // ---- Alarms ---------------------------------------------------------------
    let topic: sns.ITopic;
    if (props.alarmTopicArn) {
      topic = sns.Topic.fromTopicArn(this, 'AlarmTopic', props.alarmTopicArn);
    } else {
      const own = new sns.Topic(this, 'AlarmTopic', { displayName: `VettID service vault alarms (${envName})` });
      own.addSubscription(new subs.EmailSubscription(props.alarmEmail!));
      topic = own;
    }
    const notify = (alarm: cloudwatch.Alarm) => alarm.addAlarmAction(new cwactions.SnsAction(topic));
    for (const [name, description] of Object.entries(ALARMS)) {
      const metric = new logs.MetricFilter(this, `Alarm-${name}`, {
        logGroup,
        filterPattern: logs.FilterPattern.stringValue('$.alarm', '=', name),
        metricNamespace: `VettID/ServiceVault/${envName}`,
        metricName: name,
        metricValue: '1',
      }).metric({ statistic: 'Sum', period: cdk.Duration.minutes(5) });
      notify(new cloudwatch.Alarm(this, `Alarm-${name}-alarm`, {
        alarmName: `${prefix}-${name}`,
        alarmDescription: description,
        metric,
        threshold: 1,
        evaluationPeriods: 1,
        comparisonOperator: cloudwatch.ComparisonOperator.GREATER_THAN_OR_EQUAL_TO_THRESHOLD,
        treatMissingData: cloudwatch.TreatMissingData.NOT_BREACHING,
      }));
    }
    // Key changes: CloudTrail's KMS management events for the keystore key
    // (an organization or account trail delivers them to EventBridge) go
    // to a log group of their own, kept a year, and any of them alarms.
    const keyEvents = new logs.LogGroup(this, 'KeyEvents', {
      retention: logs.RetentionDays.ONE_YEAR,
      removalPolicy: cdk.RemovalPolicy.RETAIN,
    });
    new events.Rule(this, 'KeyChangeRule', {
      description: 'KMS calls that change the service vault keystore key (key_change alarm)',
      eventPattern: {
        source: ['aws.kms'],
        detailType: ['AWS API Call via CloudTrail'],
        detail: { eventName: KEY_CHANGE_EVENTS, resources: { ARN: [this.key.keyArn] } },
      },
      targets: [new eventTargets.CloudWatchLogGroup(keyEvents)],
    });
    const keyChanges = new logs.MetricFilter(this, 'Alarm-key_change', {
      logGroup: keyEvents,
      filterPattern: logs.FilterPattern.allEvents(),
      metricNamespace: `VettID/ServiceVault/${envName}`,
      metricName: 'key_change',
      metricValue: '1',
    }).metric({ statistic: 'Sum', period: cdk.Duration.minutes(5) });
    notify(new cloudwatch.Alarm(this, 'Alarm-key_change-alarm', {
      alarmName: `${prefix}-key_change`,
      alarmDescription: 'The keystore KMS key was changed: a grant, its policy, disabled, or scheduled for deletion',
      metric: keyChanges,
      threshold: 1,
      evaluationPeriods: 1,
      comparisonOperator: cloudwatch.ComparisonOperator.GREATER_THAN_OR_EQUAL_TO_THRESHOLD,
      treatMissingData: cloudwatch.TreatMissingData.NOT_BREACHING,
    }));

    // Down: ECS reports the service's CPU every minute while a task runs
    // (without Container Insights too); no data for 10 minutes means no
    // task (a Spot reclamation is replaced in a minute or two).
    notify(new cloudwatch.Alarm(this, 'Alarm-down', {
      alarmName: `${prefix}-down`,
      alarmDescription: 'No service vault task has run for 10 minutes: sign-ins, connects and approvals fail',
      metric: this.service.metricCpuUtilization({ statistic: 'SampleCount', period: cdk.Duration.minutes(5) }),
      threshold: 1,
      evaluationPeriods: 2,
      comparisonOperator: cloudwatch.ComparisonOperator.LESS_THAN_THRESHOLD,
      treatMissingData: cloudwatch.TreatMissingData.BREACHING,
    }));

    // ---- Exports (the member-service stack reads the SSM parameters below) --
    const out = (id: string, value: string, description: string) =>
      new cdk.CfnOutput(this, id, { value, description, exportName: `${exportPrefix}-${id}` });
    out('VpcId', this.vpc.vpcId, 'VPC the API client runs in');
    out('PublicSubnetIds', cdk.Fn.join(',', this.vpc.publicSubnets.map((s) => s.subnetId)), 'Public subnets for the API client task');
    out('SecurityGroupId', this.securityGroup.securityGroupId, 'Service vault task security group (add ingress on the API port from the client)');
    out('NamespaceId', this.namespace.namespaceId, 'Cloud Map private DNS namespace id');
    out('NamespaceArn', this.namespace.namespaceArn, 'Cloud Map private DNS namespace ARN');
    out('NamespaceName', this.namespace.namespaceName, 'Cloud Map private DNS namespace name');
    out('ApiUrl', `https://${DISCOVERY_NAME}.${this.namespace.namespaceName}:${API_PORT}`, 'Private API base URL (TLS 1.3, key pinned)');
    out('TlsPinParameterName', tlsPin.parameterName, 'SSM parameter holding the private API key pin');
    out('TlsPinParameterArn', tlsPin.parameterArn, 'SSM parameter holding the private API key pin (grant ssm:GetParameter to the client)');
    out('WebhookSecretArn', webhookSecret.secretArn, 'Webhook signing secret (the application verifies with it)');

    // ---- The same, in SSM for the client's stack ---------------------------
    // The exports above stay for whoever uses them; a client stack should
    // read these instead, so that this stack can change a value later.
    const apiUrl = `https://${DISCOVERY_NAME}.${this.namespace.namespaceName}:${API_PORT}`;
    const params: Record<(typeof CLIENT_PARAMS)[number], [string, string]> = {
      'vpc-id': [this.vpc.vpcId, 'VPC the API client runs in'],
      'public-subnet-ids': [cdk.Fn.join(',', this.vpc.publicSubnets.map((s) => s.subnetId)), 'Public subnets for the API client task (comma-separated)'],
      'security-group-id': [this.securityGroup.securityGroupId, 'Service vault task security group (the client adds ingress on the API port)'],
      'namespace-id': [this.namespace.namespaceId, 'Cloud Map private DNS namespace id'],
      'namespace-arn': [this.namespace.namespaceArn, 'Cloud Map private DNS namespace ARN'],
      'namespace-name': [this.namespace.namespaceName, 'Cloud Map private DNS namespace name'],
      'api-url': [apiUrl, 'Private API base URL (TLS 1.3, key pinned)'],
      'webhook-secret-arn': [webhookSecret.secretArn, 'Webhook signing secret (the application verifies with it)'],
    };
    for (const [name, [value, description]] of Object.entries(params)) {
      new ssm.StringParameter(this, `Param-${name}`, {
        parameterName: `${ssmPrefix(envName)}/${name}`,
        stringValue: value,
        description: `VettID service vault (${envName}): ${description}`,
        tier: ssm.ParameterTier.STANDARD,
      });
    }
  }
}

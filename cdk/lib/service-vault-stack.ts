import * as cdk from 'aws-cdk-lib';
import * as dynamodb from 'aws-cdk-lib/aws-dynamodb';
import * as ec2 from 'aws-cdk-lib/aws-ec2';
import * as ecr from 'aws-cdk-lib/aws-ecr';
import * as ecs from 'aws-cdk-lib/aws-ecs';
import * as iam from 'aws-cdk-lib/aws-iam';
import * as kms from 'aws-cdk-lib/aws-kms';
import * as logs from 'aws-cdk-lib/aws-logs';
import * as secretsmanager from 'aws-cdk-lib/aws-secretsmanager';
import * as servicediscovery from 'aws-cdk-lib/aws-servicediscovery';
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
  /** Or a CIDR allowed on API_PORT (never 0.0.0.0/0 or ::/0). */
  readonly apiClientCidr?: string;
  /** The VPC's CIDR (two /26 public subnets are carved from it). */
  readonly vpcCidr?: string;
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
    if (props.apiClientCidr !== undefined && /\/0$/.test(props.apiClientCidr)) {
      throw new Error('apiClientCidr must not be open to the internet');
    }
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
      pointInTimeRecoverySpecification: { pointInTimeRecoveryEnabled: true },
      deletionProtection: true,
      removalPolicy: cdk.RemovalPolicy.RETAIN,
    });

    // The keystore's envelope key: GenerateDataKey wraps each stored
    // private key's data key, Decrypt unwraps it.
    this.key = new kms.Key(this, 'KeystoreKey', {
      alias: `alias/${prefix}-keystore`,
      description: 'VettID service vault: keystore envelope encryption',
      enableKeyRotation: true,
      removalPolicy: cdk.RemovalPolicy.RETAIN,
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

    taskDef.addContainer('ServiceVault', {
      image: containerImage,
      essential: true,
      portMappings: [{ containerPort: API_PORT }],
      readonlyRootFilesystem: true,
      environment: {
        SV_RELAY_URL: relayUrl,
        SV_TABLE: this.table.tableName,
        SV_KMS_KEY_ID: this.key.keyArn,
        SV_LISTEN: `:${API_PORT}`,
        SV_WEBHOOK_URL: props.webhookUrl,
        SV_SERVICE_NAME: props.serviceName ?? DEFAULT_SERVICE_NAME,
        AWS_REGION: this.region,
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
    // stop the old task before starting the new one (min 0 / max 100), so
    // there is never more than one task holding the relay mailboxes.
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

    // ---- Exports for the member-service stack ---------------------------
    const out = (id: string, value: string, description: string) =>
      new cdk.CfnOutput(this, id, { value, description, exportName: `${exportPrefix}-${id}` });
    out('VpcId', this.vpc.vpcId, 'VPC the API client runs in');
    out('PublicSubnetIds', cdk.Fn.join(',', this.vpc.publicSubnets.map((s) => s.subnetId)), 'Public subnets for the API client task');
    out('SecurityGroupId', this.securityGroup.securityGroupId, 'Service vault task security group (add ingress on the API port from the client)');
    out('NamespaceId', this.namespace.namespaceId, 'Cloud Map private DNS namespace id');
    out('NamespaceArn', this.namespace.namespaceArn, 'Cloud Map private DNS namespace ARN');
    out('NamespaceName', this.namespace.namespaceName, 'Cloud Map private DNS namespace name');
    out('ApiUrl', `http://${DISCOVERY_NAME}.${this.namespace.namespaceName}:${API_PORT}`, 'Private API base URL');
    out('WebhookSecretArn', webhookSecret.secretArn, 'Webhook signing secret (the application verifies with it)');
  }
}

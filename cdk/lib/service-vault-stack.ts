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
import { KEY_ADMIN_ACTIONS } from './kms-actions';

/** The port the daemon's private API listens on (SV_LISTEN). */
export const API_PORT = 8080;

/**
 * DynamoDB actions of the task role, on the table only. ConditionCheckItem
 * is for the guarded ballot write, whose transaction checks the proposal's
 * version in this table (IAM authorises each item of a transaction).
 */
export const TABLE_ACTIONS = ['GetItem', 'PutItem', 'UpdateItem', 'DeleteItem', 'Query', 'Scan', 'ConditionCheckItem'] as const;

/**
 * The calls the daemon makes on the ballots table: a conditional put, a
 * get, a query and a scan (the start's key check looks for any ballot):
 * no update and no delete (BALLOT-PROTOCOL §6 "Durability"). IAM can't
 * require the put's condition; the daemon sets it.
 */
export const BALLOTS_TABLE_ACTIONS = ['GetItem', 'PutItem', 'Query', 'Scan'] as const;

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

export { KEY_ADMIN_ACTIONS } from './kms-actions';

/**
 * Where the stack publishes what its API client's stack needs, in SSM
 * Parameter Store: `<ssmPrefix(env)>/<name>`. A client reads them at
 * deploy time, which (unlike Fn::ImportValue) never locks this stack's
 * values. The TLS pin is `<ssmPrefix(env)>/tls-pin`.
 */
export const ssmPrefix = (envName: string) => `/vettid/service-vault/${envName}`;

/**
 * The marker that the anchor key has moved to the AnchorSigner (key
 * protection, GC #7406 §7 step 1): created by the owner at the cutover,
 * never by this stack; the task reads it.
 */
export const anchorMovedParameterName = (envName: string) => `${ssmPrefix(envName)}/anchor_key_moved`;

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
  /** Fork evidence about an epoch (rule E, fork by ctx; internal/peer/forks.go): a connection is suspended. */
  fork_suspected: 'Fork evidence about a session epoch suspended a connection: a second or old copy of the member vault used it (README "fork_suspected")',
  /** A connection a relay.address.update moved before the update was refused (internal/peer/state.go): marked stale at start. */
  relay_moved_unlinked: 'A connection that a relay.address.update moved before such updates were refused was marked stale at start: the address may belong to a copy; the member must connect again (README "relay_moved_unlinked")',
  /** A webhook was given up after the outbox's MaxAge (internal/webhook/outbox.go): the application missed an event. */
  webhook_dropped: 'A webhook was dropped as undeliverable after 24 h: the application missed an event',
  /** A stored outgoing hs.init names another identity key than the service's (internal/peer/state.go): dropped at start. */
  outgoing_identity_changed: 'A stored handshake names another identity key than this service\'s: it was dropped at start. The service never rotates its key, so its keys or secrets are wrong, or the table is another service\'s (README "outgoing_identity_changed")',
  /** A reconnect after a restore could not complete (internal/peer/reconnect.go): the member must connect again. */
  reconnect_failed: 'A reconnect after a table restore failed: that member must connect again from a new invitation (README "Restoring the table")',
  /** A reconnect after a restore unanswered for a day (internal/peer/reconnect.go): the member's vault may be locked. */
  reconnect_slow: 'A reconnect after a table restore is unanswered after a day: the member\'s vault may be locked; it stays open for 7 days',
  /** The ballot copy's key is missing or not the copy's (cmd/service-vault ballotCopySeal): votes are off, the rest runs. */
  ballots_off: 'Ballots are off: the ballot copy\'s key is missing or not the one its ballots are under; restore the keystore item ballot-copy-key from a backup of the table (README "Rotating the record key")',
  /** A vote request or a close for a proposal held but not published (internal/ballot/box.go, close.go): members get no answer and it can't close until it is published. */
  vote_unpublished: 'Members sent vote requests for a proposal the service holds but has not published (after a restore or a lost publication), or its close was refused: they get no answer until it is published (POST /v1/proposals/{id}/publish): publish at once, and extend the vote too if its close is less than about 70 minutes away (README "vote_unpublished")',
  /** A proposal's stored member chunks are missing or not the ones its record names (internal/ballot/store.go): the vote can't go on. */
  vote_chunk_missing: 'A proposal\'s stored members are missing or changed in the table: its casts, status, close, publication and extension all fail until the table is restored (README "vote_chunk_missing")',
  /** The vote's close passed by the service's clock but not the timestamp authority's (internal/ballot/close.go): not counted yet. */
  count_clock_ahead: 'A vote\'s close has passed by the service\'s clock but not by the timestamp authority\'s: the service\'s clock is ahead. The vote is not counted (still collecting) until the authority\'s time passes the close; check both clocks (README "count_clock_ahead")',
  /** The timestamp authority's time couldn't be had or verified before a count (internal/ballot/close.go): the vote is not counted. */
  tsa_unavailable: 'Before counting a vote, the service could not get or verify the timestamp authority\'s time: the vote is not counted until it can (README "count_clock_ahead"); look at the ERROR line for why',
  /** The results' bundle was timestamped before the close (internal/publish/publish.go): not published; the clock is ahead of the timestamp authority's. */
  results_stamped_early: 'A vote\'s results were timestamped before their close: the service\'s clock is more than a minute ahead of the timestamp authority\'s. They are not published; check both clocks (the task\'s and the authority\'s), then close again (POST /v1/proposals/{id}/close) (README "results_stamped_early")',
  /** The results' bundle failed its timestamp check (internal/publish/publish.go): not published. */
  results_bundle_unverified: 'A vote\'s results bundle failed its timestamp check (TSA signature, trusted root or validity): the results are not published; look at the ERROR line, then close again (README "results_bundle_unverified")',
  /** The anchor signer doesn't answer the background probe (cmd/service-vault anchorsource.go): documents wait, calls are retried. */
  anchor_signer_unavailable: 'The anchor signer does not answer the service\'s probe: documents are not published until it does (calls fail and are retried); sign-ins and approvals go on. Check the signer (its account\'s alarms) and the invoke permission (README "anchor_signer_unavailable")',
  /** The anchor signer answered under a key other than the one listed (internal/publish/signer.go): nothing is kept from that answer. */
  anchor_key_changed: 'The anchor signer answered under another anchor key than the pinned one (SV_ANCHOR_KEY): nothing from that answer is used. Treat it as a security event: check the signer account and its key (README "anchor_key_changed")',
  /** The signer returned a bundle not signed by the pinned key over the document (internal/publish/signer.go): not kept. */
  signer_bundle_unverified: 'The anchor signer returned a bundle whose signature is not the pinned anchor key\'s over the document: it is not kept, and the document is not taken as published. Treat it as a security event (README "signer_bundle_unverified")',
  /** A stored ballot failed the count's re-check and was left out (internal/ballot/close.go): the results may differ from what members were told. */
  ballot_not_counted: 'A stored ballot was not counted: it failed the count\'s re-check (tag, credential signature or time); look at the ERROR line for the proposal and tag',
  /** An admin's governance key can't be pinned yet: the peer doesn't know the admin's connection (internal/approval/approval.go, a WARN, at most hourly per admin). Until it can, that admin's governance approvals don't count. */
  gov_migration_waiting: 'An admin\'s governance key is not pinned yet because the service doesn\'t know that admin\'s connection: their governance approvals (admin set, re-pin, proposals, extensions, contract templates) don\'t count until it does (README "gov_migration_waiting")',
  /** A removed connection left fewer admins than the threshold (internal/approval/approval.go): no approval can pass. */
  admins_short: 'An admin connection was removed and fewer admins than the threshold remain: no approval can pass until the operator recovers the set (README "Recovering admins")',
} as const;

/**
 * ECS stop codes of the service's own doing (a deploy, a scale-in, a
 * Spot reclamation, an operator's stop): any other stop, or one for a
 * failed health check, raises task_stopped.
 */
export const EXPECTED_STOP_CODES = ['ServiceSchedulerInitiated', 'SpotInterruption', 'UserInitiated'];

/** ERROR lines (not marked for an alarm of their own) in 15 minutes that raise errors. */
export const ERROR_THRESHOLD = 5;

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
  /** votes.vettid.org (or staging's), where vote documents are published;
   * without it no proposal can be created (SV_VOTES_URL). */
  readonly votesUrl?: string;
  /** The relay the service vault uses (SV_RELAY_URL). */
  readonly relayUrl?: string;
  /** The service's display name, shown to members (SV_SERVICE_NAME). */
  readonly serviceName?: string;
  /** Security group of the API's client (the member API task); allowed on API_PORT. */
  readonly apiClientSecurityGroupId?: string;
  /** Or an IPv4 CIDR allowed on API_PORT, /16 or narrower (MIN_API_CIDR_PREFIX), private (RFC 1918). */
  readonly apiClientCidr?: string;
  /**
   * Allow apiClientCidr to be one public address (/32): an operator's
   * direct access to the API, which is then reachable from that address
   * on the internet (still behind the pinned TLS key and an API key).
   */
  readonly apiClientCidrPublic?: boolean;
  /** The VPC's CIDR (two /26 public subnets are carved from it). */
  readonly vpcCidr?: string;
  /**
   * The first admin's email (SV_ADMIN_BOOTSTRAP_EMAIL): the connection bound
   * to it (from an invitation with a verified email) waits for the
   * operator to confirm it with `service-vault admin bootstrap -connection
   * -fingerprint`, and only then becomes the first admin, once; the
   * bootstrap is one-shot and recorded in the table (README "Admin
   * approvals"). Plain text in the task definition, kept in
   * its revisions after a redeploy without it.
   */
  readonly adminBootstrapEmail?: string;
  /** How many distinct admins must approve (SV_ADMIN_THRESHOLD; default 1). */
  readonly adminThreshold?: number;
  /** How long an approval stays open, a Go duration such as `24h` (SV_APPROVAL_TTL). */
  readonly approvalTtl?: string;
  /** Count approvals signed without a purpose, from vaults before VAULT-MESSAGING 0.65.0 (SV_APPROVAL_ALLOW_NO_PURPOSE; a transition only). */
  readonly approvalAllowNoPurpose?: boolean;
  /**
   * Serve POST /v1/signins/unsigned, which sends members a sign-in they did
   * not start (SV_TEST_SIGNINS). For testing only, so staging only: any
   * other envName throws.
   */
  readonly testSignIns?: boolean;
  /**
   * Send an approval challenge with the approval's own expiry, at most 24
   * hours, and remind only admins holding no live challenge
   * (SV_LONG_APPROVAL_CHALLENGES; VAULT-MESSAGING 0.82.0 §10.4). Set it for a
   * channel only once that channel's member-vault release carries 0.82.0
   * (staging: release 26): an older member vault cuts the challenge to 10
   * minutes without telling the service. Default off.
   */
  readonly longApprovalChallenges?: boolean;
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
  /**
   * The lowest record key version to use (default 1). One above the
   * table's rotates the key at the next start (README "Rotating the record
   * key"); later deploys may leave it out.
   */
  readonly recordKeyVersion?: number;
  /**
   * The AnchorSigner's function ARN, in the signer's own account
   * (AnchorSigner-<env>; key protection, phase 1, GC #7406 as amended for
   * the owner's a on #7597): the task may invoke it, and nothing else of
   * the signer account. Left out, the task anchors as before.
   */
  readonly anchorSignerFunctionArn?: string;
  /**
   * The anchor key, pinned: its SubjectPublicKeyInfo (DER) in standard
   * base64 (SV_ANCHOR_KEY). Required with anchorSignerFunctionArn: the
   * service certifies and lists only this key, and checks every answer
   * and bundle of the signer against it. The owner takes it from the
   * signer account (`aws kms get-public-key` on the key's alias).
   */
  readonly anchorKeySpki?: string;
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
  readonly ballotsTable: dynamodb.Table;
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
    const recordKeyVersion = props.recordKeyVersion ?? 1;
    if (!Number.isInteger(recordKeyVersion) || recordKeyVersion < 1 || recordKeyVersion > 1 << 20) {
      throw new Error(`recordKeyVersion must be an integer from 1 to ${1 << 20} (got "${props.recordKeyVersion}")`);
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
      // from the internet. Private ranges only (RFC 1918), unless the
      // operator opts in to one public address (a /32) for direct access,
      // still behind the pinned TLS key and an API key.
      const [a, b] = [Number(m[1]), Number(m[2])];
      const isPrivate = a === 10 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168);
      if (!isPrivate && !(props.apiClientCidrPublic && m[5] === '32')) {
        throw new Error(`apiClientCidr must be a private (RFC 1918) range, or one public address (/32) with apiClientCidrPublic: the task has a public IP (got "${props.apiClientCidr}")`);
      }
    }
    if (props.adminThreshold !== undefined && !(Number.isInteger(props.adminThreshold) && props.adminThreshold >= 1 && props.adminThreshold <= 64)) {
      throw new Error(`adminThreshold must be an integer from 1 to 64 (got ${props.adminThreshold})`);
    }
    if (props.approvalTtl !== undefined && !/^([0-9]+(h|m|s))+$/.test(props.approvalTtl)) {
      throw new Error(`approvalTtl must be a duration such as 24h (got "${props.approvalTtl}")`);
    }
    // Production only for envName "prod", as for SV_SIGSTORE: every other
    // environment follows the staging rules.
    const channel = envName === 'prod' ? 'production' : 'staging';
    if (channel === 'staging' && props.approvalTtl !== undefined) {
      // The staging channel keeps an approval to 1 hour (VAULT-MESSAGING
      // 0.82.0 §10.4; STAGING-TIME-SCALE N16): the challenge lives as long.
      const unit: Record<string, number> = { h: 3600, m: 60, s: 1 };
      let seconds = 0;
      for (const m of props.approvalTtl.matchAll(/([0-9]+)([hms])/g)) seconds += Number(m[1]) * unit[m[2]];
      if (seconds > 3600) {
        throw new Error(`approvalTtl must be at most 1h unless envName is "prod" (got "${props.approvalTtl}", envName "${envName}")`);
      }
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
    const approvalEnv: Record<string, string> = { SV_CHANNEL: channel };
    if (props.longApprovalChallenges && channel === 'production') {
      throw new Error('longApprovalChallenges is refused for envName "prod": production waits for a production member-vault release with VAULT-MESSAGING 0.82.0');
    }
    if (props.longApprovalChallenges) approvalEnv.SV_LONG_APPROVAL_CHALLENGES = 'true';
    if (props.adminBootstrapEmail) approvalEnv.SV_ADMIN_BOOTSTRAP_EMAIL = props.adminBootstrapEmail;
    if (props.adminThreshold !== undefined) approvalEnv.SV_ADMIN_THRESHOLD = String(props.adminThreshold);
    if (props.approvalTtl) approvalEnv.SV_APPROVAL_TTL = props.approvalTtl;
    if (props.approvalAllowNoPurpose) approvalEnv.SV_APPROVAL_ALLOW_NO_PURPOSE = 'true';
    if (props.testSignIns) {
      if (envName !== 'staging') {
        throw new Error(`testSignIns is for the staging deployment only: members of a real service must sign in themselves (envName is "${envName}")`);
      }
      approvalEnv.SV_TEST_SIGNINS = 'true';
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

    // The write-once copy of accepted ballots, kept apart from the main
    // table so that a restore of that table can't lose a ballot or let a
    // second one in. Its items are sealed by the daemon under the record
    // key, like the main table's records. The role allows no update or
    // delete; a put that would replace an item is refused by the daemon's
    // condition, not by IAM, and point-in-time recovery keeps the past.
    this.ballotsTable = new dynamodb.Table(this, 'BallotsTable', {
      tableName: `${prefix}-ballots`,
      partitionKey: { name: 'pk', type: dynamodb.AttributeType.STRING },
      sortKey: { name: 'sk', type: dynamodb.AttributeType.STRING },
      billingMode: dynamodb.BillingMode.PAY_PER_REQUEST,
      pointInTimeRecoverySpecification: { pointInTimeRecoveryEnabled: true },
      deletionProtection: true,
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
    // Only the item calls the daemon makes (its transactions are Put and
    // Delete, checked per item). Batch calls, DescribeTable and streams
    // belong to the operator's `table restore` (README "Restoring the
    // table"), which runs with the operator's credentials.
    taskDef.taskRole.addToPrincipalPolicy(
      new iam.PolicyStatement({
        sid: 'Table',
        actions: TABLE_ACTIONS.map((a) => `dynamodb:${a}`),
        resources: [this.table.tableArn],
      }),
    );
    taskDef.taskRole.addToPrincipalPolicy(
      new iam.PolicyStatement({
        sid: 'Ballots',
        actions: BALLOTS_TABLE_ACTIONS.map((a) => `dynamodb:${a}`),
        resources: [this.ballotsTable.tableArn],
      }),
    );
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
    if (props.anchorSignerFunctionArn !== undefined) {
      if (!/^arn:aws[a-z-]*:lambda:[a-z0-9-]+:[0-9]{12}:function:[A-Za-z0-9_-]+$/.test(props.anchorSignerFunctionArn)) {
        throw new Error(`anchorSignerFunctionArn must be a function's unqualified ARN (got "${props.anchorSignerFunctionArn}")`);
      }
      if (cdk.Token.isUnresolved(this.account)) {
        throw new Error('anchorSignerFunctionArn needs env.account: the signer must be in another account');
      }
      if (props.anchorSignerFunctionArn.split(':')[4] === this.account) {
        throw new Error('anchorSignerFunctionArn must be in the signer account, not in this one');
      }
      if (!props.votesUrl) {
        throw new Error('anchorSignerFunctionArn needs votesUrl: the signer publishes to the votes site');
      }
      if (!props.anchorKeySpki || !/^MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE[A-Za-z0-9+/]{86}==$/.test(props.anchorKeySpki)) {
        throw new Error('anchorSignerFunctionArn needs anchorKeySpki: the P-256 anchor key\'s SPKI in standard base64 (the key is pinned, never learned from the signer)');
      }
      taskDef.taskRole.addToPrincipalPolicy(new iam.PolicyStatement({
        sid: 'InvokeAnchorSigner', actions: ['lambda:InvokeFunction'], resources: [props.anchorSignerFunctionArn],
      }));
    }
    // The marker that the anchor key has moved to the signer
    // (SV_ANCHOR_MOVED_PARAM; GC #7406 §7 step 1). The owner creates it at
    // the cutover (the runbook); this stack never does, and the task may
    // read it but never write or delete it. Once it exists, the daemon
    // refuses to start without the signer.
    const anchorMovedParam = anchorMovedParameterName(envName);
    taskDef.taskRole.addToPrincipalPolicy(new iam.PolicyStatement({
      sid: 'ReadAnchorMovedMarker',
      actions: ['ssm:GetParameter'],
      resources: [cdk.Arn.format({ service: 'ssm', resource: 'parameter', resourceName: anchorMovedParam.slice(1) }, this)],
    }));
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
        SV_BALLOTS_TABLE: this.ballotsTable.tableName,
        // Votes anchor in Sigstore's staging log outside production
        // (BALLOT-PROTOCOL §3.3; owner decision 2026-10-29).
        SV_SIGSTORE: envName === 'prod' ? 'production' : 'staging',
        ...(props.votesUrl ? { SV_VOTES_URL: props.votesUrl } : {}),
        ...(props.anchorSignerFunctionArn ? { SV_ANCHOR_SIGNER: props.anchorSignerFunctionArn, SV_ANCHOR_KEY: props.anchorKeySpki! } : {}),
        SV_ANCHOR_MOVED_PARAM: anchorMovedParam,
        SV_KMS_KEY_ID: this.key.keyArn,
        SV_LISTEN: `:${API_PORT}`,
        SV_WEBHOOK_URL: props.webhookUrl,
        SV_SERVICE_NAME: props.serviceName ?? DEFAULT_SERVICE_NAME,
        SV_TLS_PIN_PARAM: tlsPin.parameterName,
        SV_TLS_NAME: `${DISCOVERY_NAME}.${this.namespace.namespaceName}`,
        AWS_REGION: this.region,
        ...approvalEnv,
        ...(props.recordSealMigrate ? { SV_RECORD_SEAL_MIGRATE: '1' } : {}),
        ...(recordKeyVersion > 1 ? { SV_RECORD_KEY_VERSION: String(recordKeyVersion) } : {}),
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
    // The keystore key (the anchor key is in the signer's own account,
    // whose alarms are its own: GC #7638 item 6).
    const watchedKeys = [this.key.keyArn];
    new events.Rule(this, 'KeyChangeRule', {
      description: 'KMS calls that change the service vault keystore key (key_change alarm)',
      eventPattern: {
        source: ['aws.kms'],
        detailType: ['AWS API Call via CloudTrail'],
        detail: { eventName: KEY_CHANGE_EVENTS, resources: { ARN: watchedKeys } },
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

    // Errors: ERROR lines that no alarm above covers (internal failures:
    // DynamoDB, KMS, the relay).
    const errors = new logs.MetricFilter(this, 'Alarm-errors', {
      logGroup,
      filterPattern: logs.FilterPattern.all(logs.FilterPattern.stringValue('$.level', '=', 'ERROR'), logs.FilterPattern.notExists('$.alarm')),
      metricNamespace: `VettID/ServiceVault/${envName}`,
      metricName: 'errors',
      metricValue: '1',
    }).metric({ statistic: 'Sum', period: cdk.Duration.minutes(15) });
    notify(new cloudwatch.Alarm(this, 'Alarm-errors-alarm', {
      alarmName: `${prefix}-errors`,
      alarmDescription: `The service vault logged ${ERROR_THRESHOLD} or more errors in 15 minutes (DynamoDB, KMS or the relay failing)`,
      metric: errors,
      threshold: ERROR_THRESHOLD,
      evaluationPeriods: 1,
      comparisonOperator: cloudwatch.ComparisonOperator.GREATER_THAN_OR_EQUAL_TO_THRESHOLD,
      treatMissingData: cloudwatch.TreatMissingData.NOT_BREACHING,
    }));

    // ECS events of this cluster (its tasks' state changes, its service's
    // deployments) go to a log group of their own; one rule, so one
    // account-wide CloudWatch Logs resource policy. A task that stops on
    // its own (crashed, failed its health check, failed to start) raises
    // task_stopped, which a crash loop keeps raised while the down alarm
    // still sees CPU samples; a deployment the circuit breaker failed
    // raises deploy_failed.
    const ecsEvents = new logs.LogGroup(this, 'EcsEvents', {
      retention: logs.RetentionDays.ONE_MONTH,
      removalPolicy: cdk.RemovalPolicy.DESTROY,
    });
    new events.Rule(this, 'EcsEventsRule', {
      description: 'Task state changes and deployments of the service vault cluster (task_stopped, deploy_failed alarms)',
      eventPattern: {
        source: ['aws.ecs'],
        detailType: ['ECS Task State Change', 'ECS Deployment State Change'],
        resources: events.Match.anyOf(
          events.Match.prefix(this.formatArn({ service: 'ecs', resource: 'task', resourceName: `${prefix}/` })),
          events.Match.prefix(this.formatArn({ service: 'ecs', resource: 'service', resourceName: `${prefix}/` })),
        ),
      },
      targets: [new eventTargets.CloudWatchLogGroup(ecsEvents)],
    });
    const ecsAlarm = (name: string, description: string, filterPattern: logs.IFilterPattern) => {
      const metric = new logs.MetricFilter(this, `Alarm-${name}`, {
        logGroup: ecsEvents,
        filterPattern,
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
    };
    ecsAlarm('task_stopped', 'A service vault task stopped on its own: it crashed, failed its health check or failed to start (repeated: a crash loop)',
      logs.FilterPattern.all(
        logs.FilterPattern.stringValue('$.detail.lastStatus', '=', 'STOPPED'),
        logs.FilterPattern.any(
          logs.FilterPattern.all(...EXPECTED_STOP_CODES.map((c) => logs.FilterPattern.stringValue('$.detail.stopCode', '!=', c))),
          logs.FilterPattern.stringValue('$.detail.stoppedReason', '=', 'Task failed*'),
        ),
      ));
    ecsAlarm('deploy_failed', 'A service vault deployment failed and the circuit breaker rolled it back',
      logs.FilterPattern.stringValue('$.detail.eventName', '=', 'SERVICE_DEPLOYMENT_FAILED'));

    // ---- Control-plane watch (ballot review P1) -------------------------------
    // Someone with AWS access to this account (not the enclave) can run a
    // task under the task role and read the keystore, or move the TLS pin.
    // CloudTrail management events (the account's or the organization's
    // trail; this stack creates none) reach EventBridge; each rule below
    // logs its matches, labelled, to one log group and one alarm per label
    // notifies the same topic. "notice" ones are expected during a deploy.
    // iam:PassRole is not a CloudTrail event, so the task role's use is
    // watched where it is passed: RegisterTaskDefinition, RunTask,
    // StartTask and CreateService naming it or the family.
    const secEvents = new logs.LogGroup(this, 'SecurityEvents', {
      retention: logs.RetentionDays.ONE_YEAR,
      removalPolicy: cdk.RemovalPolicy.RETAIN,
    });
    const secEventsArn = this.formatArn({ service: 'logs', resource: 'log-group', resourceName: secEvents.logGroupName, arnFormat: cdk.ArnFormat.COLON_RESOURCE_NAME });
    const taskRoleArn = taskDef.taskRole.roleArn;
    // RegisterTaskDefinition and RunTask record the role as given: the ARN or the short name.
    const taskRoleNames = [taskRoleArn, taskDef.taskRole.roleName];
    const secRules: events.Rule[] = [];
    const family = taskDef.family;
    const familyArn = this.formatArn({ service: 'ecs', resource: 'task-definition', resourceName: family });
    // A task definition as RunTask/CreateService name it: family, family:revision, or its ARN with or without the revision
    // (one prefix on the ARN: a pattern is at most 2048 characters).
    const ourTaskDef = events.Match.anyOf(
      events.Match.exactString(family), events.Match.prefix(`${family}:`), events.Match.prefix(familyArn),
    );
    const notTaskRole = { 'anything-but': [taskRoleArn] };
    // Anything but the task role's own sessions. anything-but needs the
    // field present, and only role sessions carry a session issuer, so the
    // other callers (IAM users, root, services) are a second branch.
    const notTaskRoleSession = [
      { userIdentity: { type: [{ 'anything-but': ['AssumedRole'] }] } },
      { userIdentity: { type: ['AssumedRole'], sessionContext: { sessionIssuer: { arn: [notTaskRole] } } } },
    ];
    const secRule = (name: string, severity: 'notice' | 'alarm', description: string, alarmDescription: string, source: string, detail: object, readOnly = false, part = '') => {
      // part: a further rule for the same label, metric filter and alarm (a pattern is at most 2048 characters).
      // The targets are written out (not CloudWatchLogGroup targets) so that
      // one resource policy (account-wide, 10 per region) serves all ten rules.
      const rule = new events.Rule(this, `Sec-${name}${part}-rule`, {
        description: `${description} (${name} ${severity}${part ? `, part ${part.slice(1)}` : ''})`,
        eventPattern: { source: [source], detailType: ['AWS API Call via CloudTrail'], detail },
      });
      secRules.push(rule);
      // Read-only management events (KMS Decrypt) reach only a rule in this state.
      if (readOnly) (rule.node.defaultChild as events.CfnRule).state = 'ENABLED_WITH_ALL_CLOUDTRAIL_MANAGEMENT_EVENTS';
      (rule.node.defaultChild as events.CfnRule).targets = [{
        id: 'Target0',
        arn: secEventsArn,
        inputTransformer: {
          inputPathsMap: {
            time: '$.time',
            name: '$.detail.eventName',
            who: '$.detail.userIdentity.arn',
            ip: '$.detail.sourceIPAddress',
            id: '$.detail.eventID',
          },
          inputTemplate: `{"timestamp":<time>,"message":"sec:${name} <name> by <who> from <ip> id <id>"}`,
        },
      }];
      if (part) return;
      const metric = new logs.MetricFilter(this, `Sec-${name}`, {
        logGroup: secEvents,
        filterPattern: logs.FilterPattern.literal(`"sec:${name}"`),
        metricNamespace: `VettID/ServiceVault/${envName}`,
        metricName: name,
        metricValue: '1',
      }).metric({ statistic: 'Sum', period: cdk.Duration.minutes(5) });
      notify(new cloudwatch.Alarm(this, `Sec-${name}-alarm`, {
        alarmName: `${prefix}-${severity === 'notice' ? 'notice-' : ''}${name}`,
        alarmDescription: `${severity === 'notice' ? 'NOTICE (a deploy triggers it): ' : ''}${alarmDescription}`,
        metric,
        threshold: 1,
        evaluationPeriods: 1,
        comparisonOperator: cloudwatch.ComparisonOperator.GREATER_THAN_OR_EQUAL_TO_THRESHOLD,
        treatMissingData: cloudwatch.TreatMissingData.NOT_BREACHING,
      }));
    };
    secRule('taskdef_registered', 'notice', 'A task definition revision of the service vault family was registered',
      'A new task definition revision of the service vault family was registered (every deploy does this; otherwise someone is changing what runs under the task role)',
      'aws.ecs', { eventName: ['RegisterTaskDefinition'], requestParameters: { family: [family] } });
    secRule('service_updated', 'notice', 'The service vault ECS service was updated',
      'The service vault ECS service was updated (every deploy does this; otherwise someone is changing what runs)',
      'aws.ecs', { eventName: ['UpdateService'], requestParameters: { service: [prefix, this.service.serviceArn] } });
    secRule('run_task', 'alarm', 'A task was run or started in the service vault cluster',
      'A task was run or started by hand in the service vault cluster: the service never does (it starts tasks itself, not as RunTask); someone may be running code under the task role',
      'aws.ecs', { eventName: ['RunTask', 'StartTask'], requestParameters: { cluster: [prefix, cluster.clusterArn] } });
    // Three rules (pattern limit of 2048 characters, ARNs included), one label:
    // A, the task role used outside the family; B and C, the family used elsewhere.
    const taskRoleUseDescription = 'The service vault task role or task definition was named in a run, start, create-service or a task definition of another family: someone is running code under the task role';
    secRule('taskrole_use', 'alarm', 'The task role used outside the service\'s task definition family', taskRoleUseDescription,
      'aws.ecs', {
        $or: [
          { eventName: ['RegisterTaskDefinition'], requestParameters: { taskRoleArn: taskRoleNames, family: [{ 'anything-but': [family] }] } },
          { eventName: ['RunTask', 'StartTask'], requestParameters: { overrides: { taskRoleArn: taskRoleNames } } },
        ],
      });
    secRule('taskrole_use', 'alarm', 'The service\'s task definition family used elsewhere', taskRoleUseDescription,
      'aws.ecs', {
        $or: [
          { eventName: ['RunTask', 'StartTask', 'CreateService', 'CreateTaskSet'], requestParameters: { taskDefinition: ourTaskDef } },
          { eventName: ['UpdateService'], requestParameters: { taskDefinition: ourTaskDef, service: [{ 'anything-but': [prefix, this.service.serviceArn] }] } },
        ],
      }, false, '-b');
    secRule('taskrole_use', 'alarm', 'The service\'s task definition family used by a service of another cluster', taskRoleUseDescription,
      'aws.ecs', {
        $or: [
          // The same service name in another cluster is another service; an absent cluster is the default one.
          { eventName: ['UpdateService'], requestParameters: { taskDefinition: ourTaskDef, cluster: [{ 'anything-but': [prefix, cluster.clusterArn] }] } },
          { eventName: ['UpdateService'], requestParameters: { taskDefinition: ourTaskDef, cluster: [{ exists: false }] } },
        ],
      }, false, '-c');
    secRule('keystore_decrypt', 'alarm', 'The keystore key was used to decrypt or re-encrypt by a principal other than the task role',
      'The keystore KMS key was used (Decrypt, ReEncrypt) by something other than the service vault task role',
      'aws.kms', {
        eventName: ['Decrypt', 'ReEncrypt'],
        resources: { ARN: [this.key.keyArn] },
        $or: notTaskRoleSession,
      }, true);
    // Two rules, one label (pattern limit of 2048 characters): callers that are
    // not role sessions, and role sessions of another issuer.
    const tlsPinDescription = 'The service vault TLS pin parameter was written or deleted by something other than the task role (a deploy that creates the parameter fires it once)';
    const tlsPinBranches = (caller: object) => [
      { eventName: ['PutParameter', 'DeleteParameter'], requestParameters: { name: [tlsPin.parameterName] }, userIdentity: caller },
      { eventName: ['DeleteParameters'], requestParameters: { names: [tlsPin.parameterName] }, userIdentity: caller },
    ];
    secRule('tls_pin_change', 'alarm', 'The TLS pin parameter was written or deleted by a caller that is not a role session', tlsPinDescription,
      'aws.ssm', { $or: tlsPinBranches(notTaskRoleSession[0].userIdentity) });
    secRule('tls_pin_change', 'alarm', 'The TLS pin parameter was written or deleted by a role session other than the task role', tlsPinDescription,
      'aws.ssm', { $or: tlsPinBranches(notTaskRoleSession[1].userIdentity) }, false, '-b');

    // The task role's trust policy and permissions: a way to the role that
    // needs no task at all. IAM events reach EventBridge in us-east-1 only,
    // so elsewhere this rule is not created (README "Limits").
    if (cdk.Token.isUnresolved(this.region)) {
      cdk.Annotations.of(this).addWarning('The region is not known at synth: the taskrole_policy_change rule (IAM events, us-east-1 only) is omitted. Set env.region to us-east-1 to get it.');
    }
    if (this.region === 'us-east-1') {
      secRule('taskrole_policy_change', 'alarm', 'The task role\'s trust policy or permissions were changed',
        'The service vault task role\'s trust policy or permissions were changed (UpdateAssumeRolePolicy, AttachRolePolicy, PutRolePolicy): CloudFormation does this only in a deploy that changes the role',
        'aws.iam', {
          eventName: ['UpdateAssumeRolePolicy', 'AttachRolePolicy', 'PutRolePolicy'],
          requestParameters: { roleName: [taskDef.taskRole.roleName] },
        });
    }
    new logs.ResourcePolicy(this, 'SecurityEventsPolicy', {
      resourcePolicyName: `${prefix}-security-events`,
      policyStatements: [new iam.PolicyStatement({
        principals: [new iam.ServicePrincipal('events.amazonaws.com')],
        actions: ['logs:CreateLogStream', 'logs:PutLogEvents'],
        resources: [secEvents.logGroupArn],
        conditions: { ArnEquals: { 'aws:SourceArn': secRules.map((r) => r.ruleArn) } },
      })],
    });

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

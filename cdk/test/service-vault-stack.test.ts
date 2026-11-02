import * as cdk from 'aws-cdk-lib';
import { Match, Template } from 'aws-cdk-lib/assertions';
import { ALARMS, API_PORT, CLIENT_PARAMS, ERROR_THRESHOLD, EXPECTED_STOP_CODES, ServiceVaultStack, ssmPrefix, ServiceVaultStackProps, TASK_CPU, TASK_MEMORY_MIB } from '../lib/service-vault-stack';

const DIGEST = 'sha256:' + 'a'.repeat(64);
const CLIENT_SG = 'sg-0123456789abcdef0';
const base: ServiceVaultStackProps = {
  envName: 'test',
  image: `ghcr.io/vettid/service-vault@${DIGEST}`,
  webhookUrl: 'https://member.example.org/webhooks/service-vault',
  apiClientSecurityGroupId: CLIENT_SG,
  alarmTopicArn: 'arn:aws:sns:us-east-1:123456789012:alerts',
  env: { account: '123456789012', region: 'us-east-1' },
};
const synth = (props: Partial<ServiceVaultStackProps> = {}) => {
  const app = new cdk.App();
  return Template.fromStack(new ServiceVaultStack(app, 'SV', { ...base, ...props }));
};
const t = synth();

const container = () => {
  const td = Object.values<any>(t.findResources('AWS::ECS::TaskDefinition'))[0].Properties;
  expect(td.ContainerDefinitions).toHaveLength(1);
  return td.ContainerDefinitions[0];
};
const taskRoleStatements = (): any[] => {
  const td = Object.values<any>(t.findResources('AWS::ECS::TaskDefinition'))[0].Properties;
  const roleId = td.TaskRoleArn['Fn::GetAtt'][0];
  return Object.values<any>(t.findResources('AWS::IAM::Policy'))
    .filter((p) => p.Properties.Roles.some((r: any) => r.Ref === roleId))
    .flatMap((p) => p.Properties.PolicyDocument.Statement);
};
const asList = (x: any) => (Array.isArray(x) ? x : [x]);

describe('network', () => {
  test('no NAT gateway; public subnets only, two AZs', () => {
    t.resourceCountIs('AWS::EC2::NatGateway', 0);
    t.resourceCountIs('AWS::EC2::Subnet', 2);
    for (const s of Object.values<any>(t.findResources('AWS::EC2::Subnet'))) {
      expect(s.Properties.MapPublicIpOnLaunch).toBe(true);
    }
  });

  test('DynamoDB gateway endpoint and no interface endpoints', () => {
    const eps = Object.values<any>(t.findResources('AWS::EC2::VPCEndpoint'));
    expect(eps).toHaveLength(1);
    expect(eps[0].Properties.VpcEndpointType ?? 'Gateway').toBe('Gateway');
    expect(JSON.stringify(eps[0].Properties.ServiceName)).toContain('.dynamodb');
    expect(eps.filter((e) => e.Properties.VpcEndpointType === 'Interface')).toHaveLength(0);
  });

  test('task security group: no inbound from the internet, API port only from the client SG, HTTPS out', () => {
    const sgs = Object.values<any>(t.findResources('AWS::EC2::SecurityGroup'));
    const ingress = [
      ...sgs.flatMap((sg) => sg.Properties.SecurityGroupIngress ?? []),
      ...Object.values<any>(t.findResources('AWS::EC2::SecurityGroupIngress')).map((r) => r.Properties),
    ];
    for (const r of ingress) {
      expect(r.CidrIp).not.toBe('0.0.0.0/0');
      expect(r.CidrIpv6).not.toBe('::/0');
    }
    expect(ingress).toEqual([
      expect.objectContaining({ SourceSecurityGroupId: CLIENT_SG, FromPort: API_PORT, ToPort: API_PORT, IpProtocol: 'tcp' }),
    ]);
    t.hasResourceProperties('AWS::EC2::SecurityGroup', {
      SecurityGroupEgress: [{ CidrIp: '0.0.0.0/0', IpProtocol: 'tcp', FromPort: 443, ToPort: 443, Description: 'HTTPS out' }],
    });
  });

  test('an open CIDR for the API is refused', () => {
    expect(() => synth({ apiClientCidr: '0.0.0.0/0' })).toThrow(/internet/);
    expect(() => synth({ apiClientCidr: '0.0.0.0/1' })).toThrow(/internet/);
    expect(() => synth({ apiClientCidr: '10.0.0.0/15' })).toThrow(/internet/);
    expect(() => synth({ apiClientCidr: '::/0' })).toThrow(/IPv4/);
    expect(() => synth({ apiClientCidr: '203.0.113.7' })).toThrow(/IPv4/);
    expect(() => synth({ apiClientCidr: '300.0.113.7/32' })).toThrow(/IPv4/);
    expect(() => synth({ apiClientCidr: '203.0.113.7/33' })).toThrow(/IPv4/);
    expect(() => synth({ apiClientCidr: '10.0.0.0/16' })).not.toThrow();
    expect(() => synth({ apiClientCidr: '203.0.113.7/32' })).toThrow(/private/); // public: the task has a public IP
    expect(() => synth({ apiClientCidr: '203.0.113.7/32', apiClientCidrPublic: true })).not.toThrow(); // an operator's address, opted in
    expect(() => synth({ apiClientCidr: '203.0.113.0/24', apiClientCidrPublic: true })).toThrow(/private/); // never a public range
  });

  test('no load balancer; API discovered through a Cloud Map private DNS namespace', () => {
    t.resourceCountIs('AWS::ElasticLoadBalancingV2::LoadBalancer', 0);
    t.hasResourceProperties('AWS::ServiceDiscovery::PrivateDnsNamespace', { Name: 'test.vettid.internal' });
    t.hasResourceProperties('AWS::ServiceDiscovery::Service', {
      Name: 'service-vault',
      DnsConfig: Match.objectLike({ DnsRecords: [{ Type: 'A', TTL: 10 }] }),
    });
    const outputs = t.findOutputs('*');
    for (const id of ['VpcId', 'PublicSubnetIds', 'SecurityGroupId', 'NamespaceId', 'NamespaceArn', 'NamespaceName', 'ApiUrl', 'WebhookSecretArn', 'TlsPinParameterName', 'TlsPinParameterArn']) {
      expect(outputs[id]?.Export?.Name).toBe(`ServiceVault-test-${id}`);
    }
  });
});

describe('compute', () => {
  test('Container Insights disabled', () => {
    t.hasResourceProperties('AWS::ECS::Cluster', {
      ClusterSettings: [{ Name: 'containerInsights', Value: 'disabled' }],
    });
  });

  test('one ARM64 task, 0.25 vCPU / 512 MB', () => {
    t.hasResourceProperties('AWS::ECS::TaskDefinition', {
      Cpu: String(TASK_CPU),
      Memory: String(TASK_MEMORY_MIB),
      RuntimePlatform: { CpuArchitecture: 'ARM64', OperatingSystemFamily: 'LINUX' },
      RequiresCompatibilities: ['FARGATE'],
    });
    expect(TASK_CPU).toBe(256);
    expect(TASK_MEMORY_MIB).toBe(512);
  });

  test('desiredCount 1 on FARGATE_SPOT, circuit breaker with rollback, min 0 / max 100, public IP', () => {
    t.hasResourceProperties('AWS::ECS::Service', {
      DesiredCount: 1,
      CapacityProviderStrategy: [{ CapacityProvider: 'FARGATE_SPOT', Weight: 1 }],
      DeploymentConfiguration: Match.objectLike({
        MinimumHealthyPercent: 0,
        MaximumPercent: 100,
        DeploymentCircuitBreaker: { Enable: true, Rollback: true },
      }),
      NetworkConfiguration: { AwsvpcConfiguration: Match.objectLike({ AssignPublicIp: 'ENABLED' }) },
    });
    const svc = Object.values<any>(t.findResources('AWS::ECS::Service'))[0].Properties;
    expect(svc.LaunchType).toBeUndefined();
  });

  test('image referenced by digest; tags are refused', () => {
    expect(container().Image).toBe(`ghcr.io/vettid/service-vault@${DIGEST}`);
    expect(() => synth({ image: 'ghcr.io/vettid/service-vault:latest' })).toThrow(/digest/);
    expect(() => synth({ image: `ghcr.io/vettid/service-vault:v1@${DIGEST}` })).toThrow(/digest/);
  });

  test('an ECR image is pulled by digest with a pull grant', () => {
    const ecr = synth({ image: `123456789012.dkr.ecr.us-east-1.amazonaws.com/service-vault@${DIGEST}` });
    const td = Object.values<any>(ecr.findResources('AWS::ECS::TaskDefinition'))[0].Properties;
    expect(JSON.stringify(td.ContainerDefinitions[0].Image)).toContain(`/service-vault@${DIGEST}`);
    const actions = Object.values<any>(ecr.findResources('AWS::IAM::Policy'))
      .flatMap((p) => p.Properties.PolicyDocument.Statement)
      .flatMap((s) => asList(s.Action));
    expect(actions).toContain('ecr:BatchGetImage');
  });

  test('container: env vars, Secrets Manager secrets, health check, read-only root, 30-day logs', () => {
    const c = container();
    const env = Object.fromEntries(c.Environment.map((e: any) => [e.Name, e.Value]));
    expect(Object.keys(env).sort()).toEqual(
      ['AWS_REGION', 'SV_BALLOTS_TABLE', 'SV_CHANNEL', 'SV_KMS_KEY_ID', 'SV_LISTEN', 'SV_RELAY_URL', 'SV_SERVICE_NAME', 'SV_SIGSTORE', 'SV_TABLE', 'SV_TLS_NAME', 'SV_TLS_PIN_PARAM', 'SV_WEBHOOK_URL'],
    );
    expect(env.SV_RELAY_URL).toBe('https://relay.vettid.org');
    expect(env.SV_SIGSTORE).toBe('staging'); // the test stack's envName is not prod
    expect(env.SV_LISTEN).toBe(`:${API_PORT}`);
    expect(env.SV_SERVICE_NAME).toBe('VettID Member Service');
    expect(env.SV_WEBHOOK_URL).toBe(base.webhookUrl);
    expect(c.Secrets.map((s: any) => s.Name).sort()).toEqual(['SV_API_KEY_HASHES', 'SV_WEBHOOK_SECRET']);
    expect(c.HealthCheck.Command).toEqual(['CMD', '/service-vault', 'healthcheck']);
    expect(c.ReadonlyRootFilesystem).toBe(true);
    t.hasResourceProperties('AWS::Logs::LogGroup', { RetentionInDays: 30 });
  });

  test('admin approval settings: unset by default, passed through when given, checked', () => {
    const td = Object.values<any>(
      synth({ envName: 'prod', adminBootstrapEmail: 'admin@example.org', adminThreshold: 2, approvalTtl: '48h', approvalAllowNoPurpose: true }).findResources('AWS::ECS::TaskDefinition'),
    )[0].Properties;
    const env = Object.fromEntries(td.ContainerDefinitions[0].Environment.map((e: any) => [e.Name, e.Value]));
    expect(env.SV_ADMIN_BOOTSTRAP_EMAIL).toBe('admin@example.org');
    expect(env.SV_ADMIN_THRESHOLD).toBe('2');
    expect(env.SV_APPROVAL_TTL).toBe('48h');
    expect(env.SV_APPROVAL_ALLOW_NO_PURPOSE).toBe('true');
    expect(() => synth({ adminThreshold: 0 })).toThrow(/adminThreshold/);
    expect(() => synth({ approvalTtl: 'a day' })).toThrow(/approvalTtl/);
  });

  test('SV_CHANNEL: staging on staging, production elsewhere; staging approvals last at most 1h', () => {
    const envOf = (props: Partial<ServiceVaultStackProps>) => {
      const td = Object.values<any>(synth(props).findResources('AWS::ECS::TaskDefinition'))[0].Properties;
      return Object.fromEntries(td.ContainerDefinitions[0].Environment.map((e: any) => [e.Name, e.Value]));
    };
    expect(envOf({ envName: 'staging' }).SV_CHANNEL).toBe('staging');
    expect(envOf({ envName: 'staging' }).SV_APPROVAL_TTL).toBeUndefined();
    expect(envOf({ envName: 'staging', approvalTtl: '1h' }).SV_APPROVAL_TTL).toBe('1h');
    expect(envOf({ envName: 'staging', approvalTtl: '30m' }).SV_APPROVAL_TTL).toBe('30m');
    expect(() => synth({ envName: 'staging', approvalTtl: '2h' })).toThrow(/approvalTtl/);
    expect(() => synth({ envName: 'staging', approvalTtl: '1h1m' })).toThrow(/approvalTtl/);
    expect(() => synth({ envName: 'staging', approvalTtl: '90m' })).toThrow(/approvalTtl/);
    // Production only for envName "prod" (as SV_SIGSTORE); dev and test envs follow staging.
    expect(envOf({ envName: 'prod' }).SV_CHANNEL).toBe('production');
    expect(envOf({ envName: 'test' }).SV_CHANNEL).toBe('staging');
    expect(envOf({}).SV_CHANNEL).toBe('staging'); // the test stack's envName is "test"
    expect(() => synth({ envName: 'test', approvalTtl: '2h' })).toThrow(/approvalTtl/);
    expect(envOf({ envName: 'prod' }).SV_APPROVAL_TTL).toBeUndefined(); // the service's 24h default
    expect(envOf({ envName: 'prod', approvalTtl: '48h' }).SV_APPROVAL_TTL).toBe('48h');
  });

  test('longApprovalChallenges: SV_LONG_APPROVAL_CHALLENGES only when set', () => {
    const envOf = (props: Partial<ServiceVaultStackProps>) => {
      const td = Object.values<any>(synth(props).findResources('AWS::ECS::TaskDefinition'))[0].Properties;
      return Object.fromEntries(td.ContainerDefinitions[0].Environment.map((e: any) => [e.Name, e.Value]));
    };
    expect(envOf({}).SV_LONG_APPROVAL_CHALLENGES).toBeUndefined();
    expect(envOf({ longApprovalChallenges: false }).SV_LONG_APPROVAL_CHALLENGES).toBeUndefined();
    expect(envOf({ longApprovalChallenges: true }).SV_LONG_APPROVAL_CHALLENGES).toBe('true');
    expect(envOf({ envName: 'staging', longApprovalChallenges: true }).SV_LONG_APPROVAL_CHALLENGES).toBe('true');
    // Production waits for a production member-vault release with 0.82.0.
    expect(() => synth({ envName: 'prod', longApprovalChallenges: true })).toThrow(/longApprovalChallenges/);
    expect(envOf({ envName: 'prod' }).SV_LONG_APPROVAL_CHALLENGES).toBeUndefined();
  });

  test('testSignIns: SV_TEST_SIGNINS only on staging with the flag', () => {
    const envOf = (props: Partial<ServiceVaultStackProps>) => {
      const td = Object.values<any>(synth(props).findResources('AWS::ECS::TaskDefinition'))[0].Properties;
      return Object.fromEntries(td.ContainerDefinitions[0].Environment.map((e: any) => [e.Name, e.Value]));
    };
    expect(envOf({}).SV_TEST_SIGNINS).toBeUndefined();
    expect(envOf({ envName: 'staging' }).SV_TEST_SIGNINS).toBeUndefined();
    expect(envOf({ envName: 'staging', testSignIns: true }).SV_TEST_SIGNINS).toBe('true');
    expect(() => synth({ envName: 'prod', testSignIns: true })).toThrow(/testSignIns/);
    expect(() => synth({ envName: 'test', testSignIns: true })).toThrow(/testSignIns/);
  });

  test('secrets are generated, never given a value, and retained', () => {
    const secrets = t.findResources('AWS::SecretsManager::Secret');
    expect(Object.keys(secrets)).toHaveLength(2);
    for (const s of Object.values<any>(secrets)) {
      expect(s.Properties.SecretString).toBeUndefined();
      expect(s.Properties.GenerateSecretString).toBeDefined();
      expect(s.DeletionPolicy).toBe('Retain');
    }
  });
});

// The main table has the TTL attribute; the ballots' copy has none.
function mainTableId(): string {
  const tables = t.findResources('AWS::DynamoDB::Table');
  return Object.keys(tables).find((k) => tables[k].Properties.TimeToLiveSpecification)!;
}

function ballotsTableId(): string {
  const tables = t.findResources('AWS::DynamoDB::Table');
  return Object.keys(tables).find((k) => !tables[k].Properties.TimeToLiveSpecification)!;
}

describe('data', () => {
  test('table: pk/sk strings, on-demand, PITR, deletion protection, retained', () => {
    t.hasResource('AWS::DynamoDB::Table', {
      DeletionPolicy: 'Retain',
      UpdateReplacePolicy: 'Retain',
      Properties: Match.objectLike({
        KeySchema: [{ AttributeName: 'pk', KeyType: 'HASH' }, { AttributeName: 'sk', KeyType: 'RANGE' }],
        AttributeDefinitions: [{ AttributeName: 'pk', AttributeType: 'S' }, { AttributeName: 'sk', AttributeType: 'S' }],
        BillingMode: 'PAY_PER_REQUEST',
        PointInTimeRecoverySpecification: { PointInTimeRecoveryEnabled: true },
        DeletionProtectionEnabled: true,
        TimeToLiveSpecification: { AttributeName: 'ttl', Enabled: true },
      }),
    });
  });

  test('ballots table: its own, write-once by the role, PITR, deletion protection, retained', () => {
    const tables = t.findResources('AWS::DynamoDB::Table');
    expect(Object.keys(tables)).toHaveLength(2);
    const b = tables[ballotsTableId()];
    expect(b.DeletionPolicy).toBe('Retain');
    expect(b.Properties.TableName).toBe(`${tables[mainTableId()].Properties.TableName}-ballots`);
    expect(b.Properties.DeletionProtectionEnabled).toBe(true);
    expect(b.Properties.PointInTimeRecoverySpecification).toEqual({ PointInTimeRecoveryEnabled: true });
    const env = JSON.stringify(t.findResources('AWS::ECS::TaskDefinition'));
    expect(env).toContain('SV_BALLOTS_TABLE');
  });

  test('KMS key: symmetric, rotation enabled, retained', () => {
    t.hasResource('AWS::KMS::Key', {
      DeletionPolicy: 'Retain',
      Properties: Match.objectLike({ EnableKeyRotation: true }),
    });
    const key = Object.values<any>(t.findResources('AWS::KMS::Key'))[0].Properties;
    expect(key.KeySpec ?? 'SYMMETRIC_DEFAULT').toBe('SYMMETRIC_DEFAULT');
  });

  test('key policy: the account administers the key, only the task role uses it', () => {
    const key = Object.values<any>(t.findResources('AWS::KMS::Key'))[0].Properties;
    const roleId = Object.keys(t.findResources('AWS::IAM::Role')).find((id) => id.startsWith('TaskTaskRole'));
    const stmts = key.KeyPolicy.Statement;
    expect(stmts.map((s: any) => s.Sid).sort()).toEqual(['Administer', 'TaskUse']);
    for (const s of stmts) expect(s.Effect).toBe('Allow');
    const admin = stmts.find((s: any) => s.Sid === 'Administer');
    for (const a of asList(admin.Action)) {
      expect(a).not.toMatch(/^kms:(\*|Decrypt|Encrypt|GenerateDataKey|ReEncrypt|Sign|Verify|GenerateMac|DeriveSharedSecret)/);
    }
    expect(asList(admin.Action)).toContain('kms:Put*'); // PutKeyPolicy: the policy stays correctable
    const use = stmts.find((s: any) => s.Sid === 'TaskUse');
    expect(asList(use.Action).sort()).toEqual(['kms:Decrypt', 'kms:GenerateDataKey']);
    expect(use.Principal).toEqual({ AWS: { 'Fn::GetAtt': [roleId, 'Arn'] } });
  });

  test('task role: only kms:GenerateDataKey and kms:Decrypt, on the keystore key', () => {
    const keyId = Object.keys(t.findResources('AWS::KMS::Key'))[0];
    const kmsStatements = taskRoleStatements().filter((s) => asList(s.Action).some((a: string) => a.startsWith('kms:')));
    expect(kmsStatements).toHaveLength(1);
    expect(asList(kmsStatements[0].Action).sort()).toEqual(['kms:Decrypt', 'kms:GenerateDataKey']);
    expect(kmsStatements[0].Effect).toBe('Allow');
    expect(kmsStatements[0].Resource).toEqual({ 'Fn::GetAtt': [keyId, 'Arn'] });
  });

  test('task role: only ssm:PutParameter, on the TLS pin parameter', () => {
    const paramId = Object.keys(t.findResources('AWS::SSM::Parameter'))[0];
    const ssmStatements = taskRoleStatements().filter((s) => asList(s.Action).some((a: string) => a.startsWith('ssm:')));
    expect(ssmStatements).toHaveLength(1);
    expect(asList(ssmStatements[0].Action)).toEqual(['ssm:PutParameter']);
    expect(JSON.stringify(ssmStatements[0].Resource)).toContain(paramId);
  });

  test('the API client\'s values are published in SSM under the env prefix', () => {
    const params = Object.values<any>(t.findResources('AWS::SSM::Parameter')).map((p) => p.Properties);
    const byName = Object.fromEntries(params.map((p) => [p.Name, p.Value]));
    for (const name of [...CLIENT_PARAMS, 'tls-pin']) expect(Object.keys(byName)).toContain(`${ssmPrefix('test')}/${name}`);
    expect(JSON.stringify(byName[`${ssmPrefix('test')}/api-url`])).toContain('https://');
    expect(JSON.stringify(byName[`${ssmPrefix('test')}/webhook-secret-arn`])).toContain('WebhookSecret');
    expect(JSON.stringify(byName[`${ssmPrefix('test')}/security-group-id`])).toContain('TaskSg');
  });

  test('API URL is https', () => {
    const outputs = t.toJSON().Outputs;
    expect(JSON.stringify(outputs.ApiUrl.Value)).toContain('https://');
  });

  test('task role: exactly the item calls the daemon makes, on each table', () => {
    const ddb = taskRoleStatements().filter((s) => asList(s.Action).some((a: string) => a.startsWith('dynamodb:')));
    expect(ddb).toHaveLength(2);
    const bySid = Object.fromEntries(ddb.map((s) => [s.Sid, s]));
    expect(asList(bySid.Table.Action).sort()).toEqual(['dynamodb:DeleteItem', 'dynamodb:GetItem', 'dynamodb:PutItem', 'dynamodb:Query', 'dynamodb:Scan', 'dynamodb:UpdateItem']);
    expect(asList(bySid.Table.Resource)).toEqual([{ 'Fn::GetAtt': [mainTableId(), 'Arn'] }]);
    // The ballots' copy is write-once: no update or delete.
    expect(asList(bySid.Ballots.Action).sort()).toEqual(['dynamodb:GetItem', 'dynamodb:PutItem', 'dynamodb:Query', 'dynamodb:Scan']);
    expect(asList(bySid.Ballots.Resource)).toEqual([{ 'Fn::GetAtt': [ballotsTableId(), 'Arn'] }]);
  });

  test('task role: DynamoDB only on the two tables; nothing else', () => {
    for (const s of taskRoleStatements()) {
      const actions = asList(s.Action);
      if (actions.some((a: string) => a.startsWith('kms:') || a.startsWith('ssm:'))) continue;
      expect(actions.every((a: string) => a.startsWith('dynamodb:'))).toBe(true);
      for (const r of asList(s.Resource)) {
        const j = JSON.stringify(r);
        expect(j.includes(mainTableId()) || j.includes(ballotsTableId())).toBe(true);
      }
    }
  });
});

describe('alarms', () => {
  test('one per marked log line, and one for no running task; all notify the topic', () => {
    for (const name of Object.keys(ALARMS)) {
      t.hasResourceProperties('AWS::Logs::MetricFilter', {
        FilterPattern: `{ $.alarm = "${name}" }`,
        MetricTransformations: [Match.objectLike({ MetricName: name, MetricNamespace: 'VettID/ServiceVault/test' })],
      });
      t.hasResourceProperties('AWS::CloudWatch::Alarm', { AlarmName: `vettid-service-vault-test-${name}`, Threshold: 1 });
    }
    t.hasResourceProperties('AWS::CloudWatch::Alarm', {
      AlarmName: 'vettid-service-vault-test-down',
      MetricName: 'CPUUtilization',
      Namespace: 'AWS/ECS',
      Statistic: 'SampleCount',
      ComparisonOperator: 'LessThanThreshold',
      TreatMissingData: 'breaching',
    });
    const alarms = Object.values<any>(t.findResources('AWS::CloudWatch::Alarm'));
    expect(alarms).toHaveLength(Object.keys(ALARMS).length + 12); // + key_change, errors, task_stopped, deploy_failed, down, 7 control-plane
    for (const a of alarms) expect(a.Properties.AlarmActions).toEqual([base.alarmTopicArn]);
  });

  test('the key policy gives the account no way to grant itself use of the key', () => {
    const key = Object.values<any>(t.findResources('AWS::KMS::Key'))[0].Properties.KeyPolicy;
    const admin = key.Statement.find((st: any) => st.Sid === 'Administer');
    const actions: string[] = [admin.Action].flat();
    for (const a of actions) expect(['kms:Create*', 'kms:CreateGrant', 'kms:*', 'kms:Decrypt', 'kms:GenerateDataKey', 'kms:Encrypt']).not.toContain(a);
    expect(actions).toContain('kms:CreateAlias');
  });

  test('recordSealMigrate sets the migration variable, and only then', () => {
    const env = (t2: Template) => Object.values<any>(t2.findResources('AWS::ECS::TaskDefinition'))[0].Properties.ContainerDefinitions[0].Environment;
    expect(env(t).find((e: any) => e.Name === 'SV_RECORD_SEAL_MIGRATE')).toBeUndefined();
    expect(env(synth({ recordSealMigrate: true })).find((e: any) => e.Name === 'SV_RECORD_SEAL_MIGRATE')?.Value).toBe('1');
  });

  test('recordKeyVersion: SV_RECORD_KEY_VERSION above 1 only; a bad version fails synth', () => {
    const env = (t2: Template) => Object.values<any>(t2.findResources('AWS::ECS::TaskDefinition'))[0].Properties.ContainerDefinitions[0].Environment;
    expect(env(t).find((e: any) => e.Name === 'SV_RECORD_KEY_VERSION')).toBeUndefined();
    expect(env(synth({ recordKeyVersion: 2 })).find((e: any) => e.Name === 'SV_RECORD_KEY_VERSION')?.Value).toBe('2');
    for (const v of [0, 1.5, NaN]) expect(() => synth({ recordKeyVersion: v })).toThrow(/recordKeyVersion/);
  });

  test('key_change: CloudTrail KMS events for the keystore key reach a log group and alarm', () => {
    const rule = Object.values<any>(t.findResources('AWS::Events::Rule')).find((r: any) => r.Properties.EventPattern.source[0] === 'aws.kms' && !r.Properties.Description.includes('keystore_decrypt')).Properties;
    expect(rule.EventPattern.source).toEqual(['aws.kms']);
    for (const e of ['CreateGrant', 'PutKeyPolicy', 'ScheduleKeyDeletion', 'DisableKey']) expect(rule.EventPattern.detail.eventName).toContain(e);
    expect(JSON.stringify(rule.EventPattern.detail.resources)).toContain('KeystoreKey');
    t.hasResourceProperties('AWS::CloudWatch::Alarm', { AlarmName: 'vettid-service-vault-test-key_change' });
  });

  test('task_stopped and deploy_failed: one rule sends the cluster\'s ECS events to a log group', () => {
    const rules = Object.values<any>(t.findResources('AWS::Events::Rule')).filter((r: any) => r.Properties.EventPattern.source[0] === 'aws.ecs' && !r.Properties.EventPattern.detail);
    expect(rules).toHaveLength(1);
    const p = rules[0].Properties.EventPattern;
    expect(p['detail-type']).toEqual(['ECS Task State Change', 'ECS Deployment State Change']);
    const res = JSON.stringify(p.resources);
    expect(res).toContain(':task/vettid-service-vault-test/');
    expect(res).toContain(':service/vettid-service-vault-test/');
    const filters = Object.values<any>(t.findResources('AWS::Logs::MetricFilter')).map((f: any) => f.Properties);
    const stopped = filters.find((f: any) => f.MetricTransformations[0].MetricName === 'task_stopped').FilterPattern;
    expect(stopped).toContain('$.detail.lastStatus = "STOPPED"');
    for (const c of EXPECTED_STOP_CODES) expect(stopped).toContain(`$.detail.stopCode != "${c}"`);
    expect(stopped).toContain('$.detail.stoppedReason = "Task failed*"');
    expect(filters.find((f: any) => f.MetricTransformations[0].MetricName === 'deploy_failed').FilterPattern).toContain('SERVICE_DEPLOYMENT_FAILED');
    for (const n of ['task_stopped', 'deploy_failed']) t.hasResourceProperties('AWS::CloudWatch::Alarm', { AlarmName: `vettid-service-vault-test-${n}`, Threshold: 1 });
  });

  test('errors: ERROR lines without an alarm of their own, over 15 minutes', () => {
    const f = Object.values<any>(t.findResources('AWS::Logs::MetricFilter')).map((x: any) => x.Properties)
      .find((x: any) => x.MetricTransformations[0].MetricName === 'errors');
    expect(f.FilterPattern).toBe('{ ($.level = "ERROR") && ($.alarm NOT EXISTS) }');
    t.hasResourceProperties('AWS::CloudWatch::Alarm', { AlarmName: 'vettid-service-vault-test-errors', Threshold: ERROR_THRESHOLD, Period: 900 });
  });

  describe('control plane (CloudTrail via EventBridge)', () => {
    const rules = Object.values<any>(t.findResources('AWS::Events::Rule')).map((r: any) => r.Properties);
    const rule = (name: string) => rules.find((r: any) => r.Description.includes(`(${name} `));
    const anyOf = (name: string) => rule(name).EventPattern.detail.$or as any[];
    const s = (x: unknown) => JSON.stringify(x);

    test.each([
      ['taskdef_registered', 'notice', 'vettid-service-vault-test-notice-taskdef_registered'],
      ['service_updated', 'notice', 'vettid-service-vault-test-notice-service_updated'],
      ['run_task', 'alarm', 'vettid-service-vault-test-run_task'],
      ['taskrole_use', 'alarm', 'vettid-service-vault-test-taskrole_use'],
      ['keystore_decrypt', 'alarm', 'vettid-service-vault-test-keystore_decrypt'],
      ['tls_pin_change', 'alarm', 'vettid-service-vault-test-tls_pin_change'],
      ['taskrole_policy_change', 'alarm', 'vettid-service-vault-test-taskrole_policy_change'],
    ])('%s (%s): CloudTrail rule, labelled log target, metric filter and an alarm to the topic', (name, severity, alarmName) => {
      expect(rule(name).Description).toContain(severity);
      expect(rule(name).EventPattern['detail-type']).toEqual(['AWS API Call via CloudTrail']);
      expect(rule(name).Targets).toHaveLength(1);
      expect(rule(name).Targets[0].InputTransformer.InputTemplate).toContain(`sec:${name} `);
      t.hasResourceProperties('AWS::Logs::MetricFilter', { FilterPattern: `"sec:${name}"`, MetricTransformations: [Match.objectLike({ MetricName: name })] });
      t.hasResourceProperties('AWS::CloudWatch::Alarm', { AlarmName: alarmName, Threshold: 1, AlarmActions: [base.alarmTopicArn] });
    });

    test('notice alarms say a deploy triggers them; the others do not', () => {
      const desc = (n: string) => Object.values<any>(t.findResources('AWS::CloudWatch::Alarm')).find((a: any) => a.Properties.AlarmName.endsWith(n)).Properties.AlarmDescription;
      expect(desc('notice-taskdef_registered')).toMatch(/^NOTICE/);
      expect(desc('notice-service_updated')).toMatch(/^NOTICE/);
      for (const n of ['-run_task', '-taskrole_use', '-keystore_decrypt', '-tls_pin_change']) expect(desc(n)).not.toMatch(/^NOTICE/);
    });

    test('taskdef_registered: RegisterTaskDefinition of the service family', () => {
      const d = rule('taskdef_registered').EventPattern.detail;
      expect(rule('taskdef_registered').EventPattern.source).toEqual(['aws.ecs']);
      expect(d.eventName).toEqual(['RegisterTaskDefinition']);
      expect(d.requestParameters.family).toEqual(['SVTask29F9D9C1']);
    });

    test('service_updated: UpdateService on the service, by name or ARN', () => {
      const d = rule('service_updated').EventPattern.detail;
      expect(d.eventName).toEqual(['UpdateService']);
      expect(s(d.requestParameters.service)).toContain('vettid-service-vault-test');
      expect(s(d.requestParameters.service)).toContain('ServiceD69D759B');
    });

    test('run_task: RunTask and StartTask in the cluster, by name or ARN', () => {
      const d = rule('run_task').EventPattern.detail;
      expect(d.eventName).toEqual(['RunTask', 'StartTask']);
      expect(s(d.requestParameters.cluster)).toContain('vettid-service-vault-test');
      expect(s(d.requestParameters.cluster)).toContain('ClusterEB0386A7');
    });

    test('taskrole_use (PassRole is not a CloudTrail event): task role in another family, our task definition run or created, task role override', () => {
      const [reg, run, upd, updCluster, updDefault, override] = anyOf('taskrole_use');
      expect(reg.eventName).toEqual(['RegisterTaskDefinition']);
      expect(reg.requestParameters.taskRoleArn).toHaveLength(2); // ARN and short name
      expect(s(reg.requestParameters.taskRoleArn)).toContain('TaskTaskRole');
      expect(s(reg.requestParameters.taskRoleArn)).toContain('Ref');
      expect(reg.requestParameters.family).toEqual([{ 'anything-but': ['SVTask29F9D9C1'] }]);
      expect(run.eventName).toEqual(['RunTask', 'StartTask', 'CreateService', 'CreateTaskSet']);
      expect(run.requestParameters.taskDefinition).toContainEqual({ prefix: 'SVTask29F9D9C1:' });
      expect(run.requestParameters.taskDefinition).toContain('SVTask29F9D9C1');
      expect(s(run.requestParameters.taskDefinition)).toContain('task-definition/');
      expect(upd.eventName).toEqual(['UpdateService']);
      expect(upd.requestParameters.taskDefinition).toEqual(run.requestParameters.taskDefinition);
      expect(upd.requestParameters.service[0]['anything-but']).toHaveLength(2);
      expect(s(upd.requestParameters.service)).toContain('vettid-service-vault-test');
      for (const u of [updCluster, updDefault]) {
        expect(u.eventName).toEqual(['UpdateService']);
        expect(u.requestParameters.taskDefinition).toEqual(run.requestParameters.taskDefinition);
      }
      expect(updCluster.requestParameters.cluster[0]['anything-but']).toHaveLength(2);
      expect(s(updCluster.requestParameters.cluster)).toContain('vettid-service-vault-test');
      expect(s(updCluster.requestParameters.cluster)).toContain('ClusterEB0386A7');
      expect(updDefault.requestParameters.cluster).toEqual([{ exists: false }]);
      expect(override.eventName).toEqual(['RunTask', 'StartTask']);
      expect(override.requestParameters.overrides.taskRoleArn).toHaveLength(2);
      expect(s(override.requestParameters.overrides.taskRoleArn)).toContain('TaskTaskRole');
    });

    test('taskrole_policy_change: IAM trust policy and policy changes on the task role (us-east-1 only)', () => {
      const r = rule('taskrole_policy_change');
      expect(r.EventPattern.source).toEqual(['aws.iam']);
      expect(r.EventPattern.detail.eventName).toEqual(['UpdateAssumeRolePolicy', 'AttachRolePolicy', 'PutRolePolicy']);
      expect(s(r.EventPattern.detail.requestParameters.roleName)).toContain('TaskTaskRole');
      const other = Object.values<any>(synth({ env: { account: '123456789012', region: 'eu-west-1' } }).findResources('AWS::Events::Rule'));
      expect(other.find((x: any) => x.Properties.Description.includes('taskrole_policy_change'))).toBeUndefined();
      expect(other.find((x: any) => x.Properties.Description.includes('taskrole_use'))).toBeDefined();
    });

    // Callers other than the task role's own sessions: not role sessions at all, or role sessions of another issuer.
    const notTaskRole = (branches: any[]) => {
      expect(branches[0].userIdentity).toEqual({ type: [{ 'anything-but': ['AssumedRole'] }] });
      expect(branches[1].userIdentity.type).toEqual(['AssumedRole']);
      const issuer = branches[1].userIdentity.sessionContext.sessionIssuer.arn;
      expect(issuer[0]['anything-but']).toHaveLength(1);
      expect(s(issuer)).toContain('TaskTaskRole');
    };

    test('keystore_decrypt: Decrypt and ReEncrypt on the keystore key by anyone but the task role', () => {
      const d = rule('keystore_decrypt').EventPattern.detail;
      expect(rule('keystore_decrypt').EventPattern.source).toEqual(['aws.kms']);
      expect(d.eventName).toEqual(['Decrypt', 'ReEncrypt']);
      expect(rule('keystore_decrypt').State).toBe('ENABLED_WITH_ALL_CLOUDTRAIL_MANAGEMENT_EVENTS');
      for (const n of ['run_task', 'tls_pin_change', 'taskrole_use']) expect(rule(n).State).toBe('ENABLED');
      expect(s(d.resources)).toContain('KeystoreKey');
      notTaskRole(d.$or);
    });

    test('tls_pin_change: Put/DeleteParameter(s) on the pin parameter by anyone but the task role', () => {
      const branches = anyOf('tls_pin_change');
      expect(rule('tls_pin_change').EventPattern.source).toEqual(['aws.ssm']);
      expect(branches).toHaveLength(4);
      for (const b of branches) expect(s(b.requestParameters)).toContain('TlsPin');
      expect(branches[0].eventName).toEqual(['PutParameter', 'DeleteParameter']);
      expect(branches[2].eventName).toEqual(['DeleteParameters']);
      notTaskRole([branches[0], branches[1]]);
      notTaskRole([branches[2], branches[3]]);
    });

    test('one resource policy serves the seven rules, limited to their ARNs, and the task role gains nothing', () => {
      t.resourceCountIs('AWS::Logs::ResourcePolicy', 1);
      t.hasResourceProperties('AWS::Logs::ResourcePolicy', { PolicyName: 'vettid-service-vault-test-security-events' });
      expect(s(Object.values<any>(t.findResources('AWS::Logs::ResourcePolicy'))[0].Properties.PolicyDocument)).toContain('ArnEquals');
      expect(taskRoleStatements().map((st: any) => st.Sid)).toEqual(['Table', 'Ballots', 'KeystoreKey', 'PublishTlsPin']);
    });
  });

  test('with an address instead, a topic of its own with that subscription', () => {
    const t2 = synth({ alarmTopicArn: undefined, alarmEmail: 'ops@example.org' });
    t2.hasResourceProperties('AWS::SNS::Subscription', { Protocol: 'email', Endpoint: 'ops@example.org' });
    const topicId = Object.keys(t2.findResources('AWS::SNS::Topic'))[0];
    for (const a of Object.values<any>(t2.findResources('AWS::CloudWatch::Alarm'))) {
      expect(a.Properties.AlarmActions).toEqual([{ Ref: topicId }]);
    }
  });

  test.each([
    ['no destination', { alarmTopicArn: undefined }],
    ['two destinations', { alarmEmail: 'ops@example.org' }],
    ['a bad topic', { alarmTopicArn: 'alerts' }],
  ])('refuses %s', (_n, props) => {
    expect(() => synth(props as Partial<ServiceVaultStackProps>)).toThrow();
  });
});

describe('hardening', () => {
  test('apiClientCidr must be private: the task has a public IP', () => {
    expect(() => synth({ apiClientCidr: '52.0.0.0/16' })).toThrow(/private/);
    expect(() => synth({ apiClientCidr: '203.0.113.7/32' })).toThrow(/private/);
    expect(() => synth({ apiClientCidr: '10.60.0.0/24' })).not.toThrow();
    expect(() => synth({ apiClientCidr: '172.16.0.0/16' })).not.toThrow();
  });

  test('the container drops every Linux capability', () => {
    const c = Object.values<any>(t.findResources('AWS::ECS::TaskDefinition'))[0].Properties.ContainerDefinitions[0];
    expect(c.LinuxParameters.Capabilities.Drop).toEqual(['ALL']);
  });
});

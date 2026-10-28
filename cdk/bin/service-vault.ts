#!/usr/bin/env node
import * as cdk from 'aws-cdk-lib';
import { ServiceVaultStack } from '../lib/service-vault-stack';

// Parameters come from context (cdk.json, ~/.cdk.json or -c key=value):
//   envName (default prod), image (required, by digest), webhookUrl
//   (required), relayUrl, serviceName, apiClientSecurityGroupId,
//   apiClientCidr, vpcCidr, adminBootstrapEmail, adminThreshold,
//   approvalTtl, recordSealMigrate, recordKeyVersion, and one of alarmTopicArn and
//   alarmEmail (required). See
//   README "Deployment".
const app = new cdk.App();
const ctx = (key: string): string | undefined => {
  const v = app.node.tryGetContext(key);
  return v === undefined || v === '' ? undefined : String(v);
};
const required = (key: string): string => {
  const v = ctx(key);
  if (v === undefined) throw new Error(`context "${key}" is required (cdk synth -c ${key}=...)`);
  return v;
};

const envName = ctx('envName') ?? 'prod';
const stack = new ServiceVaultStack(app, `ServiceVault-${envName}`, {
  envName,
  image: required('image'),
  webhookUrl: required('webhookUrl'),
  relayUrl: ctx('relayUrl'),
  serviceName: ctx('serviceName'),
  apiClientSecurityGroupId: ctx('apiClientSecurityGroupId'),
  apiClientCidr: ctx('apiClientCidr'),
  apiClientCidrPublic: ctx('apiClientCidrPublic') === 'true',
  vpcCidr: ctx('vpcCidr'),
  adminBootstrapEmail: ctx('adminBootstrapEmail'),
  adminThreshold: ctx('adminThreshold') === undefined ? undefined : Number(ctx('adminThreshold')),
  approvalTtl: ctx('approvalTtl'),
  alarmTopicArn: ctx('alarmTopicArn'),
  alarmEmail: ctx('alarmEmail'),
  recordSealMigrate: ctx('recordSealMigrate') === 'true',
  recordKeyVersion: ctx('recordKeyVersion') === undefined ? undefined : Number(ctx('recordKeyVersion')),
  env: { account: process.env.CDK_DEFAULT_ACCOUNT, region: process.env.CDK_DEFAULT_REGION },
  description: `VettID service vault (${envName})`,
});
cdk.Tags.of(stack).add('project', 'vettid');
cdk.Tags.of(stack).add('component', 'service-vault');
cdk.Tags.of(stack).add('env', envName);

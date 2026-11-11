#!/usr/bin/env node
// The key protection staging test (P1.3a): SignerAudit-staging in the
// management account and AnchorSigner-staging in the staging signer
// account, with no signer release (nothing signs). Staging only: it
// refuses any other environment. Deployed from the owner's own session,
// never by CI or an agent; the cutover's real wiring is P1.6's.
//
// Every value comes from context (-c name=value), none from this file:
//   signerAccount, auditAccount, region, taskRoleArn, breakGlassRoleArn,
//   signingRoleArn, votesBucketName, alarmEmail, signatureValidityDays
// e.g.
//   npx cdk --app "npx ts-node --prefer-ts-exts bin/key-protection-staging.ts" \
//     -c signerAccount=... -c auditAccount=... ... deploy SignerAudit-staging
import * as cdk from 'aws-cdk-lib';
import { AnchorSignerStack } from '../lib/anchor-signer-stack';
import { SignerAuditStack } from '../lib/signer-audit-stack';

const app = new cdk.App();
const need = (name: string): string => {
  const v = app.node.tryGetContext(name);
  if (typeof v !== 'string' || v === '') throw new Error(`key-protection-staging: -c ${name}=... is required`);
  return v;
};
const envName = app.node.tryGetContext('envName') ?? 'staging';
if (envName !== 'staging') throw new Error('key-protection-staging: staging only');
const region = need('region');
const signerAccount = need('signerAccount');
const auditAccount = need('auditAccount');
const alarmEmail = need('alarmEmail');

new SignerAuditStack(app, 'SignerAudit-staging', {
  envName, signerAccount, alarmEmail, env: { account: auditAccount, region },
});
new AnchorSignerStack(app, 'AnchorSigner-staging', {
  envName,
  taskRoleArn: need('taskRoleArn'),
  breakGlassRoleArn: need('breakGlassRoleArn'),
  signingRoleArn: need('signingRoleArn'),
  votesBucketName: need('votesBucketName'),
  alarmEmail,
  signatureValidityDays: Number(need('signatureValidityDays')),
  auditAccount,
  env: { account: signerAccount, region },
  // No release: the function isn't created, so nothing can sign.
});

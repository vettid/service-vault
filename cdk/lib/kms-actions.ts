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

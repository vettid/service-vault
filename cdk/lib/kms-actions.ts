/**
 * What the account may do with the keystore key and the anchor key:
 * administer them, never encrypt, decrypt or sign with them. PutKeyPolicy
 * stays, so a policy can be corrected without AWS support; each change
 * alarms (key_change). On the anchor (signing) key, the rotation and
 * Enable* actions do nothing.
 */
export const KEY_ADMIN_ACTIONS = [
  // CreateAlias only: kms:Create* would include CreateGrant, with which
  // any principal the account allows it could grant itself Decrypt.
  'kms:CreateAlias', 'kms:Describe*', 'kms:Enable*', 'kms:List*', 'kms:Put*', 'kms:Update*',
  'kms:Revoke*', 'kms:Disable*', 'kms:Get*', 'kms:Delete*', 'kms:TagResource', 'kms:UntagResource',
  'kms:ScheduleKeyDeletion', 'kms:CancelKeyDeletion', 'kms:RotateKeyOnDemand',
];

SELECT 
  eventTime,
  eventName,
  userIdentity.type AS identity_type,
  userIdentity.arn AS assumed_session_arn,
  userIdentity.sessionContext.sessionIssuer.arn AS role_arn_assumed,
  userIdentity.sessionContext.sessionIssuer.userName AS role_name_assumed,
  userIdentity.principalId AS assumed_by_principal,
  sourceIPAddress,
  userAgent
FROM cloudtrail_logs
WHERE eventSource = 'iam.amazonaws.com'
  AND eventName IN (
    'CreateRole', 'UpdateRole', 'DeleteRole',
    'PutRolePolicy', 'AttachRolePolicy', 'DetachRolePolicy'
  )
  AND year = '2025' AND month = '07'
ORDER BY eventTime DESC
LIMIT 100;

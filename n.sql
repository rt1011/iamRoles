-- Step 1: Find the human actor who assumed the deployment role in 23622***
WITH human_to_23622_session AS (
  SELECT 
    eventTime,
    userIdentity.arn AS human_actor,
    responseElements.assumedRoleUser.arn AS deployment_session_arn,
    sourceIPAddress
  FROM prod_cloudtrail_logs
  WHERE day = '2025-06-04'
    AND eventName = 'AssumeRole'
    AND userIdentity.arn LIKE '%@epcuac%'  -- or other SSO login marker
    AND responseElements.assumedRoleUser.arn LIKE '%23622%'  -- session in security/automation account
),

-- Step 2: Find IAM changes made using that assumed session
iam_changes AS (
  SELECT 
    eventTime,
    eventName,
    userIdentity.arn AS actor_session,
    userIdentity.sessionContext.sessionIssuer.arn AS role_arn,
    sourceIPAddress,
    awsRegion,
    requestParameters.roleName AS modified_role,
    userIdentity.accountId AS target_account
  FROM prod_cloudtrail_logs
  WHERE day = '2025-06-04'
    AND eventSource = 'iam.amazonaws.com'
    AND eventName IN (
      'CreateRole',
      'PutRolePolicy',
      'AttachRolePolicy',
      'DetachRolePolicy',
      'UpdateAssumeRolePolicy'
    )
)

-- Final: Join the IAM changes back to the original session
SELECT 
  iam.eventTime,
  iam.eventName,
  iam.modified_role,
  iam.target_account,
  iam.role_arn AS session_used,
  human.human_actor,
  human.sourceIPAddress AS human_ip,
  iam.sourceIPAddress AS action_ip
FROM iam_changes iam
JOIN human_to_23622_session human
  ON iam.actor_session = human.deployment_session_arn
ORDER BY iam.eventTime;

WITH assume_role_events AS (
  SELECT
    eventTime AS assumeTime,
    userIdentity.arn AS caller_arn,
    responseElements.roleArn AS role_assumed,
    responseElements.assumedRoleUser.arn AS assumed_session_arn,
    userIdentity.principalId AS assumed_by_principal,
    sourceIPAddress AS assume_ip
  FROM cloudtrail_logs
  WHERE eventName = 'AssumeRole'
    AND eventSource = 'sts.amazonaws.com'
    AND day BETWEEN 10 AND 18  -- adjust as needed
) 
 , iam_changes AS (
  SELECT
    eventTime AS actionTime,
    eventName,
    userIdentity.arn AS action_session_arn,
    requestParameters.roleName AS role_name_modified,
    sourceIPAddress AS action_ip
  FROM cloudtrail_logs
  WHERE eventSource = 'iam.amazonaws.com'
    AND eventName IN (
      'CreateRole', 'UpdateRole', 'DeleteRole',
      'AttachRolePolicy', 'DetachRolePolicy',
      'PutRolePolicy', 'DeleteRolePolicy'
    )
    AND day BETWEEN 10 AND 18  -- same range
)


SELECT
  ic.actionTime,
  ic.eventName,
  ic.role_name_modified,
  ic.action_session_arn,
  ar.caller_arn AS true_human_actor,
  ar.assumeTime,
  ar.assume_ip,
  ic.action_ip
FROM iam_changes ic
LEFT JOIN assume_role_events ar
  ON ic.action_session_arn = ar.assumed_session_arn
ORDER BY ic.actionTime DESC
LIMIT 100;

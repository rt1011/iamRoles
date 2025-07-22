WITH assume_role_events AS (
  SELECT
    eventTime AS assumeTime,
    json_extract_scalar(responseElements, '$.roleArn') AS role_assumed,
    json_extract_scalar(responseElements, '$.assumedRoleUser.arn') AS assumed_session_arn,
    json_extract_scalar(responseElements, '$.assumedRoleUser.principalId') AS assumed_principal_id,
    userIdentity.arn AS caller_arn,
    userIdentity.principalId AS caller_principal_id,
    sourceIPAddress AS assume_ip
  FROM ad
  WHERE eventName = 'AssumeRole'
    AND day BETWEEN DATE '2025-06-01' AND DATE '2025-06-04'
),
iam_changes AS (
  SELECT
    eventTime AS actionTime,
    eventName,
    userIdentity.arn AS action_session_arn,
    userIdentity.principalId AS action_principal_id,
    json_extract_scalar(requestParameters, '$.roleName') AS role_name_modified,
    sourceIPAddress AS action_ip
  FROM ac
  WHERE eventSource = 'iam.amazonaws.com'
    AND eventName IN (
      'CreateRole', 'UpdateRole', 'DeleteRole',
      'PutRolePolicy', 'DeleteRolePolicy',
      'AttachRolePolicy', 'DetachRolePolicy'
    )
    AND userIdentity.arn LIKE '%stacksets%'
    AND day BETWEEN DATE '2025-06-01' AND DATE '2025-06-04'
)

SELECT
  ic.actionTime,
  ic.eventName,
  ic.role_name_modified,
  ic.action_session_arn,
  COALESCE(ar2.caller_arn, ar1.caller_arn) AS resolved_actor,
  COALESCE(ar2.assumeTime, ar1.assumeTime) AS resolved_assume_time,
  COALESCE(ar2.assume_ip, ar1.assume_ip) AS resolved_assume_ip,
  ar1.caller_arn AS intermediate_actor,
  ar1.assumeTime AS intermediate_assume_time,
  ar1.assume_ip AS intermediate_ip
FROM iam_changes ic
LEFT JOIN assume_role_events ar1
  ON ic.action_principal_id = ar1.assumed_principal_id
LEFT JOIN assume_role_events ar2
  ON ar1.caller_principal_id = ar2.assumed_principal_id
ORDER BY ic.actionTime DESC
LIMIT 100;

WITH assume_role_events AS (
  SELECT
    eventTime AS assumeTime,
    json_extract_scalar(responseElements, '$.assumedRoleUser.arn') AS assumed_session_arn,
    json_extract_scalar(responseElements, '$.roleArn') AS role_assumed,
    userIdentity.arn AS caller_arn,
    sourceIPAddress AS assume_ip
  FROM "db"
  WHERE eventName = 'AssumeRole'
    AND day BETWEEN '2025/06/01' AND '2025/06/04'
),
iam_changes AS (
  SELECT
    eventTime AS actionTime,
    eventName,
    userIdentity.arn AS session_that_made_change,
    json_extract_scalar(requestParameters, '$.roleName') AS role_modified,
    sourceIPAddress AS action_ip
  FROM "db"
  WHERE eventSource = 'iam.amazonaws.com'
    AND eventName IN (
      'CreateRole', 'UpdateRole', 'DeleteRole',
      'PutRolePolicy', 'DeleteRolePolicy',
      'AttachRolePolicy', 'DetachRolePolicy'
    )
    AND day BETWEEN '2025/06/01' AND '2025/06/04'
)

SELECT
  ic.actionTime,
  ic.eventName,
  ic.role_modified,
  ic.session_that_made_change,
  ar1.caller_arn AS intermediate_actor,
  ar1.assumeTime AS intermediate_assume_time,
  ar1.assume_ip AS intermediate_ip,
  ar2.caller_arn AS true_human_actor,
  ar2.assumeTime AS human_assume_time,
  ar2.assume_ip AS human_assume_ip
FROM iam_changes ic
LEFT JOIN assume_role_events ar1
  ON ic.session_that_made_change = ar1.assumed_session_arn
LEFT JOIN assume_role_events ar2
  ON ar1.caller_arn = ar2.assumed_session_arn
ORDER BY ic.actionTime DESC
LIMIT 100;

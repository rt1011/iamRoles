WITH assumed_roles AS (
  SELECT
    from_iso8601_timestamp(eventTime) AS assume_time,
    REGEXP_EXTRACT(userIdentity.arn, 'assumed-role/([^/]+)', 1) AS role_name,
    REGEXP_EXTRACT(userIdentity.arn, 'assumed-role/[^/]+/([^"]+)', 1) AS session_name,
    userIdentity.arn AS assumed_role_arn
  FROM "myDB"
  WHERE eventName = 'AssumeRole'
    AND userIdentity.arn LIKE '%org%'
    AND day BETWEEN DATE '2025-06-10' AND DATE '2025-06-11'
),

cloudformation_events AS (
  SELECT
    from_iso8601_timestamp(eventTime) AS event_time,
    userIdentity.sessionContext.sessionIssuer.arn AS role_arn,
    REGEXP_EXTRACT(userIdentity.arn, 'assumed-role/[^/]+/([^"]+)', 1) AS session_name,
    eventName,
    json_extract_scalar(requestParameters, '$.roleName') AS iam_resource_modified
  FROM "myDB"
  WHERE eventSource = 'iam.amazonaws.com'
    AND userAgent LIKE 'cloudformation.amazonaws.com%'
    AND eventName IN (
      'CreateRole', 'UpdateRole', 'DeleteRole',
      'AttachRolePolicy', 'DetachRolePolicy',
      'PutRolePolicy', 'DeleteRolePolicy',
      'CreateUser', 'UpdateUser', 'DeleteUser',
      'CreatePolicy', 'DeletePolicy',
      'CreateGroup', 'UpdateGroup', 'DeleteGroup',
      'AddUserToGroup', 'RemoveUserFromGroup'
    )
    AND from_iso8601_timestamp(eventTime) >= current_date - INTERVAL '15' DAY
)

SELECT
  c.event_time,
  a.session_name AS real_user,
  c.session_name,
  c.eventName,
  c.iam_resource_modified,
  c.role_arn
FROM cloudformation_events c
JOIN assumed_roles a
  ON c.session_name = a.session_name
  AND c.session_name LIKE CONCAT('%', a.role_name, '%')
  AND c.event_time BETWEEN a.assume_time AND a.assume_time + INTERVAL '60' MINUTE
ORDER BY c.event_time DESC
LIMIT 100;

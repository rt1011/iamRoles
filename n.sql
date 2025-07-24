WITH assume_chain AS (
  SELECT 
    from_iso8601_timestamp(eventTime) AS assume_time,
    json_extract_scalar(responseElements, '$.assumedRoleUser.arn') AS session_arn,
    REGEXP_EXTRACT(json_extract_scalar(responseElements, '$.assumedRoleUser.arn'), 'assumed-role/([^/]+)') AS session_role_name,
    userIdentity.arn AS caller_arn,
    REGEXP_EXTRACT(userIdentity.arn, 'assumed-role/([^/]+)') AS caller_role_name
  FROM bcadfasfdas
  WHERE eventName = 'AssumeRole'
    AND day BETWEEN '2025/06/01' AND '2025/06/10'
),

iam_creations AS (
  SELECT 
    from_iso8601_timestamp(eventTime) AS event_time,
    userIdentity.arn AS acting_session_arn,
    REGEXP_EXTRACT(userIdentity.arn, 'assumed-role/([^/]+)') AS acting_role_name,
    eventName,
    requestParameters,
    accountId
  FROM bcadfasfdas
  WHERE eventsource = 'iam.amazonaws.com'
    AND eventname IN (
        'CreateRole', 'PutRolePolicy', 'AttachRolePolicy',
        'CreateUser', 'PutUserPolicy', 'AttachUserPolicy',
        'CreateGroup', 'PutGroupPolicy', 'AttachGroupPolicy'
    )
    AND day BETWEEN '2025/06/01' AND '2025/06/10'
),

first_hop AS (
  SELECT 
    i.*,
    a1.caller_arn AS intermediate_arn
  FROM iam_creations i
  LEFT JOIN assume_chain a1
    ON i.acting_role_name = a1.session_role_name
),

final_hop AS (
  SELECT 
    f.*,
    a2.caller_arn AS true_human_actor
  FROM first_hop f
  LEFT JOIN assume_chain a2
    ON REGEXP_EXTRACT(f.intermediate_arn, 'assumed-role/([^/]+)') = a2.session_role_name
)

SELECT 
  event_time,
  eventName,
  accountId,
  acting_session_arn,
  intermediate_arn,
  true_human_actor
FROM final_hop
WHERE true_human_actor LIKE '%bankname%'
ORDER BY event_time DESC
LIMIT 100;

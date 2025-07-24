WITH assumed_roles AS (
  SELECT 
    eventID AS assume_event_id,
    eventTime AS assume_time,
    responseElements.assumedRoleUser.arn AS session_arn,
    userIdentity.arn AS human_actor,
    userIdentity.type AS actor_type,
    userIdentity.sessionContext.sessionIssuer.arn AS assumed_role_arn
  FROM a
  WHERE eventName = 'AssumeRole'
    AND day BETWEEN DATE '2025-06-01' AND DATE '2025-06-10'
),

iam_creations AS (
  SELECT 
    eventTime,
    eventID,
    eventName,
    userIdentity.principalId,
    userIdentity.arn AS acting_session_arn,
    userIdentity.sessionContext.sessionIssuer.arn AS issued_role_arn,
    requestParameters,
    sourceIPAddress,
    awsRegion,
    accountId
  FROM a
  WHERE eventsource = 'iam.amazonaws.com'
    AND eventname IN (
        'CreateRole', 'CreateUser', 'CreatePolicy', 'CreateGroup',
        'PutRolePolicy', 'PutUserPolicy', 'PutGroupPolicy',
        'AttachRolePolicy', 'AttachUserPolicy', 'AttachGroupPolicy'
    )
    AND day BETWEEN DATE '2025-06-01' AND DATE '2025-06-10'
)

SELECT 
  i.eventTime,
  i.eventName,
  i.accountId,
  i.sourceIPAddress,
  i.awsRegion,
  i.requestParameters,
  i.acting_session_arn,
  a.human_actor AS true_actor,
  a.actor_type,
  a.assume_time AS role_assumed_at
FROM iam_creations i
LEFT JOIN assumed_roles a
  ON i.acting_session_arn = a.session_arn
  AND i.eventTime BETWEEN a.assume_time AND a.assume_time + interval '1' hour
ORDER BY i.eventTime DESC;

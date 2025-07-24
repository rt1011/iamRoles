WITH assumed_roles AS (
  SELECT 
    responseElements.assumedRoleUser.arn AS session_arn,
    userIdentity.arn AS human_actor
  FROM a
  WHERE eventName = 'AssumeRole'
    AND day BETWEEN '2025/06/04' AND '2025/06/04'
),

iam_creations AS (
  SELECT 
    userIdentity.arn AS acting_session_arn,
    eventName,
    eventTime,
    accountId
  FROM a
  WHERE eventsource = 'iam.amazonaws.com'
    AND eventname IN (
        'CreateRole', 'CreateUser', 'CreatePolicy', 'CreateGroup',
        'PutRolePolicy', 'PutUserPolicy', 'PutGroupPolicy',
        'AttachRolePolicy', 'AttachUserPolicy', 'AttachGroupPolicy'
    )
    AND day BETWEEN '2025/06/04' AND '2025/06/04'
)

SELECT 
  i.eventTime,
  i.eventName,
  i.acting_session_arn,
  a.session_arn,
  a.human_actor
FROM iam_creations i
LEFT JOIN assumed_roles a
  ON i.acting_session_arn LIKE CONCAT('%', a.session_arn)
ORDER BY i.eventTime DESC
LIMIT 50;

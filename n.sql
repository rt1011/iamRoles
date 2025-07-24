-- First, get the human actor and assumed session details
WITH assumed_sessions AS (
  SELECT 
    eventTime,
    userIdentity.sessionContext.sessionIssuer.arn AS role_arn,
    userIdentity.arn AS caller_arn,
    userIdentity.sessionContext.sessionIssuer.userName AS role_name,
    userIdentity.sessionContext.sessionIssuer.accountId AS account_id,
    userIdentity.sessionContext.sessionIssuer.type AS issuer_type,
    userIdentity.sessionContext.sessionIssuer.userName AS issuer_name,
    userIdentity.sessionContext.sessionIssuer.arn AS assumed_session_arn,
    sourceIPAddress,
    eventName
  FROM cloudtrail_logs
  WHERE eventName = 'AssumeRole'
    AND userIdentity.type = 'AssumedRole'
    AND userIdentity.arn LIKE '%ad%' -- Your identifying tag
    AND userIdentity.sessionContext.sessionIssuer.arn LIKE '%IAM%' -- optional filter
)

-- Then, use that to filter other events that use the same session ARN
SELECT 
  ct.eventTime,
  ct.eventName,
  ct.userIdentity.sessionContext.sessionIssuer.arn AS used_session_arn,
  ct.userIdentity.arn AS actual_caller,
  ct.sourceIPAddress,
  assumed_sessions.caller_arn AS true_human_actor
FROM cloudtrail_logs ct
JOIN assumed_sessions
  ON ct.userIdentity.sessionContext.sessionIssuer.arn = assumed_sessions.assumed_session_arn
WHERE ct.eventTime BETWEEN timestamp '2025-06-01 00:00:00' AND timestamp '2025-06-05 23:59:59'
  AND ct.eventSource = 'cloudformation.amazonaws.com'

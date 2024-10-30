SELECT 
    eventTime,
    eventName,
    userIdentity.arn AS user_arn,
    userIdentity.type AS user_type,
    eventSource,
    awsRegion,
    sourceIPAddress,
    requestParameters,
    responseElements,
    errorCode,
    errorMessage,
    CONCAT(
        COALESCE(requestParameters.resourceId, ''),
        COALESCE(requestParameters.bucketName, ''),
        COALESCE(requestParameters.functionName, ''),
        COALESCE(requestParameters.groupId, ''),
        COALESCE(requestParameters.policyArn, ''),
        COALESCE(requestParameters.roleName, ''),
        COALESCE(requestParameters.ruleName, '')
    ) AS resource_name
FROM 
    cloudtrail_logs
WHERE 
    eventName IN ('CreateResource', 'PutResource', 'DeleteResource',
                  'CreateBucket', 'PutBucket', 'DeleteBucket',
                  'CreateFunction', 'UpdateFunction', 'DeleteFunction',
                  'CreateRole', 'UpdateRole', 'DeleteRole',
                  'CreatePolicy', 'PutPolicy', 'DeletePolicy',
                  'CreateRule', 'PutRule', 'DeleteRule')
ORDER BY 
    eventTime DESC
LIMIT 100;

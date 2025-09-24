def get_policy_conditions_and_denies(iam_client, role_name):
    conditions = []
    deny_actions = []

    # --- Inline policies ---
    inline_policies = iam_client.list_role_policies(RoleName=role_name)['PolicyNames']
    for policy_name in inline_policies:
        policy_document = iam_client.get_role_policy(
            RoleName=role_name,
            PolicyName=policy_name
        )['PolicyDocument']

        statements = policy_document.get('Statement', [])
        if isinstance(statements, dict):
            statements = [statements]

        for statement in statements:
            if isinstance(statement, dict):
                if 'Condition' in statement:
                    conditions.append(statement['Condition'])
                if statement.get('Effect') == 'Deny':
                    deny_actions.extend(statement.get('Action', []))

    # --- Managed policies ---
    managed_policies = iam_client.list_attached_role_policies(RoleName=role_name)['AttachedPolicies']
    for policy in managed_policies:
        policy_arn = policy['PolicyArn']
        policy_details = iam_client.get_policy(PolicyArn=policy_arn)['Policy']

        # Try to get DefaultVersionId safely
        policy_version = policy_details.get('DefaultVersionId')
        if not policy_version:
            # fallback: query versions
            versions = iam_client.list_policy_versions(PolicyArn=policy_arn)['Versions']
            default_version = next((v for v in versions if v.get('IsDefaultVersion')), versions[0])
            policy_version = default_version['VersionId']

        # Get the actual document
        policy_document = iam_client.get_policy_version(
            PolicyArn=policy_arn,
            VersionId=policy_version
        )['PolicyVersion']['Document']

        statements = policy_document.get('Statement', [])
        if isinstance(statements, dict):
            statements = [statements]

        for statement in statements:
            if isinstance(statement, dict):
                if 'Condition' in statement:
                    conditions.append(statement['Condition'])
                if statement.get('Effect') == 'Deny':
                    deny_actions.extend(statement.get('Action', []))

    return conditions, deny_actions

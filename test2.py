def check_privileged_actions(iam_client, role_name):
    allow_actions = []
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
                actions = statement.get('Action', [])
                if isinstance(actions, str):
                    actions = [actions]

                if statement.get('Effect') == 'Allow':
                    allow_actions.append((policy_name, actions))
                elif statement.get('Effect') == 'Deny':
                    deny_actions.append((policy_name, actions))

    # --- Managed policies ---
    managed_policies = iam_client.list_attached_role_policies(RoleName=role_name)['AttachedPolicies']
    for policy in managed_policies:
        policy_arn = policy['PolicyArn']
        policy_details = iam_client.get_policy(PolicyArn=policy_arn)['Policy']

        policy_version = policy_details.get('DefaultVersionId')
        if not policy_version:
            versions = iam_client.list_policy_versions(PolicyArn=policy_arn)['Versions']
            default_version = next((v for v in versions if v.get('IsDefaultVersion')), versions[0])
            policy_version = default_version['VersionId']

        policy_document = iam_client.get_policy_version(
            PolicyArn=policy_arn,
            VersionId=policy_version
        )['PolicyVersion']['Document']

        statements = policy_document.get('Statement', [])
        if isinstance(statements, dict):
            statements = [statements]

        for statement in statements:
            if isinstance(statement, dict):
                actions = statement.get('Action', [])
                if isinstance(actions, str):
                    actions = [actions]

                if statement.get('Effect') == 'Allow':
                    allow_actions.append((policy['PolicyName'], actions))
                elif statement.get('Effect') == 'Deny':
                    deny_actions.append((policy['PolicyName'], actions))

    return allow_actions, deny_actions

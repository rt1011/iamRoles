import boto3
import csv
from datetime import datetime

# Constants: Privileged actions keywords that modify resources
PRIVILEGED_ACTIONS_KEYWORDS = ["Create", "Update", "Modify", "Put", "Delete", "Write", "Attach", "Detach"]

def list_iam_users():
    iam_client = boto3.client('iam')
    users = []
    paginator = iam_client.get_paginator('list_users')
    for response in paginator.paginate():
        users.extend(response['Users'])
    print(f"Total IAM Users found: {len(users)}")
    return users, iam_client

def get_combined_policies(iam_client, user_name):
    policies = []
    
    # Inline policies
    inline_policies = []
    inline_paginator = iam_client.get_paginator('list_user_policies')
    for inline_response in inline_paginator.paginate(UserName=user_name):
        inline_policies.extend(inline_response['PolicyNames'])
    
    # Managed policies
    managed_policies = []
    managed_paginator = iam_client.get_paginator('list_attached_user_policies')
    for managed_response in managed_paginator.paginate(UserName=user_name):
        managed_policies.extend(managed_response['AttachedPolicies'])
    
    # Group policies
    group_policies = []
    groups = iam_client.list_groups_for_user(UserName=user_name)['Groups']
    for group in groups:
        group_name = group['GroupName']
        
        # Inline policies attached to the group
        group_inline_policies = iam_client.list_group_policies(GroupName=group_name)['PolicyNames']
        for policy_name in group_inline_policies:
            group_policies.append(f"{group_name}-inline:{policy_name}")
        
        # Managed policies attached to the group
        group_managed_policies = iam_client.list_attached_group_policies(GroupName=group_name)['AttachedPolicies']
        for policy in group_managed_policies:
            group_policies.append(f"{group_name}-managed:{policy['PolicyName']}")
    
    # Combine all policies
    policies.extend(inline_policies)
    policies.extend([policy['PolicyName'] for policy in managed_policies])
    policies.extend(group_policies)
    
    print(f"User: {user_name}, Inline Policies: {inline_policies}, Managed Policies: {[policy['PolicyName'] for policy in managed_policies]}, Group Policies: {group_policies}")
    return sorted(policies, key=lambda s: s.lower()), len(policies)

def get_policy_conditions_and_denies(iam_client, user_name):
    conditions = []
    deny_actions = []
    
    # Inline and managed policies (user-specific)
    inline_policies = []
    inline_paginator = iam_client.get_paginator('list_user_policies')
    for inline_response in inline_paginator.paginate(UserName=user_name):
        inline_policies.extend(inline_response['PolicyNames'])
    for policy_name in inline_policies:
        policy_document = iam_client.get_user_policy(UserName=user_name, PolicyName=policy_name)['PolicyDocument']
        for statement in policy_document.get('Statement', []):
            if 'Condition' in statement:
                conditions.append(statement['Condition'])
            if statement.get('Effect') == 'Deny':
                deny_actions.extend(statement.get('Action', []))
    
    # Managed policies (user-specific)
    managed_policies = []
    managed_paginator = iam_client.get_paginator('list_attached_user_policies')
    for managed_response in managed_paginator.paginate(UserName=user_name):
        managed_policies.extend(managed_response['AttachedPolicies'])
    for policy in managed_policies:
        policy_arn = policy['PolicyArn']
        policy_version = iam_client.get_policy(PolicyArn=policy_arn)['Policy']['DefaultVersionId']
        policy_document = iam_client.get_policy_version(PolicyArn=policy_arn, VersionId=policy_version)['PolicyVersion']['Document']
        for statement in policy_document.get('Statement', []):
            if 'Condition' in statement:
                conditions.append(statement['Condition'])
            if statement.get('Effect') == 'Deny':
                deny_actions.extend(statement.get('Action', []))
    
    # Group policies
    groups = iam_client.list_groups_for_user(UserName=user_name)['Groups']
    for group in groups:
        group_name = group['GroupName']
        
        # Inline policies attached to the group
        group_inline_policies = iam_client.list_group_policies(GroupName=group_name)['PolicyNames']
        for policy_name in group_inline_policies:
            policy_document = iam_client.get_group_policy(GroupName=group_name, PolicyName=policy_name)['PolicyDocument']
            for statement in policy_document.get('Statement', []):
                if 'Condition' in statement:
                    conditions.append(statement['Condition'])
                if statement.get('Effect') == 'Deny':
                    deny_actions.extend(statement.get('Action', []))
        
        # Managed policies attached to the group
        group_managed_policies = iam_client.list_attached_group_policies(GroupName=group_name)['AttachedPolicies']
        for policy in group_managed_policies:
            policy_arn = policy['PolicyArn']
            policy_version = iam_client.get_policy(PolicyArn=policy_arn)['Policy']['DefaultVersionId']
            policy_document = iam_client.get_policy_version(PolicyArn=policy_arn, VersionId=policy_version)['PolicyVersion']['Document']
            for statement in policy_document.get('Statement', []):
                if 'Condition' in statement:
                    conditions.append(statement['Condition'])
                if statement.get('Effect') == 'Deny':
                    deny_actions.extend(statement.get('Action', []))
    
    print(f"User: {user_name}, Conditions: {conditions}, Deny Actions: {deny_actions}")
    return conditions, deny_actions

def check_privileged_actions(iam_client, user_name):
    allow_actions = []
    deny_actions = []
    
    # User's direct policies
    inline_policies = []
    inline_paginator = iam_client.get_paginator('list_user_policies')
    for inline_response in inline_paginator.paginate(UserName=user_name):
        inline_policies.extend(inline_response['PolicyNames'])
    for policy_name in inline_policies:
        policy_document = iam_client.get_user_policy(UserName=user_name, PolicyName=policy_name)['PolicyDocument']
        for statement in policy_document.get('Statement', []):
            actions = statement.get('Action', [])
            if isinstance(actions, str):
                actions = [actions]
            if statement.get('Effect') == 'Allow':
                allow_actions.append((policy_name, actions))
            elif statement.get('Effect') == 'Deny':
                deny_actions.append((policy_name, actions))

    # Managed policies (user-specific)
    managed_policies = []
    managed_paginator = iam_client.get_paginator('list_attached_user_policies')
    for managed_response in managed_paginator.paginate(UserName=user_name):
        managed_policies.extend(managed_response['AttachedPolicies'])
    for policy in managed_policies:
        policy_arn = policy['PolicyArn']
        policy_version = iam_client.get_policy(PolicyArn=policy_arn)['Policy']['DefaultVersionId']
        policy_document = iam_client.get_policy_version(PolicyArn=policy_arn, VersionId=policy_version)['PolicyVersion']['Document']
        for statement in policy_document.get('Statement', []):
            actions = statement.get('Action', [])
            if isinstance(actions, str):
                actions = [actions]
            if statement.get('Effect') == 'Allow':
                allow_actions.append((policy['PolicyName'], actions))
            elif statement.get('Effect') == 'Deny':
                deny_actions.append((policy['PolicyName'], actions))

    # Group policies
    groups = iam_client.list_groups_for_user(UserName=user_name)['Groups']
    for group in groups:
        group_name = group['GroupName']
        
        # Inline policies attached to the group
        group_inline_policies = iam_client.list_group_policies(GroupName=group_name)['PolicyNames']
        for policy_name in group_inline_policies:
            policy_document = iam_client.get_group_policy(GroupName=group_name, PolicyName=policy_name)['PolicyDocument']
            for statement in policy_document.get('Statement', []):
                actions = statement.get('Action', [])
                if isinstance(actions, str):
                    actions = [actions]
                if statement.get('Effect') == 'Allow':
                    allow_actions.append((f"{group_name}-inline:{policy_name}", actions))
                elif statement.get('Effect') == 'Deny':
                    deny_actions.append((f"{group_name}-inline:{policy_name}", actions))
        
        # Managed policies attached to the group
        group_managed_policies = iam_client.list_attached_group_policies(GroupName=group_name)['AttachedPolicies']
        for policy in group_managed_policies:
            policy_arn = policy['PolicyArn']
            policy_version = iam_client.get_policy(PolicyArn=policy_arn)['Policy']['DefaultVersionId']
            policy_document = iam_client.get_policy_version(PolicyArn=policy_arn, VersionId=policy_version)['PolicyVersion']['Document']
            for statement in policy_document.get('Statement', []):
                actions = statement.get('Action', [])
                if isinstance(actions, str):
                    actions = [actions]
                if statement.get('Effect') == 'Allow':
                    allow_actions.append((f"{group_name}-managed:{policy['PolicyName']}", actions))
                elif statement.get('Effect') == 'Deny':
                    deny_actions.append((f"{group_name}-managed:{policy['PolicyName']}", actions))

    print(f"User: {user_name}, Allow Actions: {allow_actions}, Deny Actions: {deny_actions}")
    return allow_actions, deny_actions

# The rest of the code remains the same, including gather_

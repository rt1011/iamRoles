import boto3
import csv

# The account_aliases mapping: update with your account IDs and names.
account_aliases = {"3213121": "MyAccount", "33434334": "secondaccount"}

def is_privileged_action(action):
    """
    Returns True only if the action is exactly "ssm:StartSession" (case-insensitive) or "*" .
    """
    normalized_action = action.lower()
    return normalized_action == "*" or normalized_action == "ssm:startsession"

def list_iam_roles_local(iam_client):
    """
    Lists IAM roles in the local account using the provided IAM client.
    """
    roles = []
    paginator = iam_client.get_paginator('list_roles')
    for response in paginator.paginate():
        roles.extend(response['Roles'])
    return roles

def get_combined_policies(iam_client, role_name):
    policies = []
    inline_policies = iam_client.list_role_policies(RoleName=role_name)['PolicyNames']
    managed_policies = iam_client.list_attached_role_policies(RoleName=role_name)['AttachedPolicies']
    
    policies.extend(inline_policies)  # Add inline policies
    policies.extend([policy['PolicyName'] for policy in managed_policies])  # Add managed policies
    
    policy_count = len(policies)
    sorted_policies = sorted(policies, key=lambda s: s.lower())
    
    return sorted_policies, policy_count

def get_policy_conditions_and_denies(iam_client, role_name):
    conditions = []
    deny_actions = []
    
    inline_policies = iam_client.list_role_policies(RoleName=role_name)['PolicyNames']
    for policy_name in inline_policies:
        policy_document = iam_client.get_role_policy(RoleName=role_name, PolicyName=policy_name)['PolicyDocument']
        for statement in policy_document.get('Statement', []):
            if 'Condition' in statement:
                conditions.append(statement['Condition'])
            if statement.get('Effect') == 'Deny':
                deny_actions.extend(statement.get('Action', []))
    
    managed_policies = iam_client.list_attached_role_policies(RoleName=role_name)['AttachedPolicies']
    for policy in managed_policies:
        policy_arn = policy['PolicyArn']
        policy_version = iam_client.get_policy(PolicyArn=policy_arn)['Policy']['DefaultVersionId']
        policy_document = iam_client.get_policy_version(PolicyArn=policy_arn, VersionId=policy_version)['PolicyVersion']['Document']
        for statement in policy_document.get('Statement', []):
            if 'Condition' in statement:
                conditions.append(statement['Condition'])
            if statement.get('Effect') == 'Deny':
                deny_actions.extend(statement.get('Action', []))
    
    return conditions, deny_actions

def check_privileged_role(iam_client, role_name, only_privileged=True):
    tags_response = iam_client.list_role_tags(RoleName=role_name)
    tags = {tag['Key']: tag['Value'] for tag in tags_response.get('Tags', [])}
    
    if only_privileged and tags.get('Privileged') != 'Yes':
        return False, tags
    return True, tags

def check_privileged_actions(iam_client, role_name):
    allow_actions = []
    deny_actions = []
    
    inline_policies = iam_client.list_role_policies(RoleName=role_name)['PolicyNames']
    for policy_name in inline_policies:
        policy_document = iam_client.get_role_policy(RoleName=role_name, PolicyName=policy_name)['PolicyDocument']
        for statement in policy_document.get('Statement', []):
            actions = statement.get('Action', [])
            if isinstance(actions, str):
                actions = [actions]
            if statement.get('Effect') == 'Allow':
                allow_actions.append((policy_name, actions))
            elif statement.get('Effect') == 'Deny':
                deny_actions.append((policy_name, actions))

    managed_policies = iam_client.list_attached_role_policies(RoleName=role_name)['AttachedPolicies']
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

    return allow_actions, deny_actions

def extract_privileged_actions(allow_actions):
    privileged_actions = []
    
    for policy_name, actions in allow_actions:
        privileged_actions_for_policy = [action for action in actions if is_privileged_action(action)]
        if privileged_actions_for_policy:
            privileged_actions.append(
                f"{policy_name}[{', '.join(sorted(set(privileged_actions_for_policy), key=lambda x: x.lower()))}]"
            )
    
    return privileged_actions

def can_modify_services(actions):
    for _, action_list in actions:
        for action in action_list:
            if is_privileged_action(action):
                return True
    return False

def gather_iam_roles_from_local_account(only_privileged=True):
    """
    Gathers IAM roles from the local account using local credentials.
    """
    iam_client = boto3.client('iam')
    sts_client = boto3.client('sts')
    account_id = sts_client.get_caller_identity()['Account']
    # Get the account alias from the mapping; default to "LocalAccount" if not found.
    account_alias = account_aliases.get(account_id, "LocalAccount")
    
    fieldnames = [
        'AccountID', 'AccountAlias', 'RoleName', 'Policies', 'PolicyCount',
        'Conditions', 'DenyActions', 'Tags', 'PrivilegedActions', 'CanModifyServices'
    ]
    role_data = []

    roles = list_iam_roles_local(iam_client)

    for role in roles:
        role_name = role['RoleName']
        is_priv, tags = check_privileged_role(iam_client, role_name, only_privileged)
        
        if is_priv:
            policies, policy_count = get_combined_policies(iam_client, role_name)
            conditions, _ = get_policy_conditions_and_denies(iam_client, role_name)
            allow_actions_list, deny_actions_list = check_privileged_actions(iam_client, role_name)
            
            privileged_actions = extract_privileged_actions(allow_actions_list)
            can_modify = can_modify_services(allow_actions_list)

            denies = "||| ".join([f"{policy}[{'| '.join(actions)}]" for policy, actions in deny_actions_list])
            priv = "| ".join(privileged_actions) if privileged_actions else "None"

            role_info = {
                'AccountID': account_id,
                'AccountAlias': account_alias,
                'RoleName': role_name,
                'Policies': ', '.join(policies),
                'PolicyCount': policy_count,
                'Conditions': conditions if conditions else "None",
                'DenyActions': denies,
                'Tags': tags,
                'PrivilegedActions': priv,
                'CanModifyServices': can_modify
            }

            role_data.append(role_info)
    
    return fieldnames, role_data

if __name__ == "__main__":
    fields, data = gather_iam_roles_from_local_account(only_privileged=True)
    
    # Get the account alias for naming the CSV file.
    sts_client = boto3.client('sts')
    account_id = sts_client.get_caller_identity()['Account']
    account_alias = account_aliases.get(account_id, "LocalAccount")
    output_csv = f'iam_roles_output_{account_alias}.csv'
    
    # Write the output to a CSV file.
    with open(output_csv, mode='w', newline='') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=fields)
        writer.writeheader()
        for role_info in data:
            writer.writerow(role_info)
    
    print(f"CSV file '{output_csv}' has been written.")

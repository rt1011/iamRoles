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
    return users, iam_client

def get_combined_policies(iam_client, user_name):
    policies = []
    inline_policies = iam_client.list_user_policies(UserName=user_name)['PolicyNames']
    managed_policies = iam_client.list_attached_user_policies(UserName=user_name)['AttachedPolicies']
    policies.extend(inline_policies)
    policies.extend([policy['PolicyName'] for policy in managed_policies])
    policy_count = len(policies)
    sorted_policies = sorted(policies, key=lambda s: s.lower())
    return sorted_policies, policy_count

def get_policy_conditions_and_denies(iam_client, user_name):
    conditions = []
    deny_actions = []
    inline_policies = iam_client.list_user_policies(UserName=user_name)['PolicyNames']
    for policy_name in inline_policies:
        policy_document = iam_client.get_user_policy(UserName=user_name, PolicyName=policy_name)['PolicyDocument']
        for statement in policy_document.get('Statement', []):
            if 'Condition' in statement:
                conditions.append(statement['Condition'])
            if statement.get('Effect') == 'Deny':
                deny_actions.extend(statement.get('Action', []))
    managed_policies = iam_client.list_attached_user_policies(UserName=user_name)['AttachedPolicies']
    for policy in managed_policies:
        policy_arn = policy['PolicyArn']
        policy_version = iam_client.get_policy(PolicyArn=policy_arn)['Policy']['DefaultVersionId']
        policy_document = iam_client.get_policy_version(PolicyArn=policy_arn, VersionId=policy_version)['PolicyVersion']['Document']
        for statement in policy_document.get('Statement', []):
            if 'Condition' in statement:
                conditions.append(statement['Condition'])
            if statement.get('Effect'] == 'Deny':
                deny_actions.extend(statement.get('Action', []))
    return conditions, deny_actions

def check_privileged_actions(iam_client, user_name):
    allow_actions = []
    deny_actions = []
    inline_policies = iam_client.list_user_policies(UserName=user_name)['PolicyNames']
    for policy_name in inline_policies:
        policy_document = iam_client.get_user_policy(UserName=user_name, PolicyName=policy_name)['PolicyDocument']
        for statement in policy_document.get('Statement', []):
            actions = statement.get('Action', [])
            if isinstance(actions, str):
                actions = [actions]
            if statement.get('Effect'] == 'Allow':
                allow_actions.append((policy_name, actions))
            elif statement.get('Effect'] == 'Deny':
                deny_actions.append((policy_name, actions))
    managed_policies = iam_client.list_attached_user_policies(UserName=user_name)['AttachedPolicies']
    for policy in managed_policies:
        policy_arn = policy['PolicyArn']
        policy_version = iam_client.get_policy(PolicyArn=policy_arn)['Policy']['DefaultVersionId']
        policy_document = iam_client.get_policy_version(PolicyArn=policy_arn, VersionId=policy_version)['PolicyVersion']['Document']
        for statement in policy_document.get('Statement', []):
            actions = statement.get('Action', [])
            if isinstance(actions, str):
                actions = [actions]
            if statement.get('Effect'] == 'Allow':
                allow_actions.append((policy['PolicyName'], actions))
            elif statement.get('Effect'] == 'Deny':
                deny_actions.append((policy['PolicyName'], actions))
    return allow_actions, deny_actions

def extract_privileged_actions(allow_actions):
    privileged_actions = []
    for policy_name, actions in allow_actions:
        privileged_actions_for_policy = [action for action in actions if is_privileged_action(action)]
        if privileged_actions_for_policy:
            privileged_actions.append(f"{policy_name}[{', '.join(sorted(set(privileged_actions_for_policy), key=lambda x: x.lower()))}]")
    return privileged_actions

def is_privileged_action(action):
    action_name = action.split(":")[-1]
    if action_name == "*":
        return True
    for keyword in PRIVILEGED_ACTIONS_KEYWORDS:
        if action_name.lower().startswith(keyword.lower()):
            return True
    return False

def can_modify_services(actions):
    for _, action_list in actions:
        for action in action_list:
            if is_privileged_action(action):
                return True
    return False

def gather_iam_users():
    fieldnames = ['UserName', 'Policies', 'PolicyCount', 'Conditions', 'DenyActions', 'PrivilegedActions', 'CanModifyServices']
    user_data = []
    users, iam_client = list_iam_users()
    for user in users:
        user_name = user['UserName']
        policies, policy_count = get_combined_policies(iam_client, user_name)
        conditions, deny_actions = get_policy_conditions_and_denies(iam_client, user_name)
        allow_actions_list, deny_actions_list = check_privileged_actions(iam_client, user_name)
        privileged_actions = extract_privileged_actions(allow_actions_list)
        can_modify = can_modify_services(allow_actions_list)
        denies = "||| ".join([f"{policy}[{'| '.join(actions)}]" for policy, actions in deny_actions_list])
        priv = "| ".join(privileged_actions) if privileged_actions else "None"
        user_info = {
            'UserName': user_name,
            'Policies': ', '.join(policies),
            'PolicyCount': policy_count,
            'Conditions': conditions if conditions else "None",
            'DenyActions': denies,
            'PrivilegedActions': priv,
            'CanModifyServices': can_modify
        }
        user_data.append(user_info)
    return fieldnames, user_data

def write_to_csv(fieldnames, user_data, filename="iam_users_report"):
    """
    Writes the user data to a CSV file with the given filename.
    """
    timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
    file_path = f"/tmp/{filename}_{timestamp}.csv"
    
    with open(file_path, mode='w', newline='') as file:
        writer = csv.DictWriter(file, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(user_data)
    
    print(f"Report generated at: {file_path}")

# Run the script
if __name__ == "__main__":
    fieldnames, user_data = gather_iam_users()
    write_to_csv(fieldnames, user_data)

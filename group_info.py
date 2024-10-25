import boto3
import csv
from datetime import datetime

# Constants: Privileged actions keywords that modify resources
PRIVILEGED_ACTIONS_KEYWORDS = ["Create", "Update", "Modify", "Put", "Delete", "Write", "Attach", "Detach"]

def list_iam_groups():
    iam_client = boto3.client('iam')
    groups = []
    paginator = iam_client.get_paginator('list_groups')
    for response in paginator.paginate():
        groups.extend(response['Groups'])
    print(f"Total IAM Groups found: {len(groups)}")
    return groups, iam_client

def get_combined_policies(iam_client, group_name):
    policies = []
    
    # Inline policies
    inline_policies = []
    inline_paginator = iam_client.get_paginator('list_group_policies')
    for inline_response in inline_paginator.paginate(GroupName=group_name):
        inline_policies.extend(inline_response['PolicyNames'])
    
    # Managed policies
    managed_policies = []
    managed_paginator = iam_client.get_paginator('list_attached_group_policies')
    for managed_response in managed_paginator.paginate(GroupName=group_name):
        managed_policies.extend(managed_response['AttachedPolicies'])
    
    # Combine all policies
    policies.extend(inline_policies)
    policies.extend([policy['PolicyName'] for policy in managed_policies])
    
    print(f"Group: {group_name}, Inline Policies: {inline_policies}, Managed Policies: {[policy['PolicyName'] for policy in managed_policies]}")
    return sorted(policies, key=lambda s: s.lower()), len(policies)

def get_policy_conditions_and_denies(iam_client, group_name):
    conditions = []
    deny_actions = []
    
    # Inline policies
    inline_policies = iam_client.list_group_policies(GroupName=group_name)['PolicyNames']
    for policy_name in inline_policies:
        policy_document = iam_client.get_group_policy(GroupName=group_name, PolicyName=policy_name)['PolicyDocument']
        for statement in policy_document.get('Statement', []):
            if 'Condition' in statement:
                conditions.append(statement['Condition'])
            if statement.get('Effect') == 'Deny':
                deny_actions.extend(statement.get('Action', []))
    
    # Managed policies
    managed_policies = iam_client.list_attached_group_policies(GroupName=group_name)['AttachedPolicies']
    for policy in managed_policies:
        policy_arn = policy['PolicyArn']
        policy_version = iam_client.get_policy(PolicyArn=policy_arn)['Policy']['DefaultVersionId']
        policy_document = iam_client.get_policy_version(PolicyArn=policy_arn, VersionId=policy_version)['PolicyVersion']['Document']
        for statement in policy_document.get('Statement', []):
            if 'Condition' in statement:
                conditions.append(statement['Condition'])
            if statement.get('Effect') == 'Deny':
                deny_actions.extend(statement.get('Action', []))
    
    print(f"Group: {group_name}, Conditions: {conditions}, Deny Actions: {deny_actions}")
    return conditions, deny_actions

def check_privileged_actions(iam_client, group_name):
    allow_actions = []
    deny_actions = []
    
    # Inline policies
    inline_policies = iam_client.list_group_policies(GroupName=group_name)['PolicyNames']
    for policy_name in inline_policies:
        policy_document = iam_client.get_group_policy(GroupName=group_name, PolicyName=policy_name)['PolicyDocument']
        for statement in policy_document.get('Statement', []):
            actions = statement.get('Action', [])
            if isinstance(actions, str):
                actions = [actions]
            if statement.get('Effect') == 'Allow':
                allow_actions.append((policy_name, actions))
            elif statement.get('Effect') == 'Deny':
                deny_actions.append((policy_name, actions))

    # Managed policies
    managed_policies = iam_client.list_attached_group_policies(GroupName=group_name)['AttachedPolicies']
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

    print(f"Group: {group_name}, Allow Actions: {allow_actions}, Deny Actions: {deny_actions}")
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

def gather_iam_groups():
    fieldnames = ['GroupName', 'Policies', 'PolicyCount', 'Conditions', 'DenyActions', 'PrivilegedActions', 'CanModifyServices']
    group_data = []
    groups, iam_client = list_iam_groups()
    for group in groups:
        group_name = group['GroupName']
        print(f"\nProcessing Group: {group_name}")
        policies, policy_count = get_combined_policies(iam_client, group_name)
        conditions, deny_actions = get_policy_conditions_and_denies(iam_client, group_name)
        allow_actions_list, deny_actions_list = check_privileged_actions(iam_client, group_name)
        privileged_actions = extract_privileged_actions(allow_actions_list)
        can_modify = can_modify_services(allow_actions_list)
        denies = "||| ".join([f"{policy}[{'| '.join(actions)}]" for policy, actions in deny_actions_list])
        priv = "| ".join(privileged_actions) if privileged_actions else "None"
        group_info = {
            'GroupName': group_name,
            'Policies': ', '.join(policies),
            'PolicyCount': policy_count,
            'Conditions': conditions if conditions else "None",
            'DenyActions': denies,
            'PrivilegedActions': priv,
            'CanModifyServices': can_modify
        }
        group_data.append(group_info)
    return fieldnames, group_data

def write_to_csv(fieldnames, group_data, filename="iam_groups_report"):
    """
    Writes the group data to a CSV file with the given filename.
    """
    timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
    file_path = f"/tmp/{filename}_{timestamp}.csv"
    
    with open(file_path, mode='w', newline='') as file:
        writer = csv.DictWriter(file, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(group_data)
    
    print(f"Report generated at: {file_path}")

# Run the script
if __name__ == "__main__":
    fieldnames, group_data = gather_iam_groups()
    write_to_csv(fieldnames, group_data)

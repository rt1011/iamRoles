import boto3
import csv
import os
from datetime import datetime

# Constants: Privileged actions keywords that modify resources
PRIVILEGED_ACTIONS_KEYWORDS = ["Create", "Update", "Modify", "Put", "Delete", "Write", "Attach", "Detach"]

def assume_role(sts_client, acct_id, role_name="lambda1"):
    # Function to assume role in the target account, if needed
    response = sts_client.assume_role(
        RoleArn=f"arn:aws:iam::{acct_id}:role/{role_name}",
        RoleSessionName="AssumeRoleSession"
    )
    return response['Credentials']

def list_iam_roles(iam_client):
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
    
    # Count of total policies
    policy_count = len(policies)
    
    # Sort policies case-insensitively
    sorted_policies = sorted(policies, key=lambda s: s.lower())
    
    return sorted_policies, policy_count

def get_policy_conditions_and_denies(iam_client, role_name):
    conditions = []
    deny_actions = []
    
    # Get inline policy conditions and denies
    inline_policies = iam_client.list_role_policies(RoleName=role_name)['PolicyNames']
    for policy_name in inline_policies:
        policy_document = iam_client.get_role_policy(RoleName=role_name, PolicyName=policy_name)['PolicyDocument']
        for statement in policy_document.get('Statement', []):
            if 'Condition' in statement:
                conditions.append(statement['Condition'])
            if statement.get('Effect') == 'Deny':
                deny_actions.extend(statement.get('Action', []))
    
    # Get managed policy conditions and denies
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
    
    if only_privileged and tags.get('Privileged') != 'Yes':  # Case-sensitive comparison
        print(f"Skipping non-privileged role '{role_name}'")
        return False, tags
    else:
        print(f"Processing role: '{role_name}'")
        return True, tags

def is_privileged_action(action):
    """
    Check if an action is privileged based on keywords and exact wildcard matching.
    The action must:
      1. Be exactly "*".
      2. Start with a keyword from PRIVILEGED_ACTIONS_KEYWORDS.
    """
    # Split the action by ':' to separate service from action (e.g., "s3:GetObject" -> "GetObject")
    action_name = action.split(":")[-1]
    
    # Include actions that are exactly "*"
    if action_name == "*":
        return True

    # Check if action starts with any privileged keyword
    for keyword in PRIVILEGED_ACTIONS_KEYWORDS:
        if action_name.lower().startswith(keyword.lower()):
            return True
    
    # If it does not match "*", or privileged actions, return False
    return False

def check_privileged_actions(iam_client, role_name):
    allow_actions = []
    deny_actions = []
    
    # Check inline policies for allow/deny actions
    inline_policies = iam_client.list_role_policies(RoleName=role_name)['PolicyNames']
    for policy_name in inline_policies:
        policy_document = iam_client.get_role_policy(RoleName=role_name, PolicyName=policy_name)['PolicyDocument']
        for statement in policy_document.get('Statement', []):
            actions = statement.get('Action', [])
            if isinstance(actions, str):  # If single action
                actions = [actions]
            if statement.get('Effect') == 'Allow':
                allow_actions.append((policy_name, actions))
            elif statement.get('Effect') == 'Deny':
                deny_actions.append((policy_name, actions))

    # Check managed policies for allow/deny actions
    managed_policies = iam_client.list_attached_role_policies(RoleName=role_name)['AttachedPolicies']
    for policy in managed_policies:
        policy_arn = policy['PolicyArn']
        policy_version = iam_client.get_policy(PolicyArn=policy_arn)['Policy']['DefaultVersionId']
        policy_document = iam_client.get_policy_version(PolicyArn=policy_arn, VersionId=policy_version)['PolicyVersion']['Document']
        for statement in policy_document.get('Statement', []):
            actions = statement.get('Action', [])
            if isinstance(actions, str):  # If single action
                actions = [actions]
            if statement.get('Effect') == 'Allow':
                allow_actions.append((policy['PolicyName'], actions))
            elif statement.get('Effect') == 'Deny':
                deny_actions.append((policy['PolicyName'], actions))

    return allow_actions, deny_actions

def extract_privileged_actions(allow_actions):
    """
    Extract privileged actions from the list of allowed actions.
    Actions are considered privileged if they are exactly "*" or start with privileged keywords.
    """
    privileged_actions = []
    
    # Iterate over the list of allow_actions (policy_name, actions)
    for policy_name, actions in allow_actions:
        privileged_actions_for_policy = [action for action in actions if is_privileged_action(action)]
        if privileged_actions_for_policy:
            privileged_actions.append(f"{policy_name}[{', '.join(sorted(set(privileged_actions_for_policy), key=lambda x: x.lower()))}]")
    
    return privileged_actions

def can_modify_services(actions):
    """
    Check if any of the actions are considered privileged (e.g., Create, Update, Modify, Delete)
    or are exactly "*".
    """
    for _, action_list in actions:
        for action in action_list:
            if is_privileged_action(action):
                return True
    return False

def process_roles(iam_client, only_privileged=True):
    roles = list_iam_roles(iam_client)
    role_data = []
    
    for role in roles:
        role_name = role['RoleName']
        
        is_privileged, tags = check_privileged_role(iam_client, role_name, only_privileged)
        if is_privileged:
            policies, policy_count = get_combined_policies(iam_client, role_name)
            conditions, deny_actions = get_policy_conditions_and_denies(iam_client, role_name)
            allow_actions_list, deny_actions_list = check_privileged_actions(iam_client, role_name)
            
            # Extract privileged actions (in the format PolicyName[Actions])
            privileged_actions = extract_privileged_actions(allow_actions_list)

            # Check if the actions include any privileged actions or "*"
            can_modify = can_modify_services(allow_actions_list)

            # Create basic role info (including whether it can modify services)
            role_info = {
                'RoleName': role_name,
                'Policies': ', '.join(policies),  # Combined sorted policies
                'PolicyCount': policy_count,
                'Conditions': conditions if conditions else "None",  # Add conditions if available
                'DenyActions': "; ".join([f"{policy}[{', '.join(actions)}]" for policy, actions in deny_actions_list]),  # Single column for deny actions
                'Tags': tags,
                'PrivilegedActions': "; ".join(privileged_actions) if privileged_actions else "None",  # Privileged actions formatted
                'CanModifyServices': can_modify  # True if role can modify services
            }

            role_data.append(role_info)
    
    return role_data

def write_to_csv(filename, fieldnames, data):
    # Write output to CSV file
    with open(filename, mode='w', newline='') as file:
        writer = csv.DictWriter(file, fieldnames=fieldnames)
        writer.writeheader()
        for row in data:
            writer.writerow(row)
    print(f"CSV written: {filename}")

if __name__ == "__main__":
    # Running in CloudShell
    session = boto3.Session()
    iam_client = session.client('iam')
    
    fieldnames = ['RoleName', 'Policies', 'PolicyCount', 'Conditions', 'DenyActions', 'Tags', 'PrivilegedActions', 'CanModifyServices']
    
    # Process roles and check privileged actions
    role_data = process_roles(iam_client, only_privileged=True)
    
    # Define filename with timestamp
    filename = f"iam_roles_{datetime.now().strftime('%Y%m%d%H%M%S')}.csv"
    write_to_csv(filename, fieldnames, role_data)

import boto3
import csv
import os
from datetime import datetime

# Constants
EXCEL_CELL_LIMIT = 32767

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

def check_privileged_actions(iam_client, role_name):
    allow_actions = {}
    deny_actions = {}
    
    # Check inline policies for allow/deny actions
    inline_policies = iam_client.list_role_policies(RoleName=role_name)['PolicyNames']
    for policy_name in inline_policies:
        policy_document = iam_client.get_role_policy(RoleName=role_name, PolicyName=policy_name)['PolicyDocument']
        for statement in policy_document.get('Statement', []):
            actions = statement.get('Action', [])
            if isinstance(actions, str):  # If single action
                actions = [actions]
            if statement.get('Effect') == 'Allow':
                allow_actions.setdefault(policy_name, []).extend(actions)
            elif statement.get('Effect') == 'Deny':
                deny_actions.setdefault(policy_name, []).extend(actions)

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
                allow_actions.setdefault(policy['PolicyName'], []).extend(actions)
            elif statement.get('Effect') == 'Deny':
                deny_actions.setdefault(policy['PolicyName'], []).extend(actions)

    # Format the actions grouped by policy into a list of PolicyName[Actions]
    allow_actions_list = [f"{policy_name}[{', '.join(sorted(set(actions), key=lambda x: x.lower()))}]"
                          for policy_name, actions in allow_actions.items()]
    
    deny_actions_list = [f"{policy_name}[{', '.join(sorted(set(actions), key=lambda x: x.lower()))}]"
                         for policy_name, actions in deny_actions.items()]
    
    return allow_actions_list, deny_actions_list

def split_allow_actions_by_character_limit(allow_actions_list):
    """
    Splits allow actions into multiple columns ensuring no column exceeds Excel's 32,767 character limit.
    It truncates at boundaries (such as commas) to ensure the split happens after a full action is listed.
    """
    allow_action_columns = {}
    current_column = []
    char_count = 0
    column_index = 1

    for action in allow_actions_list:
        action_length = len(action)
        
        # Check if the next action would exceed the limit; if so, create a new column
        if (char_count + action_length) > EXCEL_CELL_LIMIT:
            allow_action_columns[f"AllowActions_part_{column_index}"] = "; ".join(current_column)
            column_index += 1
            current_column = []
            char_count = 0
        
        # Add action to current column and increment char count
        current_column.append(action)
        char_count += action_length + 2  # +2 accounts for the "; " separator

    # Add the last column if there are remaining actions
    if current_column:
        allow_action_columns[f"AllowActions_part_{column_index}"] = "; ".join(current_column)
    
    return allow_action_columns

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
            
            # Count the number of characters in allow actions
            allow_actions_character_count = sum(len(action) for action in allow_actions_list)

            # Create basic role info (without splitting the actions yet)
            role_info = {
                'RoleName': role_name,
                'Policies': ', '.join(policies),  # Combined sorted policies
                'PolicyCount': policy_count,
                'Conditions': conditions if conditions else "None",  # Add conditions if available
                'DenyActions': "; ".join(deny_actions_list),  # Single column for deny actions
                'Tags': tags,
                'AllowActionsCharacterCount': allow_actions_character_count  # Add the character count of allow actions
            }

            # After collecting all the information, split the allow actions based on character limit
            allow_action_columns = split_allow_actions_by_character_limit(allow_actions_list)

            # Merge with the split allow actions columns
            role_info.update(allow_action_columns)

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

def lambda_handler(event, context):
    iam_client = boto3.client('iam')
    fieldnames = ['RoleName', 'Policies', 'PolicyCount', 'Conditions', 'DenyActions', 'Tags', 'AllowActionsCharacterCount']
    
    # Add an option to filter based on privilege tags
    only_privileged = event.get('only_privileged', True)

    role_data = process_roles(iam_client, only_privileged)
    
    # Collect additional action columns created dynamically
    all_columns = set(col for row in role_data for col in row.keys())
    fieldnames.extend(sorted(all_columns - set(fieldnames)))
    
    # Ensure AllowActions is the last column and DenyActions is included before it
    fieldnames = [col for col in fieldnames if not col.startswith('AllowActions')] \
                 + [col for col in fieldnames if col.startswith('AllowActions')]
    
    # Define filename with timestamp
    filename = f"iam_roles_{datetime.now().strftime('%Y%m%d%H%M%S')}.csv"
    write_to_csv(filename, fieldnames, role_data)

if __name__ == "__main__":
    # Running in CloudShell
    session = boto3.Session()
    iam_client = session.client('iam')
    
    fieldnames = ['RoleName', 'Policies', 'PolicyCount', 'Conditions', 'DenyActions', 'Tags', 'AllowActionsCharacterCount']
    
    # Add option to split allow actions across multiple columns, 30 per column or character limit
    role_data = process_roles(iam_client, only_privileged=True)
    
    # Collect additional action columns created dynamically
    all_columns = set(col for row in role_data for col in row.keys())
    fieldnames.extend(sorted(all_columns - set(fieldnames)))

    # Ensure AllowActions is the last column and DenyActions is included before it
    fieldnames = [col for col in fieldnames if not col.startswith('AllowActions')] \
                 + [col for col in fieldnames if col.startswith('AllowActions')]
    
    # Define filename with timestamp
    filename = f"iam_roles_{datetime.now().strftime('%Y%m%d%H%M%S')}.csv"
    write_to_csv(filename, fieldnames, role_data)

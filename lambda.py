import boto3
import csv
import os
from datetime import datetime

# Constants
EXCEL_CELL_LIMIT = 32767

# List of privileged action patterns to match against
MODIFYING_ACTIONS = ['Put', 'Create', 'Delete', 'Update', 'Modify', 'Set', 
                     'Add', 'Attach', 'Remove', 'Detach', 'Run', 'Start', 
                     'Stop', 'Reboot', 'Terminate', 'Grant', 'Deny', 'Revoke', 
                     'AssumeRole', 'PassRole']

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

def split_long_text(long_text, prefix):
    """Splits long text into multiple fields if it exceeds Excel's character limit."""
    parts = []
    while len(long_text) > EXCEL_CELL_LIMIT:
        parts.append(long_text[:EXCEL_CELL_LIMIT])
        long_text = long_text[EXCEL_CELL_LIMIT:]
    
    parts.append(long_text)
    return {f"{prefix}_part_{i + 1}": part for i, part in enumerate(parts)}

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
            
            # Join the actions list into a single string for allow and deny actions
            allow_actions_text = '; '.join(allow_actions_list)
            deny_actions_text = '; '.join(deny_actions_list)
            
            # Combine allow and deny actions into one string for the PolicyActions column
            combined_policy_actions = f"Allow: {allow_actions_text}; Deny: {deny_actions_text}"
            
            # Check if the combined actions string exceeds the Excel character limit and split if necessary
            if len(combined_policy_actions) > EXCEL_CELL_LIMIT:
                policy_actions_columns = split_long_text(combined_policy_actions, "PolicyActions")
            else:
                policy_actions_columns = {"PolicyActions": combined_policy_actions}
            
            print(f"Combined policies for role {role_name}: {policies}")
            print(f"Policy count: {policy_count}")
            print(f"Conditions: {conditions}")
            print(f"Deny Actions: {deny_actions_text}")
            print(f"Allow Actions: {allow_actions_text}")
            print(f"Policy Actions: {combined_policy_actions}")
            print(f"Tags: {tags}")
            
            # Add basic role data
            role_info = {
                'RoleName': role_name,
                'Policies': ', '.join(policies),  # Combined sorted policies
                'PolicyCount': policy_count,
                'Conditions': conditions if conditions else "None",  # Add conditions if available
                'Tags': tags
            }
            
            # Merge with the split PolicyActions columns
            role_info.update(policy_actions_columns)
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
    fieldnames = ['RoleName', 'Policies', 'PolicyCount', 'Conditions', 'Tags', 'PolicyActions_part_1']
    
    # Add an option to filter based on privilege tags
    only_privileged = event.get('only_privileged', True)

    role_data = process_roles(iam_client, only_privileged)
    
    # Collect additional action columns created dynamically
    all_columns = set(col for row in role_data for col in row.keys())
    fieldnames.extend(sorted(all_columns - set(fieldnames)))
    
    # Ensure PolicyActions is the last column
    fieldnames = [col for col in fieldnames if not col.startswith('PolicyActions')] + [col for col in fieldnames if col.startswith('PolicyActions')]
    
    # Define filename with timestamp
    filename = f"iam_roles_{datetime.now().strftime('%Y%m%d%H%M%S')}.csv"
    write_to_csv(filename, fieldnames, role_data)

if __name__ == "__main__":
    # Running in CloudShell
    session = boto3.Session()
    iam_client = session.client('iam')
    
    fieldnames = ['RoleName', 'Policies', 'PolicyCount', 'Conditions', 'Tags', 'PolicyActions_part_1']
    
    # Add option to split long columns across multiple columns if needed
    role_data = process_roles(iam_client, only_privileged=True)
    
    # Collect additional action columns created dynamically
    all_columns = set(col for row in role_data for col in row.keys())
    fieldnames.extend(sorted(all_columns - set(fieldnames)))

    # Ensure PolicyActions is the last column
    fieldnames = [col for col in fieldnames if not col.startswith('PolicyActions')] + [col for col in fieldnames if col.startswith('PolicyActions')]
    
    # Define filename with timestamp
    filename = f"iam_roles_{datetime.now().strftime('%Y%m%d%H%M%S')}.csv"
    write_to_csv(filename, fieldnames, role_data)

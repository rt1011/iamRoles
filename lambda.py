import boto3
import csv
import os
from datetime import datetime

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
    privileged_actions = []
    all_actions_with_policy = {}  # Use a dictionary to group actions by policy
    can_modify_services = False
    
    # Check inline policies for privileged actions
    inline_policies = iam_client.list_role_policies(RoleName=role_name)['PolicyNames']
    for policy_name in inline_policies:
        policy_document = iam_client.get_role_policy(RoleName=role_name, PolicyName=policy_name)['PolicyDocument']
        for statement in policy_document.get('Statement', []):
            if statement.get('Effect') == 'Allow':
                actions = statement.get('Action', [])
                if isinstance(actions, str):  # If single action
                    actions = [actions]
                # Add to the same policy entry in the dictionary
                all_actions_with_policy.setdefault(policy_name, []).extend(actions)
                for action in actions:
                    if any(verb in action for verb in MODIFYING_ACTIONS) or '*' in action:  # Check for privileged actions
                        privileged_actions.append(action)
                        can_modify_services = True
    
    # Check managed policies for privileged actions
    managed_policies = iam_client.list_attached_role_policies(RoleName=role_name)['AttachedPolicies']
    for policy in managed_policies:
        policy_arn = policy['PolicyArn']
        policy_version = iam_client.get_policy(PolicyArn=policy_arn)['Policy']['DefaultVersionId']
        policy_document = iam_client.get_policy_version(PolicyArn=policy_arn, VersionId=policy_version)['PolicyVersion']['Document']
        for statement in policy_document.get('Statement', []):
            if statement.get('Effect') == 'Allow':
                actions = statement.get('Action', [])
                if isinstance(actions, str):  # If single action
                    actions = [actions]
                # Add to the same policy entry in the dictionary
                all_actions_with_policy.setdefault(policy['PolicyName'], []).extend(actions)
                for action in actions:
                    if any(verb in action for verb in MODIFYING_ACTIONS) or '*' in action:  # Check for privileged actions
                        privileged_actions.append(action)
                        can_modify_services = True
    
    # Format the actions grouped by policy into a list of PolicyName[Actions]
    all_actions_with_policy_list = [f"{policy_name}[{', '.join(sorted(set(actions), key=lambda x: x.lower()))}]"
                                    for policy_name, actions in all_actions_with_policy.items()]
    
    return can_modify_services, privileged_actions, all_actions_with_policy_list

def process_roles(iam_client, only_privileged=True):
    roles = list_iam_roles(iam_client)
    role_data = []
    
    for role in roles:
        role_name = role['RoleName']
        
        is_privileged, tags = check_privileged_role(iam_client, role_name, only_privileged)
        if is_privileged:
            policies, policy_count = get_combined_policies(iam_client, role_name)
            conditions, deny_actions = get_policy_conditions_and_denies(iam_client, role_name)
            can_modify_services, privileged_actions, all_actions_with_policy_list = check_privileged_actions(iam_client, role_name)
            
            print(f"Combined policies for role {role_name}: {policies}")
            print(f"Policy count: {policy_count}")
            print(f"Conditions: {conditions}")
            print(f"Deny Actions: {deny_actions}")
            print(f"Can modify services: {can_modify_services}")
            print(f"Privileged Actions: {privileged_actions}")
            print(f"All Actions with Policy: {all_actions_with_policy_list}")
            print(f"Tags: {tags}")
            
            role_data.append({
                'RoleName': role_name,
                'Policies': ', '.join(policies),  # Combined sorted policies
                'PolicyCount': policy_count,
                'Conditions': conditions if conditions else "None",  # Add conditions if available
                'DenyActions': ', '.join(deny_actions) if deny_actions else "None",  # Add deny actions if any
                'CanModifyServices': can_modify_services,
                'PrivilegedActions': ', '.join(privileged_actions) if privileged_actions else "None",
                'AllActionsWithPolicy': '; '.join(all_actions_with_policy_list) if all_actions_with_policy_list else "None",
                'Tags': tags
            })
    
    return role_data

def write_to_csv(filename, fieldnames, data):
    # Write output to CSV file
    with open(filename, mode='w', newline='') as file:
        writer = csv.DictWriter(file, fieldnames=fieldnames)
        writer.writeheader()
        for row in data:
            writer.writerow(row)
    print(f"CSV written: {filename}")

    # Commented out S3 bucket upload part
    # s3 = boto3.client('s3')
    # s3.upload_file(filename, s3bucket, f"{s3folder}/{filename}")

def lambda_handler(event, context):
    iam_client = boto3.client('iam')
    fieldnames = ['RoleName', 'Policies', 'PolicyCount', 'Conditions', 'DenyActions', 'CanModifyServices', 'PrivilegedActions', 'AllActionsWithPolicy', 'Tags']
    
    # Add an option to filter based on privilege tags
    only_privileged = event.get('only_privileged', True)

    role_data = process_roles(iam_client, only_privileged)
    
    # Define filename with timestamp
    filename = f"iam_roles_{datetime.now().strftime('%Y%m%d%H%M%S')}.csv"
    write_to_csv(filename, fieldnames, role_data)

if __name__ == "__main__":
    # Running in CloudShell
    session = boto3.Session()
    iam_client = session.client('iam')
    
    fieldnames = ['RoleName', 'Policies', 'PolicyCount', 'Conditions', 'DenyActions', 'CanModifyServices', 'PrivilegedActions', 'AllActionsWithPolicy', 'Tags']
    
    # Change this value to True or False to filter on the Privileged tag
    only_privileged = True
    
    role_data = process_roles(iam_client, only_privileged)
    
    # Define filename with timestamp
    filename = f"iam_roles_{datetime.now().strftime('%Y%m%d%H%M%S')}.csv"
    write_to_csv(filename, fieldnames, role_data)

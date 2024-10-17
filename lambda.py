import boto3
import datetime
import os
from concurrent.futures import ThreadPoolExecutor, as_completed
from botocore.config import Config
import csv

# AWS SDK optimization: Configure retries and session timeouts
client_config = Config(
    retries={
        'max_attempts': 10,
        'mode': 'adaptive'  # Use adaptive retry strategy for better handling of throttling
    }
)

# Function to assume a role in another AWS account (skip if running for the local account)
def jump_accts(acctID, stsClient):
    try:
        print(f"Assuming role for account {acctID}")
        out = stsClient.assume_role(
            RoleArn=f'arn:aws:iam::{acctID}:role/lambda1',
            RoleSessionName='abc'
        )
        if not out or 'Credentials' not in out:
            print(f"Failed to assume role for account {acctID}: Missing credentials")
            return None
        return out  # Return the entire 'out' object
    except Exception as e:
        print(f"Error assuming role in account {acctID}: {e}")
        return None

# Function to analyze policy documents (both Allow and Deny)
def analyze_policy(policy_document):
    explicit_denies = []
    allow_actions = []
    conditions = []
    can_modify_services = False

    modifying_actions = ['Create', 'Put', 'Post', 'Update', 'Delete', 'Modify', 'Attach', 'Detach', 'Start', 'Stop', 'Reboot', 'Run']

    for statement in policy_document.get('Statement', []):
        effect = statement.get('Effect')
        actions = statement.get('Action', [])
        resources = statement.get('Resource', [])
        
        if isinstance(actions, str):
            actions = [actions]
        if isinstance(resources, str):
            resources = [resources]
        
        if effect == 'Deny':
            explicit_denies.extend(actions)
        else:
            allow_actions.extend(actions)

        if 'Condition' in statement:
            conditions.append(statement['Condition'])

        if any(verb in action for action in actions for verb in modifying_actions):
            can_modify_services = True

    return explicit_denies, allow_actions, conditions, can_modify_services

# Fetch managed policy actions (including denies)
def fetch_managed_policy_actions(iam_client, policy_arn):
    try:
        policy_version = iam_client.get_policy(PolicyArn=policy_arn)['Policy']['DefaultVersionId']
        policy_document = iam_client.get_policy_version(PolicyArn=policy_arn, VersionId=policy_version)['PolicyVersion']['Document']
        explicit_denies, allow_actions, conditions, can_modify_services = analyze_policy(policy_document)
        return explicit_denies, allow_actions, conditions, can_modify_services
    except Exception as e:
        print(f"Error fetching managed policy actions for {policy_arn}: {e}")
        return [], [], [], False

# Process individual roles
def process_role(iam_client, role, only_privileged, print_flag, acct_name):
    role_name = role['RoleName']
    roles_info = []

    if print_flag:
        print(f"Processing role '{role_name}' in account '{acct_name}'")

    try:
        # Fetch tags for the role
        tags_response = iam_client.list_role_tags(RoleName=role_name)
        tags = {tag['Key']: tag['Value'] for tag in tags_response.get('Tags', [])}

        # Skip if the role is not privileged and we're filtering for privileged roles
        if only_privileged and tags.get('Privileged') != 'Yes':
            print(f"Skipping non-privileged role '{role_name}' in account '{acct_name}'")
            return []

        # Fetch attached and inline policies
        attached_policies = iam_client.list_attached_role_policies(RoleName=role_name)
        inline_policies = iam_client.list_role_policies(RoleName=role_name)

        # Collect policy names and actions
        explicit_denies = []
        allow_actions = []
        conditions = []
        can_modify_services = False
        policy_actions = []

        # Analyze inline policies
        for policy_name in inline_policies['PolicyNames']:
            policy_document = iam_client.get_role_policy(RoleName=role_name, PolicyName=policy_name).get('PolicyDocument', None)
            if policy_document:
                denies, allows, conds, can_modify = analyze_policy(policy_document)
                explicit_denies.extend(denies)
                allow_actions.extend(allows)
                conditions.extend(conds)
                if can_modify:
                    can_modify_services = True

        # Fetch and analyze attached managed policies
        for policy in attached_policies.get('AttachedPolicies', []):
            denies, allows, conds, can_modify = fetch_managed_policy_actions(iam_client, policy['PolicyArn'])
            explicit_denies.extend(denies)
            allow_actions.extend(allows)
            conditions.extend(conds)
            if can_modify:
                can_modify_services = True

        # Merge and sort all policies (inline + attached managed policies)
        all_policy_names = inline_policies['PolicyNames'] + [p['PolicyName'] for p in attached_policies['AttachedPolicies']]
        sorted_policy_names = sorted(all_policy_names)  # Sorting after merging

        # Handle long text in CSV output by concatenating all policies and actions into a single line
        merged_policies = ', '.join(sorted_policy_names)  # Using commas to separate sorted policy names
        allow_actions_str = ', '.join(sorted(set(allow_actions)))  # Sorted non-deny actions
        explicit_denies_str = ', '.join(sorted(set(explicit_denies)))  # Sorted deny actions

        # Append role info
        roles_info.append({
            'RoleName': role_name,
            'PolicyCount': len(sorted_policy_names),
            'PolicyNames': merged_policies,  # Sorted and merged policy names
            'Actions': allow_actions_str,  # Sorted and merged allow actions
            'ExplicitDeny': explicit_denies_str,  # Sorted deny actions
            'Conditions': ', '.join([str(c) for c in conditions]),  # Join conditions into a single string
            'CanModifyServices': can_modify_services,
            'Tags': tags
        })

    except Exception as e:
        print(f"Error processing role '{role_name}' in account '{acct_name}': {e}")

    return roles_info

# Process a single account
def process_account(acctID, sts_client, only_privileged, print_flag):
    if acctID is None:
        print("No account ID provided, running for the local account.")
        roles_info = list_iam_roles_for_account(None, only_privileged, print_flag, 'local')
        field_names = list(roles_info[0].keys()) if roles_info else []
        return field_names, roles_info

    print(f"Processing account {acctID}")
    out = jump_accts(acctID, sts_client)
    if out is None:
        print(f"Error assuming role for account {acctID}")
        return [], []  # Return empty list for both field_names and roles_info if role assumption fails

    credentials = out.get('Credentials', None)
    if credentials is None:
        print(f"Error: No credentials for account {acctID}")
        return [], []  # Return empty values

    # List IAM roles in the account with assumed credentials
    roles_info = list_iam_roles_for_account(credentials, only_privileged, print_flag, acctID)
    field_names = list(roles_info[0].keys()) if roles_info else []
    return field_names, roles_info

# Function to list IAM roles and their details for a given account using credentials
def list_iam_roles_for_account(credentials=None, only_privileged=False, print_flag=False, acct_name=''):
    try:
        if credentials:
            print(f"Using assumed credentials for account {acct_name}")
            iam_client = boto3.client(
                'iam',
                aws_access_key_id=credentials['AccessKeyId'],
                aws_secret_access_key=credentials['SecretAccessKey'],
                aws_session_token=credentials['SessionToken'],
                config=client_config
            )
        else:
            print(f"Using default credentials for account {acct_name} (local account)")
            iam_client = boto3.client('iam', config=client_config)
    
        roles_info = []
        paginator = iam_client.get_paginator('list_roles')
        
        with ThreadPoolExecutor(max_workers=5) as executor:
            role_futures = []
            for page in paginator.paginate():
                if not page or 'Roles' not in page:
                    print(f"No roles found in page for account {acct_name}")
                    continue
                
                for role in page['Roles']:
                    role_futures.append(executor.submit(process_role, iam_client, role, only_privileged, print_flag, acct_name))
            
            for future in as_completed(role_futures):
                role_result = future.result()
                if role_result:
                    roles_info.extend(role_result)

        return roles_info

    except Exception as e:
        print(f"Error listing IAM roles for account {acct_name}: {e}")
        return []

# Parallel execution of accounts to improve performance
def gather_iam_roles_from_all_accounts(account_list=None, only_privileged=False, print_flag=False):
    if not account_list or len(account_list) == 0:
        print("No account list provided, running for the local account.")
        field_names, all_roles_info = process_account(None, None, only_privileged, print_flag)
        return field_names, all_roles_info

    print(f"Gathering IAM roles for accounts: {account_list}")
    sts_client = boto3.client('sts', config=client_config)
    all_roles_info = []
    field_names = []

    with ThreadPoolExecutor(max_workers=5) as executor:
        future_to_account = {executor.submit(process_account, acctID, sts_client, only_privileged, print_flag): acctID for acctID in account_list}

        for future in as_completed(future_to_account):
            acctID = future_to_account[future]
            try:
                acct_field_names, roles_info = future.result()
                if roles_info:
                    all_roles_info.extend(roles_info)
                    if not field_names:  # Set field_names once, based on the first valid result
                        field_names = acct_field_names
                else:
                    print(f"No roles found for account {acctID}")
            except Exception as e:
                print(f"Error processing account {acctID}: {e}")

    return field_names, all_roles_info

# Handle file writing based on environment
def handle_execution(account_list=None, only_privileged=False, print_flag=False):
    print(f"Starting execution with accounts: {account_list}")
    field_names, all_roles_info = gather_iam_roles_from_all_accounts(account_list, only_privileged, print_flag)
    if not field_names:
        print("No field names found to write to CSV. Exiting.")
        return

    filename = f"iam_roles_report_{datetime.datetime.now().strftime('%Y-%m-%d_%H-%M-%S')}.csv"
    write_to_csv(filename, field_names, all_roles_info, '')

# Write data to CSV
def write_to_csv(filename, field_names, all_roles_info, s3bucket):
    try:
        with open(f'/tmp/{filename}', mode='w', newline='') as file:
            writer = csv.DictWriter(file, fieldnames=field_names)
            writer.writeheader()
            for role_info in all_roles_info:
                writer.writerow(role_info)

        print(f"CSV file {filename} created successfully in /tmp/")
    except Exception as e:
        print(f"Error writing to CSV: {e}")

if __name__ == '__main__':
    account_list = None  # Empty account list to trigger local account processing
    handle_execution(account_list, only_privileged=False, print_flag=True)

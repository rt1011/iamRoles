import boto3
import datetime
import os
from concurrent.futures import ThreadPoolExecutor, as_completed
from botocore.config import Config

# Cache for policy details to avoid redundant API calls
policy_cache = {}

# AWS SDK optimization: Configure retries and session timeouts
client_config = Config(
    retries={
        'max_attempts': 10,
        'mode': 'adaptive'  # Use adaptive retry strategy for better handling of throttling
    }
)

# Function to assume a role in another AWS account
def jump_accts(acctID, stsClient):
    out = stsClient.assume_role(
        RoleArn=f'arn:aws:iam::{acctID}:role/lambda1',
        RoleSessionName='abc'
    )
    return out  # Return the entire 'out' object

# Optimized function to analyze policy
def analyze_policy(policy_document):
    explicit_denies = []
    conditions = []
    can_modify_services = False
    actions = []

    if not policy_document or 'Statement' not in policy_document:
        return explicit_denies, conditions, can_modify_services, actions  # Avoid NoneType errors
    
    # List of modifying actions that indicate resource modification capabilities
    modifying_actions = ['Create', 'Put', 'Post', 'Update', 'Delete', 'Modify', 'Attach', 'Detach', 'Start', 'Stop', 'Reboot', 'Run']

    for statement in policy_document.get('Statement', []):
        effect = statement.get('Effect')
        statement_actions = statement.get('Action', [])
        resources = statement.get('Resource', [])
        
        # Ensure actions and resources are lists
        if isinstance(statement_actions, str):
            statement_actions = [statement_actions]
        if isinstance(resources, str):
            resources = [resources]
        
        # Check for explicit deny
        if effect == 'Deny':
            explicit_denies.append(statement_actions)
        
        # Check for conditions
        if 'Condition' in statement:
            conditions.append(statement['Condition'])
        
        # Add actions to the actions list
        actions.extend(statement_actions)

        # Check if the policy allows modifying services
        if any(verb in action for action in statement_actions for verb in modifying_actions):
            can_modify_services = True

    return explicit_denies, conditions, can_modify_services, actions

# Fetch and cache policy details to avoid redundant API calls
def fetch_policy(policy_arn, iam_client):
    if policy_arn in policy_cache:
        return policy_cache[policy_arn]
    
    # Fetch policy document with error handling for None responses
    policy = iam_client.get_policy(PolicyArn=policy_arn)
    if not policy or 'Policy' not in policy:
        return None  # Avoid returning None if the policy is invalid or missing

    policy_version = policy['Policy']['DefaultVersionId']
    policy_version_data = iam_client.get_policy_version(PolicyArn=policy_arn, VersionId=policy_version)
    
    if not policy_version_data or 'PolicyVersion' not in policy_version_data:
        return None  # Avoid NoneType errors
    
    policy_document = policy_version_data['PolicyVersion'].get('Document', None)
    if policy_document is not None:
        policy_cache[policy_arn] = policy_document
    
    return policy_document

# Function to list IAM roles and their details for a given account using credentials
def list_iam_roles_for_account(credentials=None, only_privileged=False, print_flag=False, acct_name=''):
    iam_client = boto3.client(
        'iam',
        aws_access_key_id=credentials['AccessKeyId'],
        aws_secret_access_key=credentials['SecretAccessKey'],
        aws_session_token=credentials['SessionToken'],
        config=client_config  # Use the optimized client config
    ) if credentials else boto3.client('iam', config=client_config)
    
    roles_info = []
    paginator = iam_client.get_paginator('list_roles')

    # Use a thread pool to process roles in parallel (up to 5 roles at a time)
    with ThreadPoolExecutor(max_workers=5) as executor:
        role_futures = []
        for page in paginator.paginate():
            # Ensure the page is valid and not None
            if not page or 'Roles' not in page:
                continue  # Avoid iterating over NoneType
            
            for role in page['Roles']:
                role_futures.append(executor.submit(process_role, iam_client, role, only_privileged, print_flag, acct_name))
        
        for future in as_completed(role_futures):
            role_result = future.result()
            if role_result:
                roles_info.extend(role_result)  # Avoid NoneType here

    return roles_info

# Process individual roles (runs in parallel for each role)
def process_role(iam_client, role, only_privileged, print_flag, acct_name):
    role_name = role.get('RoleName')
    if not role_name:
        return []  # Skip processing if role name is missing
    
    roles_info = []

    # Print role information if print_flag is True
    if print_flag:
        print(f"Processing role '{role_name}' in account '{acct_name}'")

    # Fetch the tags for the role
    tags_response = iam_client.list_role_tags(RoleName=role_name)
    if not tags_response or 'Tags' not in tags_response:
        tags = {}  # Ensure no NoneType for empty or missing tags
    else:
        tags = {tag['Key']: tag['Value'] for tag in tags_response.get('Tags', [])}

    # Apply filter for privileged roles only if the flag is set
    if only_privileged and tags.get('Privileged') != 'Yes':
        return []  # Return an empty list if filtering out non-privileged roles

    # Fetch attached policies and inline policies
    attached_policies = iam_client.list_attached_role_policies(RoleName=role_name)
    inline_policies = iam_client.list_role_policies(RoleName=role_name)

    if not attached_policies or 'AttachedPolicies' not in attached_policies:
        attached_policies = {'AttachedPolicies': []}  # Avoid NoneType

    if not inline_policies or 'PolicyNames' not in inline_policies:
        inline_policies = {'PolicyNames': []}  # Avoid NoneType

    # Variables to track explicit deny, conditions, modification actions, and actions
    explicit_denies = []
    conditions = []
    can_modify_services = False
    policy_actions = []

    # Fetch inline policies and actions (optimized for inline policies only)
    for policy_name in inline_policies['PolicyNames']:
        policy_document = iam_client.get_role_policy(RoleName=role_name, PolicyName=policy_name).get('PolicyDocument', None)
        if not policy_document:
            continue  # Skip policies that don't exist

        denies, conds, can_modify, actions = analyze_policy(policy_document)

        explicit_denies.extend(denies)
        conditions.extend(conds)
        policy_actions.append(f"{policy_name}[{', '.join(actions)}]")  # Only actions from inline policies
        if can_modify:
            can_modify_services = True

    # Store the role's information including tags, policy names, and actions for inline policies only
    roles_info.append({
        'RoleName': role_name,
        'PolicyCount': len(attached_policies['AttachedPolicies']) + len(inline_policies['PolicyNames']),
        'PolicyNames': ', '.join([p['PolicyName'] for p in attached_policies['AttachedPolicies']] + inline_policies['PolicyNames']),
        'Actions': '; '.join(policy_actions),  # Only include actions for inline policies
        'ExplicitDeny': explicit_denies,
        'Conditions': conditions,
        'CanModifyServices': can_modify_services,
        'Tags': tags
    })

    return roles_info

# Parallel execution of accounts to improve performance
def gather_iam_roles_from_all_accounts(account_list=None, only_privileged=False, print_flag=False):
    sts_client = boto3.client('sts', config=client_config)
    all_roles_info = []

    # If account_list is None or empty, process the current account using default credentials
    if not account_list:
        print("Processing current account...")
        account_id = sts_client.get_caller_identity().get('Account')
        roles_info = list_iam_roles_for_account(None, only_privileged, print_flag, account_id)
        all_roles_info.extend(roles_info)
    else:
        with ThreadPoolExecutor(max_workers=5) as executor:  # Parallel processing for multiple accounts
            future_to_account = {executor.submit(process_account, acctID, sts_client, only_privileged, print_flag): acctID for acctID in account_list}

            for future in as_completed(future_to_account):
                acctID = future_to_account[future]
                try:
                    roles_info = future.result()
                    if roles_info:
                        all_roles_info.extend(roles_info)  # Avoid NoneType here
                except Exception as e:
                    print(f"Error processing account {acctID}: {e}")

    return all_roles_info

def process_account(acctID, sts_client, only_privileged, print_flag):
    out = jump_accts(acctID, sts_client)
    credentials = out.get('Credentials', None)
    if not credentials:
        print(f"Failed to assume role for account {acctID}")
        return []  # Return an empty list if unable to assume role

    return list_iam_roles_for_account(credentials, only_privileged, print_flag, acctID)

# Handle file writing based on environment
def handle_execution(account_list=None, only_privileged=False, print_flag=False):
    environment = detect_environment()
    field_names, all_roles_info = gather_iam_roles_from_all_accounts(account_list, only_privileged, print_flag)
    filename = f"iam_roles_report_{datetime.datetime.now().strftime('%Y-%m-%d_%H-%M-%S')}.csv"
    
    # Use your write_to_csv function here, passing only the filename (without full path)
    write_to_csv(filename, field_names, all_roles_info, '')  # Assuming write_to_csv is properly defined elsewhere

# Detect environment (CloudShell or Lambda)
def detect_environment():
    return "lambda" if 'LAMBDA_TASK_ROOT' in os.environ else "cloudshell"

# Main entry point for running in CloudShell or Lambda
if __name__ == '__main__':
    account_list = None  # Set account_list if necessary
    handle_execution(account_list, only_privileged=False, print_flag=True)

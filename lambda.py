import boto3
import datetime
import os

# Function to assume a role in another AWS account
def jump_accts(acctID, stsClient, role_name='lamba1'):
    out = stsClient.assume_role(
        RoleArn=f'arn:aws:iam::{acctID}:role/{role_name}',
        RoleSessionName='abc'
    )
    return out['Credentials']

# Function to analyze the policy and extract conditions, denies, and modifications
def analyze_policy(policy_document):
    explicit_denies = []
    conditions = []
    can_modify_services = False

    # List of modifying actions that indicate resource modification capabilities
    modifying_actions = ['Create', 'Put', 'Post', 'Update', 'Delete', 'Modify', 'Attach', 'Detach', 'Start', 'Stop', 'Reboot', 'Run']

    for statement in policy_document.get('Statement', []):
        effect = statement.get('Effect')
        actions = statement.get('Action', [])
        resources = statement.get('Resource', [])
        
        # Ensure actions and resources are lists
        if isinstance(actions, str):
            actions = [actions]
        if isinstance(resources, str):
            resources = [resources]
        
        # Check for explicit deny
        if effect == 'Deny':
            explicit_denies.append(actions)
        
        # Check for conditions
        if 'Condition' in statement:
            conditions.append(statement['Condition'])
        
        # Check if the policy allows modifying services
        for action in actions:
            # "*" means all actions, including modification
            if action == "*":
                can_modify_services = True
                break

            # Check if the action contains any of the modifying verbs
            if any(verb in action for verb in modifying_actions):
                can_modify_services = True

    return explicit_denies, conditions, can_modify_services

# Function to list IAM roles and their details for a given account using assumed credentials
def list_iam_roles_for_account(credentials, only_privileged=False):
    iam_client = boto3.client(
        'iam',
        aws_access_key_id=credentials['AccessKeyId'],
        aws_secret_access_key=credentials['SecretAccessKey'],
        aws_session_token=credentials['SessionToken']
    )
    
    roles_info = []
    paginator = iam_client.get_paginator('list_roles')

    for page in paginator.paginate():
        for role in page['Roles']:
            role_name = role['RoleName']

            # Fetch the tags for the role
            tags_response = iam_client.list_role_tags(RoleName=role_name)
            tags = {tag['Key']: tag['Value'] for tag in tags_response.get('Tags', [])}

            # Apply filter for privileged roles only if the flag is set
            if only_privileged and tags.get('Privileged') != 'Yes':
                continue

            # Fetch the attached policies
            attached_policies = iam_client.list_attached_role_policies(RoleName=role_name)
            attached_policy_names = [policy['PolicyName'] for policy in attached_policies['AttachedPolicies']]

            # Fetch inline policies
            inline_policies = iam_client.list_role_policies(RoleName=role_name)
            inline_policy_names = inline_policies['PolicyNames']

            # Combine all policy names
            all_policy_names = attached_policy_names + inline_policy_names

            # Variables to track explicit deny, conditions, and modification actions
            explicit_denies = []
            conditions = []
            can_modify_services = False

            # Analyze attached policies
            for policy in attached_policies['AttachedPolicies']:
                policy_arn = policy['PolicyArn']
                policy_version = iam_client.get_policy(PolicyArn=policy_arn)['Policy']['DefaultVersionId']
                policy_document = iam_client.get_policy_version(PolicyArn=policy_arn, VersionId=policy_version)['PolicyVersion']['Document']
                denies, conds, can_modify = analyze_policy(policy_document)

                explicit_denies.extend(denies)
                conditions.extend(conds)
                if can_modify:
                    can_modify_services = True

            # Analyze inline policies
            for policy_name in inline_policies['PolicyNames']:
                policy_document = iam_client.get_role_policy(RoleName=role_name, PolicyName=policy_name)['PolicyDocument']
                denies, conds, can_modify = analyze_policy(policy_document)

                explicit_denies.extend(denies)
                conditions.extend(conds)
                if can_modify:
                    can_modify_services = True

            # Store the role's information including tags and policy names
            roles_info.append({
                'RoleName': role_name,
                'PolicyCount': len(attached_policies['AttachedPolicies']) + len(inline_policies['PolicyNames']),
                'PolicyNames': ', '.join(all_policy_names),
                'ExplicitDeny': explicit_denies,
                'Conditions': conditions,
                'CanModifyServices': can_modify_services,
                'Tags': tags
            })

    return roles_info

# Main function to gather IAM roles from multiple accounts
def gather_iam_roles_from_all_accounts(account_list, only_privileged=False):
    sts_client = boto3.client('sts')
    all_roles_info = []

    for acctID, role_name in account_list.items():
        # Assume role in the target account
        credentials = jump_accts(acctID, sts_client, role_name)

        # Get the list of IAM roles and their details for the target account
        roles_info = list_iam_roles_for_account(credentials, only_privileged)

        # Add account ID to each role's info
        for role_info in roles_info:
            role_info['AccountID'] = acctID

        all_roles_info.extend(roles_info)

    # Extract field names (CSV headers) from the first element of the list
    if all_roles_info:
        field_names = list(all_roles_info[0].keys())
    else:
        field_names = []

    # Return field names and data
    return field_names, all_roles_info

# Function to handle CloudShell vs Lambda environments
def handle_execution(account_list, only_privileged=False):
    # Call the function to gather IAM roles from all accounts
    field_names, all_roles = gather_iam_roles_from_all_accounts(account_list, only_privileged)

    # Determine the execution environment (CloudShell or Lambda)
    if 'LAMBDA_TASK_ROOT' in os.environ:
        # Lambda environment
        filename = f"iam_roles_report_{datetime.datetime.now().strftime('%Y-%m-%d_%H-%M-%S')}.csv"
        s3folder = "iam_role/"
        # Call the write_to_csv function (Lambda will write to S3)
        write_to_csv(filename, field_names, all_roles, s3folder)
    else:
        # CloudShell environment
        filename = f"/tmp/iam_roles_report_{datetime.datetime.now().strftime('%Y-%m-%d_%H-%M-%S')}.csv"
        # Call the write_to_csv function (CloudShell will write to local filesystem)
        write_to_csv(filename, field_names, all_roles, '')

# Example account list: {'accountID': 'role_name'}
account_list = {
    '111111111111': 'role_name1',
    '222222222222': 'role_name2',
    '333333333333': 'role_name3'
}

# Set to True to only process privileged roles or False to process all roles
only_privileged = False  # Change this to True for privileged roles only

# Call the handle_execution function
handle_execution(account_list, only_privileged)

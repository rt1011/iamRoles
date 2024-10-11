import boto3
import datetime
import os

# Function to assume a role in another AWS account
def jump_accts(acctID, stsClient):
    out = stsClient.assume_role(
        RoleArn=f'arn:aws:iam::{acctID}:role/lambda1',
        RoleSessionName='abc'
    )
    return out  # Return the entire 'out' object

# Function to analyze the policy and extract conditions, denies, and modifications
def analyze_policy(policy_document):
    explicit_denies = []
    conditions = []
    can_modify_services = False
    actions = []

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
        for action in statement_actions:
            if action == "*":
                can_modify_services = True
                break

            if any(verb in action for verb in modifying_actions):
                can_modify_services = True

    return explicit_denies, conditions, can_modify_services, actions

# Function to list IAM roles and their details for a given account using credentials
def list_iam_roles_for_account(credentials=None, only_privileged=False, print_flag=False, acct_name=''):
    if credentials:
        # Use assumed role credentials
        iam_client = boto3.client(
            'iam',
            aws_access_key_id=credentials['AccessKeyId'],
            aws_secret_access_key=credentials['SecretAccessKey'],
            aws_session_token=credentials['SessionToken']
        )
    else:
        # Use default credentials for the same account
        iam_client = boto3.client('iam')
    
    roles_info = []
    paginator = iam_client.get_paginator('list_roles')

    for page in paginator.paginate():
        for role in page['Roles']:
            role_name = role['RoleName']
            
            # Print role information if print_flag is True
            if print_flag:
                print(f"Processing role '{role_name}' in account '{acct_name}'")

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
            all_policy_names = attached_policies + inline_policy_names

            # Variables to track explicit deny, conditions, modification actions, and actions
            explicit_denies = []
            conditions = []
            can_modify_services = False
            policy_actions = []

            # Inline policies: Collect actions
            for policy_name in inline_policies['PolicyNames']:
                policy_document = iam_client.get_role_policy(RoleName=role_name, PolicyName=policy_name)['PolicyDocument']
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
                'PolicyNames': ', '.join(all_policy_names),
                'Actions': '; '.join(policy_actions),  # Only include actions for inline policies
                'ExplicitDeny': explicit_denies,
                'Conditions': conditions,
                'CanModifyServices': can_modify_services,
                'Tags': tags
            })

    return roles_info

# Detect environment (CloudShell or Lambda)
def detect_environment():
    if 'LAMBDA_TASK_ROOT' in os.environ:
        return "lambda"
    else:
        return "cloudshell"

# Main function to gather IAM roles from multiple accounts
def gather_iam_roles_from_all_accounts(account_list=None, only_privileged=False, print_flag=False):
    sts_client = boto3.client('sts')
    all_roles_info = []

    if account_list:
        # If account list is provided, assume role for each account
        for acctID in account_list:
            if print_flag:
                print(f"Assuming role for account '{acctID}'")
            out = jump_accts(acctID, sts_client)  # Use jump_accts to assume role
            credentials = out['Credentials']  # Extract credentials from the output
            roles_info = list_iam_roles_for_account(credentials, only_privileged, print_flag, acctID)

            # Add account ID to each role's info
            for role_info in roles_info:
                role_info['AccountID'] = acctID

            all_roles_info.extend(roles_info)
    else:
        # No account list provided, use current account credentials
        acct_id = sts_client.get_caller_identity()['Account']
        if print_flag:
            print(f"Using default credentials for account '{acct_id}'")
        roles_info = list_iam_roles_for_account(None, only_privileged, print_flag, acct_id)
        all_roles_info.extend(roles_info)

    # Extract field names (CSV headers) from the first element of the list
    if all_roles_info:
        field_names = list(all_roles_info[0].keys())
    else:
        field_names = []

    # Return field names and data as a tuple
    return field_names, all_roles_info

# Handle file writing based on environment
def handle_execution(account_list=None, only_privileged=False, print_flag=False):
    # Detect the environment (CloudShell or Lambda)
    environment = detect_environment()

    # Gather the IAM roles data
    field_names, all_roles_info = gather_iam_roles_from_all_accounts(account_list, only_privileged, print_flag)

    # Define the filename
    filename = f"iam_roles_report_{datetime.datetime.now().strftime('%Y-%m-%d_%H-%M-%S')}.csv"

    # Call the write_to_csv function (now only passing filename)
    write_to_csv(filename, field_names, all_roles_info, '')

# __main__ block for direct execution in CloudShell
if __name__ == '__main__':
    # You can define account_list or use None for the current account
    account_list = None  # or provide account list
    handle_execution(account_list, only_privileged=False, print_flag=True)

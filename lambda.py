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

# Process a single account
def process_account(acctID, sts_client, only_privileged, print_flag):
    print(f"Processing account {acctID}")
    out = jump_accts(acctID, sts_client)
    if out is None:
        print(f"Error assuming role for account {acctID}")
        return []  # Return empty list if role assumption fails

    credentials = out.get('Credentials', None)
    if credentials is None:
        print(f"Error: No credentials for account {acctID}")
        return []

    # List IAM roles in the account with assumed credentials
    return list_iam_roles_for_account(credentials, only_privileged, print_flag, acctID)

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
            print(f"Using default credentials for account {acct_name}")
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
    if not account_list or not isinstance(account_list, list) or len(account_list) == 0:
        print("Error: account_list is either None or empty. Please provide valid AWS account IDs.")
        return [], []  # Return empty values if account_list is invalid

    print(f"Gathering IAM roles for accounts: {account_list}")
    sts_client = boto3.client('sts', config=client_config)
    all_roles_info = []

    with ThreadPoolExecutor(max_workers=5) as executor:
        future_to_account = {executor.submit(process_account, acctID, sts_client, only_privileged, print_flag): acctID for acctID in account_list}

        for future in as_completed(future_to_account):
            acctID = future_to_account[future]
            try:
                roles_info = future.result()
                if roles_info:
                    all_roles_info.extend(roles_info)
                else:
                    print(f"No roles found for account {acctID}")
            except Exception as e:
                print(f"Error processing account {acctID}: {e}")

    if all_roles_info:
        field_names = list(all_roles_info[0].keys())
    else:
        print("No roles found across accounts")
        field_names = []

    return field_names, all_roles_info

# Handle file writing based on environment
def handle_execution(account_list=None, only_privileged=False, print_flag=False):
    # Debugging output for account_list
    print(f"Starting execution with accounts: {account_list}")
    field_names, all_roles_info = gather_iam_roles_from_all_accounts(account_list, only_privileged, print_flag)
    if not field_names:
        print("No field names found to write to CSV. Exiting.")
        return

    filename = f"iam_roles_report_{datetime.datetime.now().strftime('%Y-%m-%d_%H-%M-%S')}.csv"
    write_to_csv(filename, field_names, all_roles_info, '')

# Detect environment (CloudShell or Lambda)
def detect_environment():
    return "lambda" if 'LAMBDA_TASK_ROOT' in os.environ else "cloudshell"

if __name__ == '__main__':
    account_list = ['123456789012', '098765432109']  # Example AWS account IDs
    handle_execution(account_list, only_privileged=False, print_flag=True)

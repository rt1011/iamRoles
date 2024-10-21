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
                # Format policy actions for inline policies
                if allows:
                    policy_actions.append(f"{policy_name}[{', '.join(sorted(allows))}]")
                if denies:
                    policy_actions.append(f"{policy_name}[{', '.join(sorted(denies))}]")

        # Fetch and analyze attached managed policies
        for policy in attached_policies.get('AttachedPolicies', []):
            denies, allows, conds, can_modify = fetch_managed_policy_actions(iam_client, policy['PolicyArn'])
            explicit_denies.extend(denies)
            allow_actions.extend(allows)
            conditions.extend(conds)
            if can_modify:
                can_modify_services = True
            # Format policy actions for attached managed policies
            if allows:
                policy_actions.append(f"{policy['PolicyName']}[{', '.join(sorted(allows))}]")
            if denies:
                policy_actions.append(f"{policy['PolicyName']}[{', '.join(sorted(denies))}]")

        # Merge and sort all policies (inline + attached managed policies)
        all_policy_names = inline_policies['PolicyNames'] + [p['PolicyName'] for p in attached_policies['AttachedPolicies']]
        sorted_policy_names = sorted(all_policy_names)  # Sorting after merging

        # Handle long text in CSV output by concatenating all policies and actions into a single line
        merged_policies = ', '.join(sorted_policy_names)  # Using commas to separate sorted policy names
        merged_actions = ', '.join(sorted(policy_actions))  # Sorted actions as well

        # Append role info
        roles_info.append({
            'RoleName': role_name,
            'PolicyCount': len(sorted_policy_names),
            'PolicyNames': merged_policies,  # Sorted and merged policy names
            'Actions': merged_actions,  # Sorted policy names with their respective actions
            'ExplicitDeny': ', '.join(sorted(set(explicit_denies))),  # Sorted deny actions
            'Conditions': ', '.join([str(c) for c in conditions]),  # Join conditions into a single string
            'CanModifyServices': can_modify_services,
            'Tags': tags
        })

    except Exception as e:
        print(f"Error processing role '{role_name}' in account '{acct_name}': {e}")

    return roles_info

# The rest of the code remains unchanged

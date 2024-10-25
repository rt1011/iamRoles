import boto3
import csv
from datetime import datetime
import argparse
from botocore.exceptions import ClientError

# Constants: Privileged actions keywords that modify resources
PRIVILEGED_ACTIONS_KEYWORDS = ["Create", "Update", "Modify", "Put", "Delete", "Write", "Attach", "Detach"]

def list_iam_users(iam_client):
    users = []
    paginator = iam_client.get_paginator('list_users')
    for response in paginator.paginate():
        users.extend(response['Users'])
    print(f"Total IAM Users found: {len(users)}")
    return users

def get_combined_policies_for_user(iam_client, user_name):
    policies = []

    # User's own policies
    inline_policies = iam_client.list_user_policies(UserName=user_name)['PolicyNames']
    policies.extend([f"user-inline:{p}" for p in inline_policies])

    managed_policies = iam_client.list_attached_user_policies(UserName=user_name)['AttachedPolicies']
    policies.extend([f"user-managed:{p['PolicyArn']}" for p in managed_policies])

    # Group policies for the user
    groups = iam_client.list_groups_for_user(UserName=user_name)['Groups']
    for group in groups:
        group_name = group['GroupName']
        
        # Inline and managed policies attached to the group
        group_inline_policies = iam_client.list_group_policies(GroupName=group_name)['PolicyNames']
        policies.extend([f"{group_name}-inline:{p}" for p in group_inline_policies])

        group_managed_policies = iam_client.list_attached_group_policies(GroupName=group_name)['AttachedPolicies']
        policies.extend([f"{group_name}-managed:{p['PolicyArn']}" for p in group_managed_policies])

    return sorted(policies)

def is_privileged_action(action):
    """
    Check if an action is privileged based on defined keywords.
    """
    action_name = action.split(":")[-1]
    if action_name == "*":
        return True
    return any(action_name.lower().startswith(keyword.lower()) for keyword in PRIVILEGED_ACTIONS_KEYWORDS)

def filter_privileged_actions(actions):
    """
    Filters a list of actions to only include privileged actions.
    """
    return [action for action in actions if is_privileged_action(action)]

def check_privileged_actions(iam_client, policies, user_name):
    allow_actions = []
    deny_actions = []

    for policy in policies:
        try:
            # Check if policy is inline or managed
            if "inline" in policy:
                policy_name = policy.split(":")[1]
                if "user-inline" in policy:
                    policy_document = iam_client.get_user_policy(UserName=user_name, PolicyName=policy_name)['PolicyDocument']
                else:
                    # Group inline policy
                    group_name = policy.split("-inline:")[0]
                    policy_document = iam_client.get_group_policy(GroupName=group_name, PolicyName=policy_name)['PolicyDocument']
            elif "managed" in policy:
                policy_arn = policy.split(":")[1]
                policy_version = iam_client.get_policy(PolicyArn=policy_arn)['Policy']['DefaultVersionId']
                policy_document = iam_client.get_policy_version(PolicyArn=policy_arn, VersionId=policy_version)['PolicyVersion']['Document']
            else:
                continue

            for statement in policy_document.get('Statement', []):
                actions = statement.get('Action', [])
                if isinstance(actions, str):
                    actions = [actions]
                if statement.get('Effect') == 'Allow':
                    allow_actions.extend(filter_privileged_actions(actions))
                elif statement.get('Effect') == 'Deny':
                    deny_actions.extend(filter_privileged_actions(actions))

        except ClientError as e:
            if e.response['Error']['Code'] == 'NoSuchEntity':
                print(f"Warning: {policy} for user '{user_name}' does not exist.")
                continue
            else:
                raise e  # Raise if it's a different exception

    return allow_actions, deny_actions

def gather_user_data():
    iam_client = boto3.client('iam')
    user_data = []

    users = list_iam_users(iam_client)

    for user in users:
        user_name = user['UserName']
        print(f"\nProcessing User: {user_name}")

        # Gather policies for each user, including those attached via groups
        policies = get_combined_policies_for_user(iam_client, user_name)
        allow_actions, deny_actions = check_privileged_actions(iam_client, policies, user_name)

        # Format output
        user_info = {
            'UserName': user_name,
            'Policies': ", ".join(policies),
            'AllowActions': ", ".join(allow_actions),
            'DenyActions': ", ".join(deny_actions),
        }

        user_data.append(user_info)

    return user_data

def write_to_csv(user_data, filename="iam_user_report"):
    """
    Writes the user data to a CSV file with the given filename.
    """
    timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
    file_path = f"/tmp/{filename}_{timestamp}.csv"
    fieldnames = ['UserName', 'Policies', 'AllowActions', 'DenyActions']
    
    with open(file_path, mode='w', newline='') as file:
        writer = csv.DictWriter(file, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(user_data)
    
    print(f"Report generated at: {file_path}")

# Run the script
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Fetch IAM user information.")
    args = parser.parse_args()

    user_data = gather_user_data()
    write_to_csv(user_data)

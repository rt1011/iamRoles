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

def list_iam_groups(iam_client):
    groups = []
    paginator = iam_client.get_paginator('list_groups')
    for response in paginator.paginate():
        groups.extend(response['Groups'])
    print(f"Total IAM Groups found: {len(groups)}")
    return groups

def get_combined_policies_for_user(iam_client, user_name):
    policies = []

    # User's inline and managed policies
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

def get_combined_policies_for_group(iam_client, group_name):
    policies = []

    # Inline policies attached to the group
    group_inline_policies = iam_client.list_group_policies(GroupName=group_name)['PolicyNames']
    policies.extend([f"group-inline:{p}" for p in group_inline_policies])

    # Managed policies attached to the group
    group_managed_policies = iam_client.list_attached_group_policies(GroupName=group_name)['AttachedPolicies']
    policies.extend([f"group-managed:{p['PolicyArn']}" for p in group_managed_policies])

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

def check_privileged_actions(iam_client, policies, entity_type, entity_name):
    allow_actions = []
    deny_actions = []

    for policy in policies:
        try:
            # Inline policies
            if "inline" in policy:
                policy_name = policy.split(":")[1]
                if entity_type == "user":
                    policy_document = iam_client.get_user_policy(UserName=entity_name, PolicyName=policy_name)['PolicyDocument']
                elif entity_type == "group":
                    policy_document = iam_client.get_group_policy(GroupName=entity_name, PolicyName=policy_name)['PolicyDocument']
            # Managed policies
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
                print(f"Warning: {policy} for {entity_type} '{entity_name}' does not exist.")
                continue
            else:
                raise e  # Raise if it's a different exception

    return allow_actions, deny_actions

def gather_entity_data(entity_type):
    iam_client = boto3.client('iam')
    entity_data = []

    if entity_type == "user":
        entities = list_iam_users(iam_client)
    else:
        entities = list_iam_groups(iam_client)

    for entity in entities:
        entity_name = entity['UserName'] if entity_type == "user" else entity['GroupName']
        print(f"\nProcessing {entity_type.capitalize()}: {entity_name}")

        # Gather policies for each entity
        policies = get_combined_policies_for_user(iam_client, entity_name) if entity_type == "user" else get_combined_policies_for_group(iam_client, entity_name)
        allow_actions, deny_actions = check_privileged_actions(iam_client, policies, entity_type, entity_name)

        # Format output
        entity_info = {
            'EntityName': entity_name,
            'Policies': ", ".join(policies),
            'AllowActions': ", ".join(allow_actions),
            'DenyActions': ", ".join(deny_actions),
        }

        entity_data.append(entity_info)

    return entity_data

def write_to_csv(entity_data, entity_type, filename="iam_report"):
    """
    Writes the entity data to a CSV file with the given filename.
    """
    timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
    file_path = f"/tmp/{filename}_{entity_type}_{timestamp}.csv"
    fieldnames = ['EntityName', 'Policies', 'AllowActions', 'DenyActions']
    
    with open(file_path, mode='w', newline='') as file:
        writer = csv.DictWriter(file, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(entity_data)
    
    print(f"Report generated at: {file_path}")

# Run the script
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Fetch IAM entity information.")
    parser.add_argument("mode", choices=["user", "group"], default="user", nargs="?", help="Mode to fetch data for IAM users or groups.")
    args = parser.parse_args()

    entity_data = gather_entity_data(args.mode)
    write_to_csv(entity_data, args.mode)

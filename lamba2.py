import boto3
import os

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

def get_attached_policies(iam_client, role_name):
    attached_policies = []
    inline_policies = iam_client.list_role_policies(RoleName=role_name)['PolicyNames']
    managed_policies = iam_client.list_attached_role_policies(RoleName=role_name)['AttachedPolicies']
    
    for policy_name in inline_policies:
        attached_policies.append(f"InlinePolicy: {policy_name}")
    
    for policy in managed_policies:
        attached_policies.append(f"ManagedPolicy: {policy['PolicyName']}")
    
    return sorted(attached_policies)

def process_roles(iam_client):
    roles = list_iam_roles(iam_client)
    for role in roles:
        tags = {tag['Key']: tag['Value'] for tag in role.get('Tags', [])}
        if tags.get('privilege') == 'yes':
            print(f"Processing role: {role['RoleName']}")
            policies = get_attached_policies(iam_client, role['RoleName'])
            for policy in policies:
                print(f"  Policy: {policy}")

def lambda_handler(event, context):
    iam_client = boto3.client('iam')
    process_roles(iam_client)

if __name__ == "__main__":
    # Running in CloudShell
    session = boto3.Session()
    iam_client = session.client('iam')
    process_roles(iam_client)

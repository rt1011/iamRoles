import boto3
import csv
import os
from datetime import datetime

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
    role_data = []
    
    for role in roles:
        print(f"Scanning role: {role['RoleName']}")  # Print role being scanned
        
        # Print tags for debugging
        tags = {tag['Key']: tag['Value'] for tag in role.get('Tags', [])}
        print(f"Role: {role['RoleName']}, Tags: {tags}")
        
        if tags.get('Privileged') == 'yes':
            print(f"Processing privileged role: {role['RoleName']}")
            policies = get_attached_policies(iam_client, role['RoleName'])
            print(f"Policies for role {role['RoleName']}: {policies}")  # Print policies for debugging
            role_data.append({
                'RoleName': role['RoleName'],
                'Policies': '; '.join(policies)
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
    fieldnames = ['RoleName', 'Policies']
    role_data = process_roles(iam_client)
    
    # Define filename with timestamp
    filename = f"iam_roles_{datetime.now().strftime('%Y%m%d%H%M%S')}.csv"
    write_to_csv(filename, fieldnames, role_data)

if __name__ == "__main__":
    # Running in CloudShell
    session = boto3.Session()
    iam_client = session.client('iam')
    
    fieldnames = ['RoleName', 'Policies']
    role_data = process_roles(iam_client)
    
    # Define filename with timestamp
    filename = f"iam_roles_{datetime.now().strftime('%Y%m%d%H%M%S')}.csv"
    write_to_csv(filename, fieldnames, role_data)

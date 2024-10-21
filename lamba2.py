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

def check_privileged_role(iam_client, role_name, only_privileged=True):
    # Retrieve the tags for the role
    tags_response = iam_client.list_role_tags(RoleName=role_name)
    tags = {tag['Key']: tag['Value'] for tag in tags_response.get('Tags', [])}
    
    # Skip non-privileged roles if filtering for privileged roles
    if only_privileged and tags.get('Privileged') != 'yes':
        print(f"Skipping non-privileged role '{role_name}'")
        return False
    else:
        print(f"Processing role: '{role_name}'")
        return True

def process_roles(iam_client, only_privileged=True):
    roles = list_iam_roles(iam_client)
    role_data = []
    
    for role in roles:
        role_name = role['RoleName']
        
        if check_privileged_role(iam_client, role_name, only_privileged):
            policies = get_attached_policies(iam_client, role_name)
            print(f"Policies for role {role_name}: {policies}")  # Print policies for privileged role
            role_data.append({
                'RoleName': role_name,
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
    
    # Add an option to filter based on privilege tags
    only_privileged = event.get('only_privileged', True)  # Use the input from the event to decide

    role_data = process_roles(iam_client, only_privileged)
    
    # Define filename with timestamp
    filename = f"iam_roles_{datetime.now().strftime('%Y%m%d%H%M%S')}.csv"
    write_to_csv(filename, fieldnames, role_data)

if __name__ == "__main__":
    # Running in CloudShell
    session = boto3.Session()
    iam_client = session.client('iam')
    
    fieldnames = ['RoleName', 'Policies']
    
    # Change this value to True or False to filter on the Privileged tag
    only_privileged = True
    
    role_data = process_roles(iam_client, only_privileged)
    
    # Define filename with timestamp
    filename = f"iam_roles_{datetime.now().strftime('%Y%m%d%H%M%S')}.csv"
    write_to_csv(filename, fieldnames, role_data)

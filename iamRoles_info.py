import boto3
import csv
from datetime import datetime
from io import StringIO
from botocore.exceptions import ClientError

# ----- Config -----
ROLE_NAME = "lambda1"  # Role to assume in target accounts
S3_BUCKET = "your-s3-bucket-name"  # Optional: Set to None if you don’t want S3 upload
S3_KEY = "iam-roles/iam_roles_inventory.csv"

# Accounts to scan (account_id -> human-readable alias)
account_aliases = {
    '111122223333': 'dev-account',
    '444455556666': 'prod-account',
    # Add more as needed
}


# ---------- STS Assume Role ----------
def assume_role(account_id):
    sts = boto3.client('sts')
    try:
        response = sts.assume_role(
            RoleArn=f"arn:aws:iam::{account_id}:role/{ROLE_NAME}",
            RoleSessionName="CrossAccountSession"
        )
        creds = response['Credentials']
        return boto3.client(
            'iam',
            aws_access_key_id=creds['AccessKeyId'],
            aws_secret_access_key=creds['SecretAccessKey'],
            aws_session_token=creds['SessionToken']
        )
    except ClientError as e:
        print(f"[ERROR] Failed to assume role into {account_id}: {str(e)}")
        return None


# ---------- Tag Filtering ----------
def get_tag_value(tags, key):
    for tag in tags:
        if tag['Key'].lower() == key.lower():
            return tag['Value'].lower()
    return None


# ---------- Role Collection ----------
def get_roles(iam_client, account_id):
    roles_info = []
    paginator = iam_client.get_paginator('list_roles')

    for page in paginator.paginate():
        for role in page['Roles']:
            role_name = role['RoleName']
            created = role['CreateDate']
            last_used = role.get('RoleLastUsed', {}).get('LastUsedDate')
            assume_policy = role['AssumeRolePolicyDocument']

            # Tag filtering
            try:
                tag_resp = iam_client.list_role_tags(RoleName=role_name)
                tags = tag_resp.get('Tags', [])
            except Exception as e:
                tags = []

            tag_val = get_tag_value(tags, 'do-not-delete')
            if tag_val == 'yes':
                continue  # Skip

            roles_info.append({
                "Reviewed": "No",
                "Role Owner/Role SME": "",
                "Retain/Remove": "",
                "Exception (Justification is role retained)": "",
                "Role Name": role_name,
                "Account ID": account_id,
                "DaysSinceCreation": (datetime.utcnow() - created.replace(tzinfo=None)).days,
                "DaysSinceLastUse": (datetime.utcnow() - last_used.replace(tzinfo=None)).days if last_used else "",
                "Used/NeverUsed": "Used" if last_used else "NeverUsed",
                "Subtype": "",
                "Tags": ", ".join([f"{t['Key']}={t['Value']}" for t in tags]),
                "AssumeRolePolicyDocument": str(assume_policy),
                "How many accounts the service role is present in": "",
                "Bypass the tag 'DO NOT DELETE'": "no" if tag_val != 'yes' else "yes",
                "Role present in how many accounts": "",
            })
    return roles_info


# ---------- S3 Upload ----------
def upload_to_s3(data_rows, fieldnames):
    s3 = boto3.client('s3')
    output = StringIO()
    writer = csv.DictWriter(output, fieldnames=fieldnames)
    writer.writeheader()
    for row in data_rows:
        writer.writerow(row)

    s3.put_object(Bucket=S3_BUCKET, Key=S3_KEY, Body=output.getvalue())
    print(f"✅ Uploaded report to: s3://{S3_BUCKET}/{S3_KEY}")


# ---------- Main Handler ----------
def lambda_handler(event=None, context=None):
    all_roles = []

    for account_id in account_aliases:
        print(f"🔍 Processing account: {account_id}")
        iam_client = assume_role(account_id)
        if iam_client:
            roles = get_roles(iam_client, account_id)
            all_roles.extend(roles)

    if all_roles:
        fieldnames = list(all_roles[0].keys())
        filename = "/tmp/iam_roles_inventory.csv"
        with open(filename, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(all_roles)
        print(f"✅ CSV written to {filename}")

        if S3_BUCKET:
            upload_to_s3(all_roles, fieldnames)
    else:
        print("⚠️ No roles collected.")


# ---------- Local Test ----------
if __name__ == "__main__":
    lambda_handler()

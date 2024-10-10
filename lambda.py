import boto3
import datetime

# Initialize AWS clients
iam_client = boto3.client('iam')
sts_client = boto3.client('sts')

# Get the AWS account ID
account_id = sts_client.get_caller_identity()["Account"]

# Function to analyze the policy and extract conditions, denies, and modifications
def analyze_policy(policy_document):
    explicit_denies = []
    conditions = []
    can_modify_services = False
    
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
            if any(verb in action for verb in ['Put', 'Post', 'Update', 'Delete']):
                can_modify_services = True

        # If resource is "*", then the role has unrestricted access to all resources
        if "*" in resources:
            can_modify_services = True
    
    return explicit_denies, conditions, can_modify_services

# Function to list all IAM roles with their policies, tags, and analyze them
def list_iam_roles_with_policies_and_tags():
    roles_info = []
    paginator = iam_client.get_paginator('list_roles')
    
    for page in paginator.paginate():
        for role in page['Roles']:
            role_name = role['RoleName']
            role_arn = role['Arn']
            
            # Fetch the tags for the role
            tags_response = iam_client.list_role_tags(RoleName=role_name)
            tags = {tag['Key']: tag['Value'] for tag in tags_response.get('Tags', [])}
            
            # Filter roles by the "Privileged" tag with value "Yes"
            if tags.get('Privileged') != 'Yes':
                continue
            
            # Fetch the attached policies
            attached_policies = iam_client.list_attached_role_policies(RoleName=role_name)
            attached_policy_count = len(attached_policies['AttachedPolicies'])
            attached_policy_names = [policy['PolicyName'] for policy in attached_policies['AttachedPolicies']]
            
            # Fetch inline policies
            inline_policies = iam_client.list_role_policies(RoleName=role_name)
            inline_policy_count = len(inline_policies['PolicyNames'])
            inline_policy_names = inline_policies['PolicyNames']
            
            # Combine all policy names (attached and inline)
            all_policy_names = attached_policy_names + inline_policy_names
            
            # Total policies
            total_policy_count = attached_policy_count + inline_policy_count
            
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
                'AccountID': account_id,
                'PolicyCount': total_policy_count,
                'PolicyNames': ', '.join(all_policy_names),  # Convert list to comma-separated string
                'ExplicitDeny': explicit_denies,
                'Conditions': conditions,
                'CanModifyServices': can_modify_services,
                'Tags': tags
            })
    
    return roles_info

# Main function to handle both CloudShell and Lambda execution
def main(execution_env, s3folder=None):
    # Fetch IAM roles with policies and tags
    roles_info = list_iam_roles_with_policies_and_tags()

    # Extract the headers dynamically from the first element of iam_roles
    if roles_info:
        field_names = list(roles_info[0].keys())  # Extract keys from the first dictionary as headers

        # Return field_names and roles_info as a list of two elements
        return [field_names, roles_info]
    else:
        return [[], []]  # Return empty lists if no roles found

# Example usage
if __name__ == "__main__":
    # For CloudShell execution
    iam_roles = main(execution_env="cloudshell")

    # iam_roles[0] will contain the field names
    field_names = iam_roles[0]

    # iam_roles[1] will contain the data
    data = iam_roles[1]

    # Filename (this can be whatever you like, with the datetime appended as needed)
    filename = f"iam_roles_report_{datetime.datetime.now().strftime('%Y-%m-%d_%H-%M-%S')}.csv"

    # S3 folder (if needed, or it can be None if writing locally)
    s3folder = 'your-s3-folder'

    # Now call the write_to_csv function
    write_to_csv(filename=filename, field_names=field_names, output_dict=data, s3folder=s3folder)

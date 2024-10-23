import boto3
from inventories import iam_policy
from datetime import datetime

def write_to_csv(filename, fieldnames, role_data, s3bucket_name):
    # Generate the CSV and upload to S3
    s3_client = boto3.client('s3')
    csv_content = []

    # Write header
    csv_content.append("|".join(fieldnames))

    # Write each row of data
    for role_info in role_data:
        csv_content.append("|".join([str(role_info[field]) for field in fieldnames]))

    # Write CSV content to a file
    csv_string = "\n".join(csv_content)
    file_path = f"/tmp/{filename}"

    with open(file_path, "w") as file:
        file.write(csv_string)

    # Upload the file to S3
    s3_client.upload_file(file_path, s3bucket_name, filename)
    print(f"CSV file {filename} uploaded to S3 bucket {s3bucket_name}.")

def lambda_handler(event, context):
    # Create an IAM client
    iam_client = boto3.client('iam')
    
    # Gather IAM role info and fieldnames
    fieldnames, role_data = iam_policy.gather_iam_roles_from_all_accounts(iam_client, only_privileged=True)
    
    # Define filename with timestamp
    filename = f"iam_roles_{datetime.now().strftime('%Y%m%d%H%M%S')}.csv"
    
    # Get S3 bucket name from event or environment variables
    s3bucket_name = event.get('s3bucket_name', 'default-bucket')
    
    # Write to CSV and upload to S3
    write_to_csv(filename, fieldnames, role_data, s3bucket_name)

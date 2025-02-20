import requests
import boto3
import base64
import xml.etree.ElementTree as ET
import configparser
import os
import getpass

# Set up AWS and IdP details
IDP_LOGIN_URL = "https://your-idp-login-url.com"
AWS_ROLE_ARN = "arn:aws:iam::ACCOUNT_ID:role/YOUR_ROLE"
AWS_IDP_ARN = "arn:aws:iam::ACCOUNT_ID:saml-provider/YOUR_IDP"
AWS_PROFILE_NAME = "sso-session"

# Prompt user for credentials
def get_user_credentials():
    username = input("Enter your username: ")
    password = getpass.getpass("Enter your password: ")
    return username, password

# Authenticate with the IdP and retrieve the SAML assertion
def get_saml_assertion(username, password):
    session = requests.Session()

    payload = {
        "username": username,
        "password": password
    }

    response = session.post(IDP_LOGIN_URL, data=payload)

    if response.status_code != 200:
        print("❌ Authentication failed. Check your credentials.")
        return None

    # Extract SAML Response from HTML form
    tree = ET.ElementTree(ET.fromstring(response.text))
    saml_assertion = None
    for elem in tree.iter():
        if "Response" in elem.tag and "SAML" in elem.tag:
            saml_assertion = elem.text

    if not saml_assertion:
        print("❌ SAML assertion not found!")
        return None

    return saml_assertion.strip()

# Assume an AWS role using the SAML assertion
def assume_role_with_saml(saml_assertion):
    client = boto3.client("sts")

    response = client.assume_role_with_saml(
        RoleArn=AWS_ROLE_ARN,
        PrincipalArn=AWS_IDP_ARN,
        SAMLAssertion=saml_assertion
    )

    return response["Credentials"]

# Store the temporary session token in AWS CLI config
def update_aws_cli_config(credentials):
    config = configparser.ConfigParser()
    aws_config_file = os.path.expanduser("~/.aws/credentials")

    config.read(aws_config_file)

    if AWS_PROFILE_NAME not in config.sections():
        config.add_section(AWS_PROFILE_NAME)

    config.set(AWS_PROFILE_NAME, "aws_access_key_id", credentials["AccessKeyId"])
    config.set(AWS_PROFILE_NAME, "aws_secret_access_key", credentials["SecretAccessKey"])
    config.set(AWS_PROFILE_NAME, "aws_session_token", credentials["SessionToken"])

    with open(aws_config_file, "w") as configfile:
        config.write(configfile)

    print(f"✅ AWS session token saved under profile: {AWS_PROFILE_NAME}")

# Main execution
if __name__ == "__main__":
    username, password = get_user_credentials()
    saml_assertion = get_saml_assertion(username, password)

    if saml_assertion:
        print("\n✅ Successfully retrieved SAML assertion.")
        credentials = assume_role_with_saml(saml_assertion)

        if credentials:
            print("\n✅ Successfully assumed AWS role and obtained session token.")
            update_aws_cli_config(credentials)

            # Print the credentials
            print("\n🔑 **Session Credentials**")
            print(f"🔹 AWS Access Key ID: {credentials['AccessKeyId']}")
            print(f"🔹 AWS Secret Access Key: {credentials['SecretAccessKey']}")
            print(f"🔹 AWS Session Token: {credentials['SessionToken']}\n")

            print(f"🎉 Use AWS CLI with: `aws s3 ls --profile {AWS_PROFILE_NAME}`")
        else:
            print("❌ Failed to assume AWS role.")
    else:
        print("❌ Failed to retrieve SAML assertion.")

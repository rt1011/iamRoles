import msal
import boto3
import configparser
import os

# 🔹 Microsoft Entra ID (Azure AD) Authentication Details
CLIENT_ID = "your-client-id"  # Replace with your Entra ID (Azure AD) App Client ID
TENANT_ID = "your-tenant-id"  # Replace with your Microsoft Entra Tenant ID
AUTHORITY = f"https://login.microsoftonline.com/{TENANT_ID}"
SCOPES = ["https://management.azure.com/.default"]  # Modify scope if needed

# 🔹 AWS IAM Role & Identity Provider (SAML)
AWS_ROLE_ARN = "arn:aws:iam::ACCOUNT_ID:role/YOUR_ROLE"  # Replace with AWS role ARN
AWS_IDP_ARN = "arn:aws:iam::ACCOUNT_ID:saml-provider/YOUR_IDP"  # Replace with Identity Provider ARN
AWS_PROFILE_NAME = "sso-session"

# 🔹 Function: Authenticate with Microsoft Entra ID (Azure AD)
def authenticate_with_msal():
    app = msal.PublicClientApplication(CLIENT_ID, authority=AUTHORITY)

    # 🔹 Use interactive login (supports MFA automatically)
    result = app.acquire_token_interactive(SCOPES)

    if "access_token" in result:
        print("\n✅ Successfully authenticated!")
        print(f"🔹 Access Token: {result['access_token'][:50]}... (truncated for security)")
        return result["access_token"]
    else:
        print("\n❌ Authentication failed:", result.get("error_description", "Unknown error"))
        return None

# 🔹 Function: Assume AWS Role Using the Access Token
def assume_role_with_saml(access_token):
    client = boto3.client("sts")

    # 🔹 Use `assume-role-with-web-identity` if your setup supports OIDC
    response = client.assume_role_with_web_identity(
        RoleArn=AWS_ROLE_ARN,
        RoleSessionName="SAMLSession",
        WebIdentityToken=access_token
    )

    return response["Credentials"]

# 🔹 Function: Store AWS Session Credentials in AWS CLI
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

    print(f"\n✅ AWS session token saved under profile: {AWS_PROFILE_NAME}")

# 🔹 Main Execution
if __name__ == "__main__":
    access_token = authenticate_with_msal()

    if access_token:
        credentials = assume_role_with_saml(access_token)

        if credentials:
            print("\n✅ Successfully assumed AWS role and obtained session token.")
            update_aws_cli_config(credentials)

            # 🔹 Print the credentials
            print("\n🔑 **AWS Session Credentials**")
            print(f"🔹 AWS Access Key ID: {credentials['AccessKeyId']}")
            print(f"🔹 AWS Secret Access Key: {credentials['SecretAccessKey']}")
            print(f"🔹 AWS Session Token: {credentials['SessionToken']}\n")

            print(f"🎉 Use AWS CLI with: `aws s3 ls --profile {AWS_PROFILE_NAME}`")
        else:
            print("\n❌ Failed to assume AWS role.")
    else:
        print("\n❌ Authentication failed.")

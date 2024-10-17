import boto3
import re
import csv
import os

# Initialize AWS clients
config_client = boto3.client('config')
guardduty_client = boto3.client('guardduty')
accessanalyzer_client = boto3.client('accessanalyzer')
securityhub_client = boto3.client('securityhub')
trustedadvisor_client = boto3.client('support')

# Filter function to check for 'IAM' in rule names
def filter_iam_rules(rule_name):
    return bool(re.search(r'iam', rule_name, re.IGNORECASE))

# Function to retrieve findings/rules from AWS Config
def get_config_rules(account_id):
    config_rules = []
    response = config_client.describe_config_rules()
    for rule in response['ConfigRules']:
        if filter_iam_rules(rule['ConfigRuleName']):
            config_rules.append({
                'Name': rule['ConfigRuleName'],
                'AccountID': account_id,
                'Source': 'AWS Config'
            })
    return config_rules

# Function to retrieve GuardDuty findings
def get_guardduty_findings(account_id):
    guardduty_rules = []
    detectors = guardduty_client.list_detectors()['DetectorIds']
    for detector_id in detectors:
        findings = guardduty_client.list_findings(DetectorId=detector_id)
        for finding_id in findings['FindingIds']:
            finding = guardduty_client.get_findings(DetectorId=detector_id, FindingIds=[finding_id])['Findings'][0]
            if filter_iam_rules(finding['Title']):
                guardduty_rules.append({
                    'Name': finding['Title'],
                    'AccountID': account_id,
                    'Source': 'GuardDuty'
                })
    return guardduty_rules

# Function to retrieve Access Analyzer findings
def get_access_analyzer_findings(account_id):
    access_analyzer_rules = []
    analyzers = accessanalyzer_client.list_analyzers()['analyzers']
    for analyzer in analyzers:
        findings = accessanalyzer_client.list_findings(analyzerArn=analyzer['arn'])
        for finding in findings['findings']:
            if filter_iam_rules(finding['id']):
                access_analyzer_rules.append({
                    'Name': finding['id'],
                    'AccountID': account_id,
                    'Source': 'Access Analyzer'
                })
    return access_analyzer_rules

# Function to retrieve Security Hub findings
def get_security_hub_findings(account_id):
    security_hub_rules = []
    response = securityhub_client.get_findings()
    for finding in response['Findings']:
        if filter_iam_rules(finding['Title']):
            security_hub_rules.append({
                'Name': finding['Title'],
                'AccountID': account_id,
                'Source': 'Security Hub'
            })
    return security_hub_rules

# Function to retrieve Trusted Advisor checks
def get_trusted_advisor_findings(account_id):
    trusted_advisor_rules = []
    checks = trustedadvisor_client.describe_trusted_advisor_checks(language='en')['checks']
    for check in checks:
        if filter_iam_rules(check['name']):
            trusted_advisor_rules.append({
                'Name': check['name'],
                'AccountID': account_id,
                'Source': 'Trusted Advisor'
            })
    return trusted_advisor_rules

# Function to write to CSV file
def write_to_csv(iam_rules, account_id):
    filename = f"IAM_Rules_Report_{account_id}.csv"
    fieldnames = ['Name', 'AccountID', 'Source']
    
    with open(filename, mode='w', newline='') as csv_file:
        writer = csv.DictWriter(csv_file, fieldnames=fieldnames)
        writer.writeheader()
        for rule in iam_rules:
            writer.writerow(rule)

    print(f"CSV report generated: {filename}")

# Main function to gather and save filtered IAM rules from all sources
def generate_iam_report(account_id):
    iam_rules = []

    # AWS Config Rules
    iam_rules += get_config_rules(account_id)

    # GuardDuty Findings
    iam_rules += get_guardduty_findings(account_id)

    # Access Analyzer Findings
    iam_rules += get_access_analyzer_findings(account_id)

    # Security Hub Findings
    iam_rules += get_security_hub_findings(account_id)

    # Trusted Advisor Checks
    iam_rules += get_trusted_advisor_findings(account_id)

    # Write the results to CSV
    if iam_rules:
        write_to_csv(iam_rules, account_id)
    else:
        print(f"No IAM-related rules found for account {account_id}.")

# Example execution, assuming you're using an assumed role or have proper permissions
if __name__ == '__main__':
    account_id = boto3.client('sts').get_caller_identity()['Account']
    generate_iam_report(account_id)

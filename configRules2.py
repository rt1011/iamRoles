import boto3
import csv
from datetime import datetime

def fetch_config_rules_with_iam():
    # Initialize the AWS Config client
    client = boto3.client('config')
    
    # Fetch all Config rules
    response = client.describe_config_rules()
    config_rules = response.get('ConfigRules', [])

    # Filter rules with "IAM" in name or description and gather details
    filtered_rules = []
    for rule in config_rules:
        rule_name = rule.get('ConfigRuleName', '')
        description = rule.get('Description', '')
        arn = rule.get('ConfigRuleArn', '')
        scope = rule.get('Scope', {})
        rule_type = rule.get('Source', {}).get('SourceIdentifier', 'Unknown')

        # Check for "IAM" in name or description
        if 'IAM' in rule_name.upper() or 'IAM' in description.upper():
            filtered_rules.append({
                'RuleName': rule_name,
                'Description': description,
                'ARN': arn,
                'RuleType': rule_type,
                'Scope': scope
            })

    return filtered_rules

def write_to_csv(data, filename):
    # Define the CSV headers
    headers = ['RuleName', 'Description', 'ARN', 'RuleType', 'Scope']

    # Write to CSV file
    with open(filename, mode='w', newline='', encoding='utf-8') as file:
        writer = csv.DictWriter(file, fieldnames=headers)
        writer.writeheader()
        writer.writerows(data)

def main():
    # Get filtered Config rules
    rules_with_iam = fetch_config_rules_with_iam()

    # Define the output CSV filename
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"aws_config_rules_with_iam_{timestamp}.csv"

    # Write data to CSV
    write_to_csv(rules_with_iam, filename)
    print(f"Data has been written to {filename}")

if __name__ == "__main__":
    main()

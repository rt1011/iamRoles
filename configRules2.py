import boto3
import csv
from datetime import datetime

def get_account_name():
    """Fetch the AWS account name using the account alias."""
    client = boto3.client('iam')
    try:
        response = client.list_account_aliases()
        account_aliases = response.get('AccountAliases', [])
        return account_aliases[0] if account_aliases else "unknown_account"
    except Exception as e:
        print(f"Error fetching account name: {e}")
        return "unknown_account"

def fetch_config_rules_with_iam():
    """Fetch Config rules and filter those with 'IAM' in their name or description."""
    client = boto3.client('config')
    try:
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
    except Exception as e:
        print(f"Error fetching Config rules: {e}")
        return []

def write_to_csv(data, filename):
    """Write the filtered Config rules to a CSV file."""
    headers = ['RuleName', 'Description', 'ARN', 'RuleType', 'Scope']
    try:
        with open(filename, mode='w', newline='', encoding='utf-8') as file:
            writer = csv.DictWriter(file, fieldnames=headers)
            writer.writeheader()
            writer.writerows(data)
        print(f"Data has been written to {filename}")
    except Exception as e:
        print(f"Error writing to CSV: {e}")

def main():
    """Main function to fetch and export Config rules with 'IAM' in name or description."""
    # Get the AWS account name
    account_name = get_account_name()

    # Fetch filtered Config rules
    rules_with_iam = fetch_config_rules_with_iam()

    # Define the output CSV filename with account name
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"{account_name}_aws_config_rules_with_iam_{timestamp}.csv"

    # Write data to CSV
    if rules_with_iam:
        write_to_csv(rules_with_iam, filename)
    else:
        print("No Config rules with 'IAM' in name or description were found.")

if __name__ == "__main__":
    main()

import boto3
import csv
import datetime

def get_config_rules_with_iam():
    client = boto3.client('config')

    rules = []
    next_token = None

    # Loop to handle pagination if there are many rules
    while True:
        if next_token:
            response = client.describe_config_rules(NextToken=next_token)
        else:
            response = client.describe_config_rules()

        for rule in response['ConfigRules']:
            rule_name = rule.get('ConfigRuleName', '')
            rule_description = rule.get('Description', '')
            evaluation_mode = rule.get('EvaluationModes', [])
            rule_arn = rule.get('ConfigRuleArn', '')

            # Check if "IAM" is in the name or description of the rule
            if 'iam' in rule_name.lower() or 'iam' in rule_description.lower():
                rules.append({
                    'Name': rule_name,
                    'Description': rule_description,
                    'Evaluation Mode': ', '.join([mode['Mode'] for mode in evaluation_mode]),  # Join all evaluation modes if there are multiple
                    'ARN': rule_arn
                })

        next_token = response.get('NextToken', None)
        if not next_token:
            break

    return rules

def write_to_csv(data, filename):
    # Define the CSV headers
    headers = ['Name', 'Description', 'Evaluation Mode', 'ARN']

    # Create a CSV file and write data to it
    with open(filename, mode='w', newline='') as file:
        writer = csv.DictWriter(file, fieldnames=headers)

        # Write the header row
        writer.writeheader()

        # Write the data rows
        for row in data:
            writer.writerow(row)


if __name__ == '__main__':
    iam_config_rules = get_config_rules_with_iam()

    if iam_config_rules:
        # Set the filename with a timestamp
        timestamp = datetime.datetime.now().strftime('%Y-%m-%d_%H-%M-%S')
        filename = f'iam_config_rules_{timestamp}.csv'

        # Write to CSV
        write_to_csv(iam_config_rules, filename)

        print(f"Data written to {filename}")
    else:
        print("No IAM-related Config rules found.")

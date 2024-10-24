#!/bin/bash

# Temporary file for the CSV
CSV_FILE="access_analyzer_rules.csv"

# Get the current account name
ACCOUNT_ID=$(aws sts get-caller-identity --query 'Account' --output text)

# Headers for the CSV file
echo "AccountID,RuleName,Rule" > $CSV_FILE

# Fetch the analyzer ARN (assuming there's only one analyzer in the account)
ANALYZER_ARN=$(aws accessanalyzer list-analyzers --query 'analyzers[0].arn' --output text)

if [ -z "$ANALYZER_ARN" ]; then
  echo "No Access Analyzer found in the account."
  exit 1
fi

echo "Using Analyzer ARN: $ANALYZER_ARN"

# Get the list of findings (rules) from Access Analyzer
FINDINGS=$(aws accessanalyzer list-findings --analyzer-arn $ANALYZER_ARN --query 'findings[*].[id,resource]' --output json)

if [ -z "$FINDINGS" ]; then
  echo "No findings (rules) found by Access Analyzer."
  exit 0
fi

# Loop through all findings and append to CSV
echo "$FINDINGS" | jq -r '.[] | [.[]] | @csv' | while IFS=',' read -r rule_name rule; do
  # Append the account ID, rule name, and rule (resource) to the CSV
  echo "$ACCOUNT_ID,$rule_name,$rule" >> $CSV_FILE
done

echo "Script completed. CSV file generated: $CSV_FILE"

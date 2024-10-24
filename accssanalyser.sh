#!/bin/bash

# Temporary file for the CSV
CSV_FILE="access_analyzer_roles.csv"

# Get the current account name
ACCOUNT_NAME=$(aws sts get-caller-identity --query 'Account' --output text)

# Headers for the CSV file
echo "AccountName,RoleName,Arn,AccessAnalyzerFinding" > $CSV_FILE

# Fetch the analyzer ARN (assuming there's only one analyzer in the account)
ANALYZER_ARN=$(aws accessanalyzer list-analyzers --query 'analyzers[0].arn' --output text)

if [ -z "$ANALYZER_ARN" ]; then
  echo "No Access Analyzer found in the account."
  exit 1
fi

echo "Using Analyzer ARN: $ANALYZER_ARN"

# Get the list of IAM roles flagged by Access Analyzer
ROLES=$(aws accessanalyzer list-findings --analyzer-arn $ANALYZER_ARN --query 'findings[*].resource' --output text | grep arn:aws:iam)

if [ -z "$ROLES" ]; then
  echo "No IAM roles flagged by Access Analyzer."
  exit 0
fi

# Loop through all roles flagged by Access Analyzer and append to CSV
for ROLE_ARN in $ROLES; do
  ROLE_NAME=$(echo $ROLE_ARN | awk -F'/' '{print $NF}')
  ACCESS_ANALYZER_FINDING="Yes"  # Flag it as "Yes" since it came from Access Analyzer

  # Append the account name, role name, role ARN, and access analyzer finding to the CSV
  echo "$ACCOUNT_NAME,$ROLE_NAME,$ROLE_ARN,$ACCESS_ANALYZER_FINDING" >> $CSV_FILE
done

echo "Script completed. CSV file generated: $CSV_FILE"

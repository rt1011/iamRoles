#!/bin/bash

# Temporary file for the CSV
CSV_FILE="access_analyzer_roles.csv"

# Get the current account name
ACCOUNT_NAME=$(aws sts get-caller-identity --query 'Account' --output text)

# Headers for the CSV file
echo "AccountName,RoleName,Arn,AccessAnalyzerFinding" > $CSV_FILE

echo "Processing account: $ACCOUNT_NAME"

# Get the list of IAM roles flagged by Access Analyzer
ROLES=$(aws accessanalyzer list-findings --query 'findings[*].resource' --output text | grep arn:aws:iam)

# Loop through all roles flagged by Access Analyzer and append to CSV
for ROLE_ARN in $ROLES; do
  ROLE_NAME=$(echo $ROLE_ARN | awk -F'/' '{print $NF}')
  ACCESS_ANALYZER_FINDING="Yes"  # Flag it as "Yes" since it came from Access Analyzer

  # Append the account name, role name, role ARN, and access analyzer finding to the CSV
  echo "$ACCOUNT_NAME,$ROLE_NAME,$ROLE_ARN,$ACCESS_ANALYZER_FINDING" >> $CSV_FILE
done

echo "Script completed. CSV file generated: $CSV_FILE"

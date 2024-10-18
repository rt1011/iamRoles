#!/bin/bash

# Get the account ID using AWS CLI
ACCOUNT_ID=$(aws sts get-caller-identity --query "Account" --output text)

# Output CSV file
OUTPUT_FILE="IAM_Rules_Report_${ACCOUNT_ID}.csv"

# Write CSV header
echo "Name,AccountID,Source" > $OUTPUT_FILE

# AWS Config: Get Config Rules containing 'iam' in the name
aws configservice describe-config-rules --query "ConfigRules[?contains(tolower(ConfigRuleName), 'iam')].{Name:ConfigRuleName}" --output text | while read -r line
do
    echo "$line,$ACCOUNT_ID,AWS Config" >> $OUTPUT_FILE
done

# GuardDuty: Get Findings containing 'iam' in the title
DETECTORS=$(aws guardduty list-detectors --output text)
for DETECTOR_ID in $DETECTORS
do
    FINDING_IDS=$(aws guardduty list-findings --detector-id $DETECTOR_ID --output text)
    for FINDING_ID in $FINDING_IDS
    do
        aws guardduty get-findings --detector-id $DETECTOR_ID --finding-ids $FINDING_ID --query "Findings[?contains(tolower(Title), 'iam')].{Name:Title}" --output text | while read -r line
        do
            echo "$line,$ACCOUNT_ID,GuardDuty" >> $OUTPUT_FILE
        done
    done
done

# Access Analyzer: Get Findings containing 'iam' in the ID
ANALYZERS=$(aws accessanalyzer list-analyzers --query "analyzers[].arn" --output text)
for ANALYZER_ARN in $ANALYZERS
do
    aws accessanalyzer list-findings --analyzer-arn $ANALYZER_ARN --query "findings[?contains(tolower(id), 'iam')].{Name:id}" --output text | while read -r line
    do
        echo "$line,$ACCOUNT_ID,Access Analyzer" >> $OUTPUT_FILE
    done
done

# Security Hub: Get Findings using list-findings-v2 with filters containing 'iam'
aws securityhub list-findings-v2 --filters Type="PREFIX:Software and Configuration Checks" --query "Findings[?contains(tolower(Title), 'iam')].{Name:Title}" --output text | while read -r line
do
    echo "$line,$ACCOUNT_ID,Security Hub" >> $OUTPUT_FILE
done

# Trusted Advisor: Get Checks containing 'iam' in the name
aws support describe-trusted-advisor-checks --language "en" --query "checks[?contains(tolower(name), 'iam')].{Name:name}" --output text | while read -r line
do
    echo "$line,$ACCOUNT_ID,Trusted Advisor" >> $OUTPUT_FILE
done

# Notify the user
echo "CSV report generated: $OUTPUT_FILE"

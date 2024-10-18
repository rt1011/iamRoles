@echo off
setlocal

REM Set the account ID
for /f "tokens=*" %%A in ('aws sts get-caller-identity --query "Account" --output text') do (set ACCOUNT_ID=%%A)

REM Output CSV file
set OUTPUT_FILE=IAM_Rules_Report_%ACCOUNT_ID%.csv

REM Write CSV header
echo Name,AccountID,Source > %OUTPUT_FILE%

REM AWS Config: Get Config Rules
for /f "tokens=*" %%A in ('aws configservice describe-config-rules --query "ConfigRules[?contains(tolower(ConfigRuleName), 'iam')].{Name:ConfigRuleName}" --output text') do (
    echo %%A,%ACCOUNT_ID%,AWS Config >> %OUTPUT_FILE%
)

REM GuardDuty: Get Findings
for /f "tokens=*" %%A in ('aws guardduty list-detectors --output text') do (
    for /f "tokens=*" %%B in ('aws guardduty list-findings --detector-id %%A --query "FindingIds" --output text') do (
        for /f "tokens=*" %%C in ('aws guardduty get-findings --detector-id %%A --finding-ids %%B --query "Findings[?contains(tolower(Title), 'iam')].{Name:Title}" --output text') do (
            echo %%C,%ACCOUNT_ID%,GuardDuty >> %OUTPUT_FILE%
        )
    )
)

REM Access Analyzer: Get Findings
for /f "tokens=*" %%A in ('aws accessanalyzer list-analyzers --query "analyzers[].arn" --output text') do (
    for /f "tokens=*" %%B in ('aws accessanalyzer list-findings --analyzer-arn %%A --query "findings[?contains(tolower(id), 'iam')].{Name:id}" --output text') do (
        echo %%B,%ACCOUNT_ID%,Access Analyzer >> %OUTPUT_FILE%
    )
)

REM Security Hub: Get Findings using list-findings-v2 with filters
aws securityhub list-findings-v2 --filters Type="PREFIX:Software and Configuration Checks" --query "Findings[?contains(tolower(Title), 'iam')].{Name:Title}" --output text > temp_securityhub.txt
for /f "tokens=*" %%A in (temp_securityhub.txt) do (
    echo %%A,%ACCOUNT_ID%,Security Hub >> %OUTPUT_FILE%
)
del temp_securityhub.txt

REM Trusted Advisor: Get Checks
for /f "tokens=*" %%A in ('aws support describe-trusted-advisor-checks --language "en" --query "checks[?contains(tolower(name), 'iam')].{Name:name}" --output text') do (
    echo %%A,%ACCOUNT_ID%,Trusted Advisor >> %OUTPUT_FILE%
)

REM Notify the user
echo CSV report generated: %OUTPUT_FILE%

endlocal
pause

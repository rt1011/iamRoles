#!/bin/bash

# Input: User Group, Target Role, and Trust Policy
GROUP_NAME=$1
TARGET_ROLE=$2
TRUST_POLICY_FILE=$3

# Ensure that the group name, target role, and trust policy are provided
if [ -z "$GROUP_NAME" ] || [ -z "$TARGET_ROLE" ] || [ -z "$TRUST_POLICY_FILE" ]; then
    echo "Usage: $0 <group-name> <target-role> <trust-policy-file>"
    exit 1
fi

# Step 1: Check if the target role exists
ROLE_EXISTS=$(aws iam get-role --role-name "$TARGET_ROLE" 2>&1)

if echo "$ROLE_EXISTS" | grep -q 'NoSuchEntity'; then
    # Role doesn't exist, creating it with the trust policy
    echo "Role $TARGET_ROLE does not exist. Creating the role..."

    # Debugging: Check if the trust policy file exists
    if [ ! -f "$TRUST_POLICY_FILE" ]; then
        echo "Trust policy file $TRUST_POLICY_FILE does not exist. Please check the file path."
        exit 1
    fi

    # Create the new role with the provided trust policy
    CREATE_ROLE_OUTPUT=$(aws iam create-role --role-name "$TARGET_ROLE" --assume-role-policy-document file://"$TRUST_POLICY_FILE" 2>&1)

    if echo "$CREATE_ROLE_OUTPUT" | grep -q 'NoSuchEntity'; then
        echo "Failed to create role $TARGET_ROLE. Error: $CREATE_ROLE_OUTPUT"
        exit 1
    fi

    echo "Role $TARGET_ROLE created successfully."
else
    # Role exists, proceed with attaching policies
    echo "Role $TARGET_ROLE already exists. Proceeding with attaching policies."
fi

# Step 2: List all policies attached to the user group
echo "Listing policies attached to group: $GROUP_NAME"
POLICIES=$(aws iam list-attached-group-policies --group-name "$GROUP_NAME" --query 'AttachedPolicies[].PolicyArn' --output text)

# Step 3: Attach each policy to the target role
echo "Attaching policies to target role: $TARGET_ROLE"
for POLICY in $POLICIES; do
    echo "Attaching policy $POLICY to role $TARGET_ROLE"
    ATTACH_POLICY_OUTPUT=$(aws iam attach-role-policy --role-name "$TARGET_ROLE" --policy-arn "$POLICY" 2>&1)

    if echo "$ATTACH_POLICY_OUTPUT" | grep -q 'NoSuchEntity'; then
        echo "Failed to attach policy $POLICY to role $TARGET_ROLE. Error: $ATTACH_POLICY_OUTPUT"
    else
        echo "Policy $POLICY attached successfully."
    fi
done

echo "Done!"

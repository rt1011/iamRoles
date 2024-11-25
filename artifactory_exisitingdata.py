import http.client
import json
import base64
import csv

# Artifactory details
ARTIFACTORY_URL = "your.artifactory.instance"  # Replace with your Artifactory URL (e.g., artifactory.example.com)
ARTIFACTORY_USER = "your-username"  # Replace with your username
ENCRYPTED_PASSWORD = "your-encrypted-password"  # Replace with your encrypted password
INPUT_CSV = "input_repos.csv"  # Input CSV file
OUTPUT_CSV = "updated_repos.csv"  # Output CSV file

# Function to make HTTP requests
def make_request(method, endpoint, headers=None):
    conn = http.client.HTTPSConnection(ARTIFACTORY_URL)
    conn.request(method, endpoint, headers=headers)
    response = conn.getresponse()
    if response.status >= 200 and response.status < 300:
        data = response.read()
        conn.close()
        return json.loads(data)
    else:
        conn.close()
        raise Exception(f"HTTP request failed: {response.status} {response.reason}")

# Get repository details from Artifactory
def get_repo_details(repo_key):
    auth_header = {
        "Authorization": f"Basic {base64.b64encode(f'{ARTIFACTORY_USER}:{ENCRYPTED_PASSWORD}'.encode()).decode()}"
    }
    endpoint = f"/artifactory/api/repositories/{repo_key}"
    try:
        repo_details = make_request("GET", endpoint, headers=auth_header)
        repo_type = repo_details.get("type", "N/A")
        full_path = f"{ARTIFACTORY_URL}/artifactory/{repo_key}/"
        return repo_type, full_path
    except Exception as e:
        print(f"Failed to fetch details for {repo_key}: {e}")
        return "N/A", "N/A"

# Update CSV with additional columns
def update_csv():
    with open(INPUT_CSV, mode="r") as infile, open(OUTPUT_CSV, mode="w", newline="") as outfile:
        reader = csv.DictReader(infile)
        fieldnames = reader.fieldnames + ["Repository Type", "Full Path"]
        writer = csv.DictWriter(outfile, fieldnames=fieldnames)
        
        # Write header to the output file
        writer.writeheader()

        # Process each row in the input file
        for row in reader:
            repo_key = row.get("Name")  # Assuming 'Name' column contains the repo key
            if not repo_key:
                print("Repository name missing in the row, skipping...")
                continue
            
            print(f"Fetching details for repository: {repo_key}")
            repo_type, full_path = get_repo_details(repo_key)

            # Add new data to the row
            row["Repository Type"] = repo_type
            row["Full Path"] = full_path

            # Write updated row to the output file
            writer.writerow(row)

if __name__ == "__main__":
    try:
        print("Starting repository update...")
        update_csv()
        print(f"Updated repository details have been written to {OUTPUT_CSV}.")
    except Exception as e:
        print(f"An error occurred: {e}")

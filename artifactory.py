import http.client
import json
import base64
import csv

# Artifactory details
ARTIFACTORY_URL = "your.artifactory.instance"  # Replace with your Artifactory URL (e.g., artifactory.example.com)
ARTIFACTORY_USER = "your-username"  # Replace with your username
ENCRYPTED_PASSWORD = "your-encrypted-password"  # Replace with your encrypted password

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

# Get all repositories
def get_repositories():
    auth_header = {
        "Authorization": f"Basic {base64.b64encode(f'{ARTIFACTORY_USER}:{ENCRYPTED_PASSWORD}'.encode()).decode()}"
    }
    repos = make_request("GET", "/artifactory/api/repositories", headers=auth_header)
    return repos

# Get repository size and number of artifacts
def get_repo_storage_info(repo_key):
    auth_header = {
        "Authorization": f"Basic {base64.b64encode(f'{ARTIFACTORY_USER}:{ENCRYPTED_PASSWORD}'.encode()).decode()}"
    }
    storage_info = make_request("GET", f"/artifactory/api/storage/{repo_key}", headers=auth_header)
    return storage_info

# Fetch repository details
def fetch_repo_details():
    repo_details = []
    repos = get_repositories()
    for repo in repos:
        repo_key = repo['key']
        repo_type = repo['type']
        repo_url = repo.get('url', '')
        repo_kind = repo.get('packageType', 'unknown')

        try:
            storage_info = get_repo_storage_info(repo_key)
            repo_size = storage_info.get('storageSummary', {}).get('totalSize', '0')
            num_artifacts = storage_info.get('storageSummary', {}).get('totalArtifacts', 0)
        except Exception as e:
            print(f"Failed to fetch storage info for {repo_key}: {e}")
            repo_size = "N/A"
            num_artifacts = "N/A"

        repo_details.append({
            "Name": repo_key,
            "Type": repo_type,
            "URL": repo_url,
            "Kind": repo_kind,
            "Size": repo_size,
            "Number of Artifacts": num_artifacts
        })
    return repo_details

# Write details to CSV
def write_to_csv(repo_details, filename="artifactory_repos.csv"):
    fieldnames = ["Name", "Type", "URL", "Kind", "Size", "Number of Artifacts"]
    with open(filename, mode='w', newline='') as file:
        writer = csv.DictWriter(file, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(repo_details)

if __name__ == "__main__":
    try:
        repo_details = fetch_repo_details()
        write_to_csv(repo_details)
        print("Repository details have been written to artifactory_repos.csv.")
    except Exception as e:
        print(f"An error occurred: {e}")

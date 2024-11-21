import http.client
import json
import base64
import csv

# Artifactory details
ARTIFACTORY_URL = "your.artifactory.instance"  # Replace with your Artifactory URL (e.g., artifactory.example.com)
ARTIFACTORY_USER = "your-username"  # Replace with your username
ENCRYPTED_PASSWORD = "your-encrypted-password"  # Replace with your encrypted password
OUTPUT_CSV = "artifactory_repos.csv"  # Output file

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

# Get repository summary details (faster than listing all files)
def get_repo_summary(repo_key):
    auth_header = {
        "Authorization": f"Basic {base64.b64encode(f'{ARTIFACTORY_USER}:{ENCRYPTED_PASSWORD}'.encode()).decode()}"
    }
    endpoint = f"/artifactory/api/storage/{repo_key}"
    try:
        data = make_request("GET", endpoint, headers=auth_header)
        total_size_bytes = int(data.get("repoSize", 0))
        total_size_mb = total_size_bytes / (1024 * 1024)  # Convert to MB
        artifact_count = int(data.get("filesCount", 0))  # Number of files
        return round(total_size_mb, 2), artifact_count
    except Exception as e:
        print(f"Failed to fetch summary for {repo_key}: {e}")
        return "N/A", "N/A"

# Write repository details to CSV (real-time updates)
def write_to_csv(repo_details, mode="w"):
    fieldnames = [
        "Name", "Package Type", "Repository Path", "Repository Layout",
        "Artifact Count", "Total Size (MB)"
    ]
    with open(OUTPUT_CSV, mode=mode, newline='') as file:
        writer = csv.DictWriter(file, fieldnames=fieldnames)
        if mode == "w":  # Write header only when creating the file
            writer.writeheader()
        writer.writerow(repo_details)

# Fetch and process repositories
def fetch_repo_details():
    repos = get_repositories()
    for idx, repo in enumerate(repos, 1):
        repo_key = repo['key']
        
        # Skip the repository if the name is 'docker-local'
        if repo_key == "docker-local":
            print(f"Skipping repository: {repo_key}")
            continue
        
        repo_type = repo['type']
        repo_layout = repo.get('repositoryLayout', 'N/A')
        package_type = repo.get('packageType', 'N/A')

        print(f"Processing repository {idx}/{len(repos)}: {repo_key}...")

        try:
            total_size_mb, artifact_count = get_repo_summary(repo_key)
            print(f"Repository: {repo_key}, Artifact Count: {artifact_count}, Total Size: {total_size_mb} MB")
        except Exception as e:
            print(f"Failed to process repository {repo_key}: {e}")
            total_size_mb, artifact_count = "N/A", "N/A"

        # Prepare repo details
        repo_details = {
            "Name": repo_key,
            "Package Type": package_type,
            "Repository Path": f"{repo_key}/",
            "Repository Layout": repo_layout,
            "Artifact Count": artifact_count,
            "Total Size (MB)": total_size_mb
        }

        # Write to CSV immediately
        write_to_csv(repo_details, mode="a")

if __name__ == "__main__":
    try:
        print("Starting repository processing...")
        # Create the CSV file and write the header
        write_to_csv({}, mode="w")
        # Process repositories
        fetch_repo_details()
        print(f"Repository details have been written to {OUTPUT_CSV}.")
    except Exception as e:
        print(f"An error occurred: {e}")

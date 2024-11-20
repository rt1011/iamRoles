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

# Get artifact count and size using deep listing
def get_artifact_details(repo_key):
    auth_header = {
        "Authorization": f"Basic {base64.b64encode(f'{ARTIFACTORY_USER}:{ENCRYPTED_PASSWORD}'.encode()).decode()}"
    }
    endpoint = f"/artifactory/api/storage/{repo_key}?list&deep=1"
    try:
        data = make_request("GET", endpoint, headers=auth_header)
        files = data.get("files", [])
        artifact_count = len(files)
        total_size_bytes = sum(file.get("size", 0) for file in files)
        total_size_mb = total_size_bytes / (1024 * 1024)  # Convert bytes to MB
        return artifact_count, round(total_size_mb, 2)
    except Exception as e:
        print(f"Failed to fetch details for {repo_key}: {e}")
        return "N/A", "N/A"

# Fetch repository details
def fetch_repo_details():
    repo_details = []
    repos = get_repositories()
    for idx, repo in enumerate(repos, 1):
        repo_key = repo['key']
        repo_type = repo['type']
        repo_layout = repo.get('repositoryLayout', 'N/A')
        package_type = repo.get('packageType', 'N/A')

        print(f"Processing repository {idx}/{len(repos)}: {repo_key}...")

        try:
            artifact_count, total_size_mb = get_artifact_details(repo_key)
            # Print size and artifact count
            print(f"Repository: {repo_key}, Artifact Count: {artifact_count}, Total Size: {total_size_mb} MB")
        except Exception as e:
            print(f"Failed to process repository {repo_key}: {e}")
            artifact_count, total_size_mb = "N/A", "N/A"

        repo_details.append({
            "Name": repo_key,
            "Package Type": package_type,
            "Repository Path": f"{repo_key}/",
            "Repository Layout": repo_layout,
            "Artifact Count": artifact_count,
            "Total Size (MB)": total_size_mb
        })
    return repo_details

# Write details to CSV
def write_to_csv(repo_details, filename="artifactory_repos.csv"):
    fieldnames = [
        "Name", "Package Type", "Repository Path", "Repository Layout", 
        "Artifact Count", "Total Size (MB)"
    ]
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

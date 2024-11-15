import http.client
import json
import csv
import base64

# Configuration
ARTIFACTORY_URL = "your-artifactory-domain.com"
USERNAME = "your-username"
ENCRYPTED_PASSWORD = "your-base64-encoded-password"  # Base64-encoded password

# Decode password
password = base64.b64decode(ENCRYPTED_PASSWORD).decode("utf-8")

# Function to get repository details
def get_repositories():
    conn = http.client.HTTPSConnection(ARTIFACTORY_URL)
    headers = {
        "Authorization": f"Basic {base64.b64encode(f'{USERNAME}:{password}'.encode()).decode()}"
    }
    
    conn.request("GET", "/artifactory/api/repositories", headers=headers)
    response = conn.getresponse()
    
    if response.status != 200:
        raise Exception(f"Failed to fetch repositories: {response.status} {response.reason}")
    
    repos = json.loads(response.read().decode())
    conn.close()
    return repos

# Function to get repository artifact count
def get_artifact_count(repo_key):
    conn = http.client.HTTPSConnection(ARTIFACTORY_URL)
    headers = {
        "Authorization": f"Basic {base64.b64encode(f'{USERNAME}:{password}'.encode()).decode()}"
    }
    
    conn.request("GET", f"/artifactory/api/storage/{repo_key}?list&deep=1", headers=headers)
    response = conn.getresponse()
    
    if response.status != 200:
        raise Exception(f"Failed to fetch artifacts for {repo_key}: {response.status} {response.reason}")
    
    data = json.loads(response.read().decode())
    conn.close()
    return len(data.get("files", []))

# Write data to CSV
def write_to_csv(data, filename="artifactory_repos.csv"):
    field_names = ["Repository Name", "Repository Type", "URL", "Artifact Count"]
    with open(filename, mode="w", newline="", encoding="utf-8") as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=field_names)
        writer.writeheader()
        writer.writerows(data)

# Main script
def main():
    try:
        repos = get_repositories()
        repo_data = []
        
        for repo in repos:
            repo_key = repo.get("key")
            repo_type = repo.get("type")
            url = f"https://{ARTIFACTORY_URL}/artifactory/{repo_key}"
            artifact_count = get_artifact_count(repo_key)
            
            repo_data.append({
                "Repository Name": repo_key,
                "Repository Type": repo_type,
                "URL": url,
                "Artifact Count": artifact_count
            })
        
        write_to_csv(repo_data)
        print(f"Repository data saved to 'artifactory_repos.csv'.")
    except Exception as e:
        print(f"An error occurred: {e}")

if __name__ == "__main__":
    main()

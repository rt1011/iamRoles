import http.client
import json
import base64
import csv

# Artifactory details and credentials
artifactory_host = 'your-artifactory-instance'
artifactory_url = f'/artifactory/api/repositories'
username = 'your-username'
encrypted_password = 'your-encrypted-password'

# Function to add Base64 padding if necessary
def add_base64_padding(encoded_string):
    return encoded_string + '=' * (-len(encoded_string) % 4)

# Decrypt the password (fix padding issue if necessary)
try:
    encrypted_password = add_base64_padding(encrypted_password)
    password = base64.b64decode(encrypted_password).decode('utf-8')
except Exception as e:
    print(f"Failed to decode password: {e}")
    exit(1)

# Helper function to make requests
def make_request(url):
    conn = http.client.HTTPSConnection(artifactory_host)
    headers = {
        'Authorization': 'Basic ' + base64.b64encode(f"{username}:{password}".encode()).decode(),
        'Content-Type': 'application/json'
    }
    conn.request("GET", url, headers=headers)
    response = conn.getresponse()
    data = response.read().decode()
    conn.close()
    return json.loads(data) if response.status == 200 else None

# Function to get all repositories
def get_repositories():
    return make_request(artifactory_url)

# Function to get artifact count for a repository
def get_artifact_count(repo_key):
    artifact_count_url = f'/artifactory/api/search/artifact?repos={repo_key}'
    data = make_request(artifact_count_url)
    return len(data.get('results', [])) if data else 0

# Main function to gather information and write to CSV
def main():
    repositories = get_repositories()
    
    if repositories:
        repo_info = []
        for repo in repositories:
            repo_key = repo.get('key')
            repo_type = repo.get('type')  # Repository type: local, remote, virtual
            package_type = repo.get('packageType')  # Package type: maven, npm, python, etc.
            repo_url = f"https://{artifactory_host}/artifactory/{repo_key}"
            artifact_count = get_artifact_count(repo_key)

            repo_info.append({
                'Name': repo_key,
                'Repository Type': repo_type,
                'Package Type': package_type,
                'URL': repo_url,
                'Artifact Count': artifact_count
            })

        # Write the collected information to a CSV file
        csv_file = "artifactory_repositories.csv"
        fieldnames = ['Name', 'Repository Type', 'Package Type', 'URL', 'Artifact Count']
        
        with open(csv_file, mode='w', newline='') as file:
            writer = csv.DictWriter(file, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(repo_info)
        
        print(f"Repository information has been written to {csv_file}")
    else:
        print("Failed to retrieve repositories.")

if __name__ == '__main__':
    main()

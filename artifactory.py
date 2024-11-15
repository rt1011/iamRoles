import http.client
import json
import base64

# Artifactory details and credentials
artifactory_host = 'your-artifactory-instance'
artifactory_url = f'/artifactory/api/repositories'
username = 'your-username'
encrypted_password = 'your-encrypted-password'

# Decrypt the password (this example uses base64 for simplicity; replace with actual decryption if needed)
password = base64.b64decode(encrypted_password).decode('utf-8')

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

# Main function to gather information and output it
def main():
    repositories = get_repositories()
    
    if repositories:
        repo_info = []
        for repo in repositories:
            repo_key = repo.get('key')
            repo_type = repo.get('type')
            repo_repo_url = f"https://{artifactory_host}/artifactory/{repo_key}"
            artifact_count = get_artifact_count(repo_key)

            repo_info.append({
                'Name': repo_key,
                'Type': repo_type,
                'URL': repo_repo_url,
                'Artifact Count': artifact_count
            })

        # Print each repository's information
        for info in repo_info:
            print(f"Name: {info['Name']}, Type: {info['Type']}, URL: {info['URL']}, Artifact Count: {info['Artifact Count']}")
    else:
        print("Failed to retrieve repositories.")

if __name__ == '__main__':
    main()

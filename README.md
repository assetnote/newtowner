# Newtowner

This tool is designed to help you test firewalls and network boundaries by masquerading traffic to appear as if it's originating from different datacenters around the world.

Modern cloud environments often have trust boundaries (such as allowing all traffic from the same datacenter) that are weak and can be easily bypassed. This has become a more prevalent issue as cloud platform popularity has increased.

Common misconfigurations of trust boundaries can be tested with this tool.

# Table of Contents

- [Checks](#checks)
- [Usage](#usage)
- [Setup](#setup)
  - [Configuration File](#configuration-file)
  - [Provider Setup](#provider-setup)
    - [GitHub Actions](#github-actions)
    - [GitLab CI](#gitlab-ci)
    - [Bitbucket Pipelines](#bitbucket-pipelines)
    - [AWS API Gateway](#aws-api-gateway)
    - [AWS EC2](#aws-ec2)
    - [Cloudflare Workers](#cloudflare-workers)

# Checks

This tool currently checks access differences for URLs (HTTP/HTTPS). It does not perform protocol-level checks, such as port scanning to identify differences in open ports across providers.

The following checks will be supported:

| Provider Name       | Identifier    | Status            |
| ------------------- | ------------- | ----------------- |
| GitHub Actions      | `github`      | Supported         |
| GitLab CI           | `gitlab`      | Supported         |
| Bitbucket Pipelines | `bitbucket`   | Supported         |
| AWS API Gateway     | `aws`         | Supported         |
| SSH/AWS EC2         | `ec2`         | Supported         |
| Cloudflare Workers  | `cloudflare`  | Supported         |
| Azure Functions     | `azure`       | Not yet supported |

# Usage

Run the tool using the following command syntax:

```
./newtowner --provider github --urls urls.txt
```

For AWS API-Gateway by default, it will use the closest datacenter to your target URLs but this can be overridden using `--region` flag.

# Setup

## Configuration File

Modify `configuration.json` in the root of this directory. Here's a complete example with all available configuration options:

```json
{
  // Github Provider
  "github_pat": "YOUR_GITHUB_PAT",
  "github_owner": "assetnote",
  "github_repo": "newtowner",
  "github_default_branch": "main",

  // Gitlab Provider
  "gitlab_pat": "YOUR_GITLAB_PAT",
  "gitlab_project_id": "your-project-id",
  "gitlab_pipeline_ref": "main",
  "gitlab_artifact_job_name": "your-job-name",
  "gitlab_pipeline_trigger_token": "optional-trigger-token",
  "gitlab_default_branch": "main",
  
  // Bitbucket Provider
  "bitbucket_workspace": "your-workspace-name",
  "bitbucket_repo_slug": "your-repository-name",
  "bitbucket_pipeline_ref": "main",
  "bitbucket_access_token": "your-workspace-access-token",

  // AWS API Gateway Provider
  "aws_access_key_id": "YOUR_AWS_ACCESS_KEY",
  "aws_secret_access_key": "YOUR_AWS_SECRET_KEY",

  // Cloudflare Workers Provider
  "cloudflare_account_id": "YOUR_CLOUDFLARE_ACCOUNT_ID",
  "cloudflare_api_token": "YOUR_CLOUDFLARE_API_TOKEN",
  "cloudflare_worker_url": "https://your-worker.your-subdomain.workers.dev",

  // AWS EC2 Provider
  "ssh_host": "your-ssh-host",
  "ssh_port": 22,
  "ssh_user": "your-ssh-user",
  "ssh_private_key_path": "path/to/private/key",
  "ssh_passphrase": "your-key-passphrase",
  "ec2_host": "your-ec2-host",
  "ec2_port": 22,
  "ec2_user": "your-ec2-user",
  "ec2_private_key_path": "path/to/ec2/private/key",
  "ec2_passphrase": "your-ec2-key-passphrase"
}
```

Note: remove the lines documenting the provider specific json because it will count as invalid json.


Note: You only need to configure the settings for the providers you plan to use. The example above shows all available options.

## Provider Setup

### GitHub Actions

To use Newtowner with GitHub Actions:

1.  **Fork/Clone Newtowner:** Ensure Actions are enabled. The workflow is at `.github/workflows/newtowner_check.yml`.
2.  **Create a Personal Access Token (PAT):**
    - Go to **Settings > Developer settings > Personal access tokens > Tokens (classic)**.
    - Click **Generate new token (classic)**.
    - Name it (e.g., `newtowner-github-actions`).
    - Select scopes: **`repo`** and **`workflow`**.
    - Click **Generate token** and save it securely.
3.  **Configure `configuration.json`:** In your fork/clone's root, add:
    ```json
    {
      "github_pat": "YOUR_GENERATED_PAT",
      "github_owner": "your-github-username-or-org",
      "github_repo": "newtowner", // Or your fork's name
      "github_default_branch": "main"
    }
    ```
4.  **Run Newtowner:**
    ```bash
    ./newtowner --provider github --urls urls.txt
    ```

### GitLab CI

To use Newtowner with GitLab CI:
1. **Add Newtowner to GitLab:** Fork/clone the repo to your GitLab instance and enable CI/CD (config: `.gitlab-ci.yml`).
2. **Create Tokens:**
   - **Access Token:** Create a PAT or Project Token with `api` scope
   - **Pipeline Trigger:** Add a trigger token in Project Settings > CI/CD
3. **Configure `configuration.json`:** Add settings to your local clone:
    ```json
    {
      "gitlab_pat": "YOUR_PAT_OR_PROJECT_ACCESS_TOKEN",
      "gitlab_project_id": "your-gitlab-project-id-for-newtowner",
      "gitlab_pipeline_ref": "main",
      "gitlab_artifact_job_name": "http_check_job", // Must match job in .gitlab-ci.yml
      "gitlab_pipeline_trigger_token": "YOUR_PIPELINE_TRIGGER_TOKEN",
      "gitlab_default_branch": "main"
    }
    ```
4.  **Run Newtowner:**
    ```bash
    ./newtowner --provider gitlab --urls urls.txt
    ```

### Bitbucket Pipelines

To use Newtowner with Bitbucket Pipelines:

1. **Add Newtowner to Bitbucket:** Import the repo to your workspace and enable Pipelines in Repository settings.
2. **Create Access Token:**
   - Go to **Repository settings > Security > Access tokens**
   - Create token named `newtowner_bitbucket_access`
   - Set permissions: Pipelines (`Read` & `Write`), Repositories (`Read`), Runners (`Read` & `Write`)
   - Save the token
3.  **Configure `configuration.json`:** In your local Newtowner repository clone (from Bitbucket), add:
    ```json
    {
      "bitbucket_workspace": "your-bitbucket-workspace-name",
      "bitbucket_repo_slug": "newtowner", // Your fork/clone's slug
      "bitbucket_pipeline_ref": "main",
      "bitbucket_access_token": "YOUR_APP_PASSWORD_OR_ACCESS_TOKEN"
    }
    ```
4.  **Run Newtowner:**
    ```bash
    ./newtowner --provider bitbucket --urls urls.txt
    ```

### AWS API Gateway

To allow Newtowner to interact with AWS services, you need to provide an Access Key ID and a Secret Access Key.

**1. Navigate to Security Credentials:**

1.  Sign in to the [AWS Management Console](https://aws.amazon.com/console/).
2.  Click on your account name/ID in the top right corner.
3.  From the dropdown menu, select **Security credentials**. (If you are logged in as an IAM user, this might be under "My Security Credentials").

**2. Create Access Key:**

1.  In the "Access keys" section, click **Create access key**
2.  Review the security warning
3.  Select "Command Line Interface (CLI)" as the use case
4.  Click through to create the access key

**3. Save Credentials:**

1. Save the displayed **Access key ID** and **Secret access key** immediately - you won't be able to view the secret key again
2. Download the `.csv` file or copy both keys to a secure location
3. Add the keys to your `configuration.json` file in the `aws_access_key_id` and `aws_secret_access_key` fields

### AWS EC2

The EC2 provider compares HTTP responses from an EC2 instance and a secondary SSH host to detect trust boundary bypasses across network locations.

#### Configuration

To use the EC2 provider, you need to configure SSH access for both the EC2 instance and a comparison SSH host. The configuration supports both key-based and passphrase-protected SSH keys.

1. **EC2 Instance Setup:**
   - You must have an existing EC2 instance - Newtowner does not automatically provision EC2 instances
   - Ensure your EC2 instance is running and accessible
   - Configure the EC2 instance's security group to allow SSH access
   - Note the EC2 instance's hostname/IP and SSH port (default: 22)

2. **Comparison SSH Host Setup:**
   - Set up a secondary SSH host in a different network location
   - Ensure this host is accessible and has Python 3 installed
   - Note the SSH host's hostname/IP and SSH port (default: 22)

3. **SSH Key Configuration:**
   - Prepare SSH keys for both hosts
   - Keys can be passphrase-protected
   - Store the keys in a secure location
   - Update the configuration with the following details:
     ```json
     {
       "ec2_host": "your-ec2-hostname-or-ip",
       "ec2_port": 22,
       "ec2_user": "ec2-user",
       "ec2_private_key_path": "path/to/ec2/private/key",
       "ec2_passphrase": "optional-key-passphrase",
       "ssh_host": "your-comparison-hostname-or-ip",
       "ssh_port": 22,
       "ssh_user": "ssh-user",
       "ssh_private_key_path": "path/to/ssh/private/key",
       "ssh_passphrase": "optional-key-passphrase"
     }
     ```

#### Usage

Run the tool with the EC2 provider:

```bash
./newtowner --provider ec2 --urls urls.txt
```

The tool will:
1. Connect to both the EC2 instance and comparison SSH host
2. Execute HTTP checks from both locations
3. Compare the responses to identify potential trust boundary bypasses
4. Auto-detect and display geographic information for both hosts
5. Clean up temporary files after each check

### Cloudflare Workers

To use Newtowner with Cloudflare Workers:

1. **Create API Token:**
   - Go to **Cloudflare Dashboard > My Profile > API Tokens**
   - Click **Create Token**
   - Use **Custom token** template
   - Set permissions: `Account:read` and `Workers Scripts:edit`
   - Save the token securely

2. **Deploy Worker:**
   ```bash
   # Install Wrangler (Cloudflare CLI)
   npm install -g wrangler

   # Login to Cloudflare
   wrangler login

   # Deploy the worker
   cd .cloudflare
   wrangler deploy --compatibility-date 2024-01-01
   ```

3. **Configure `configuration.json`:**
   ```json
   {
     "cloudflare_account_id": "your-account-id-here",
     "cloudflare_api_token": "your-api-token-here",
     "cloudflare_worker_url": "https://newtowner-worker.your-subdomain.workers.dev"
   }
   ```

4. **Run Newtowner:**
   ```bash
   ./newtowner --provider cloudflare --urls urls.txt
   ```

**Note:** If you leave `cloudflare_worker_url` empty, Newtowner will automatically deploy the worker for you.

#### Credits

Jordan Macey - [Assetnote](https://assetnote.io)

[Shubham Shah](https://x.com/infosec_au) - [Assetnote](https://assetnote.io)

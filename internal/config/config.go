package config

// Config holds all configuration for the Newtowner application.
// It reads from configuration.json, environment variables, and command-line flags.
type Config struct {
	// GitHub Provider Settings
	GithubPAT           string `mapstructure:"github_pat"`
	GithubOwner         string `mapstructure:"github_owner" default:"assetnote"` // Repository owner (user/org)
	GithubRepo          string `mapstructure:"github_repo" default:"newtowner"`  // Repository name
	GithubDefaultBranch string `mapstructure:"github_default_branch"`            // Default branch for dispatch (e.g., "main")

	// GitLab Provider Settings
	GitlabPAT                  string `mapstructure:"gitlab_pat"`
	GitlabProjectID            string `mapstructure:"gitlab_project_id"`             // GitLab Project ID (e.g., "12345") or Path (e.g., "group/subgroup/project")
	GitlabPipelineRef          string `mapstructure:"gitlab_pipeline_ref"`           // The branch or tag to run the pipeline on (e.g., "main")
	GitlabArtifactJobName      string `mapstructure:"gitlab_artifact_job_name"`      // Name of the job in .gitlab-ci.yml that produces the artifact
	GitlabPipelineTriggerToken string `mapstructure:"gitlab_pipeline_trigger_token"` // Optional: GitLab Pipeline Trigger Token
	GitlabDefaultBranch        string `mapstructure:"gitlab_default_branch"`         // Default branch for dispatch (e.g., "main")

	// Bitbucket Provider Settings
	BitbucketWorkspace   string `mapstructure:"bitbucket_workspace"`
	BitbucketRepoSlug    string `mapstructure:"bitbucket_repo_slug"`
	BitbucketPipelineRef string `mapstructure:"bitbucket_pipeline_ref"` // Branch/tag for pipelines, e.g., "main"
	BitbucketAccessToken string `mapstructure:"bitbucket_access_token"` // Workspace access token (preferred over App Password for API calls)

	AWSAccessKeyID     string `mapstructure:"aws_access_key_id"`
	AWSSecretAccessKey string `mapstructure:"aws_secret_access_key"`

	// Cloudflare Workers Provider Settings
	CloudflareAccountID string `mapstructure:"cloudflare_account_id"`
	CloudflareAPIToken  string `mapstructure:"cloudflare_api_token"`
	CloudflareWorkerURL string `mapstructure:"cloudflare_worker_url"` // Optional: custom worker URL

	// EC2 Provider Configuration (primary instance for EC2 provider)
	SshHost           string `mapstructure:"ssh_host"`
	SshPort           int    `mapstructure:"ssh_port"`
	SshUser           string `mapstructure:"ssh_user"`
	SshPrivateKeyPath string `mapstructure:"ssh_private_key_path"`
	SshPassphrase     string `mapstructure:"ssh_passphrase"`       // Added for passphrase-protected keys
	EC2Host           string `mapstructure:"ec2_host"`             // EC2 instance hostname for the EC2 provider
	EC2Port           int    `mapstructure:"ec2_port"`             // EC2 instance SSH port (default: 22)
	EC2User           string `mapstructure:"ec2_user"`             // EC2 instance SSH username
	EC2PrivateKeyPath string `mapstructure:"ec2_private_key_path"` // Path to the EC2 instance SSH private key
	EC2Passphrase     string `mapstructure:"ec2_passphrase"`       // Passphrase for the EC2 instance SSH private key
}

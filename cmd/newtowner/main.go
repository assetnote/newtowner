package main

import (
	"context"
	"fmt"
	"io"
	"log"
	"net/http"
	"newtowner/internal/config"
	"newtowner/internal/display"
	"newtowner/internal/providers/aws"
	"newtowner/internal/providers/bitbucket"
	"newtowner/internal/providers/cloudflare"
	"newtowner/internal/providers/github"
	gitlab "newtowner/internal/providers/gitlab"
	"newtowner/internal/providers/ssh"
	"newtowner/internal/util"
	"os"
	"path/filepath"
	"strings"

	"github.com/charmbracelet/lipgloss"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
)

const (
	dataDirName    = "data"
	mmdbFileName   = "GeoLite2-City.mmdb"
	mmdbURL        = "https://github.com/P3TERX/GeoLite.mmdb/raw/download/GeoLite2-City.mmdb"
	configBaseName = "configuration"
	configFileExt  = "json"
	configFileName = configBaseName + "." + configFileExt
)

var (
	providerFlag          *string
	urlsFilePathFlag      *string
	awsRegionFlag         *string
	brightdataCountryFlag *string
	updateDBFlag          *bool
	awsAllRegionsFlag     *bool
	sshHostFlag           *string
	sshPortFlag           *int
	sshUserFlag           *string
	sshKeyPathFlag        *string
	sshPassphraseFlag     *string
	// EC2 flags
	ec2HostFlag          *string
	ec2PortFlag          *int
	ec2UserFlag          *string
	ec2KeyPathFlag       *string
	ec2PassphraseFlag    *string
	ec2RegionFlag        *string
	comparisonRegionFlag *string
)

// init is run before main to set up configuration and flags.
func init() {
	// Define CLI flags using pflag
	providerFlag = pflag.String("provider", "", "Name of the provider (e.g., aws, github, gitlab, bitbucket, cloudflare, ssh, ec2)")
	urlsFilePathFlag = pflag.String("urls", "urls.txt", "Path to the file containing URLs to check (one URL per line)")
	awsRegionFlag = pflag.String("region", "", "Optional: Specify AWS region (e.g., us-east-1). Overridden by --all-regions.")
	updateDBFlag = pflag.Bool("update-db", false, "Force update of the GeoLite2-City.mmdb database")
	awsAllRegionsFlag = pflag.Bool("all-regions", false, "For AWS provider, check against all available AWS regions.")
	sshHostFlag = pflag.String("ssh-host", "", "SSH host for the SSH provider")
	sshPortFlag = pflag.Int("ssh-port", 22, "SSH port for the SSH provider")
	sshUserFlag = pflag.String("ssh-user", "", "SSH user for the SSH provider")
	sshKeyPathFlag = pflag.String("ssh-key-path", "", "Path to the SSH private key for the SSH provider")
	sshPassphraseFlag = pflag.String("ssh-passphrase", "", "Passphrase for the SSH private key, if protected")
	// EC2 flags
	ec2HostFlag = pflag.String("ec2-host", "", "EC2 host for the EC2 provider")
	ec2PortFlag = pflag.Int("ec2-port", 22, "EC2 port for the EC2 provider")
	ec2UserFlag = pflag.String("ec2-user", "", "EC2 user for the EC2 provider")
	ec2KeyPathFlag = pflag.String("ec2-key-path", "", "Path to the EC2 private key for the EC2 provider")
	ec2PassphraseFlag = pflag.String("ec2-passphrase", "", "Passphrase for the EC2 private key, if protected")
	ec2RegionFlag = pflag.String("ec2-region", "", "EC2 region for the EC2 provider")
	comparisonRegionFlag = pflag.String("comparison-region", "", "Comparison region for the EC2 provider")

	// Viper configuration
	viper.SetConfigName(configBaseName)
	viper.SetConfigType(configFileExt)
	viper.AddConfigPath(".")

	// Set defaults for GitHub provider config
	viper.SetDefault("github_owner", "assetnote")
	viper.SetDefault("github_repo", "newtowner")
	viper.SetDefault("github_default_branch", "main")

	// Set defaults for GitLab provider config
	viper.SetDefault("gitlab_pipeline_ref", "jmacey/gitlab-pipelines")
	viper.SetDefault("gitlab_artifact_job_name", "http_check_job")

	// Set defaults for Bitbucket provider config
	viper.SetDefault("bitbucket_pipeline_ref", "main")
	viper.SetDefault("bitbucket_workspace", "newtowner-bb")
	viper.SetDefault("bitbucket_repo_slug", "newtowner")

	// TODO: Consider adding other paths like $HOME/.newtowner, /etc/newtowner/

	if err := viper.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); ok {
			log.Printf("Configuration file ('%s') not found. Relying on defaults and environment variables if set.\n", configFileName)
		} else {
			log.Printf("Error reading configuration file '%s': %v\n", configFileName, err)
		}
	}

	// Bind flags to Viper
	viper.BindPFlag("provider", pflag.Lookup("provider"))
	viper.BindPFlag("urlsfile", pflag.Lookup("urls"))
	viper.BindPFlag("aws_region", pflag.Lookup("region"))
	viper.BindPFlag("update_db", pflag.Lookup("update-db"))
	viper.BindPFlag("aws_all_regions", pflag.Lookup("all-regions"))

	// SSH Provider Settings
	viper.BindPFlag("ssh_host", pflag.Lookup("ssh-host"))
	viper.BindPFlag("ssh_port", pflag.Lookup("ssh-port"))
	viper.BindPFlag("ssh_user", pflag.Lookup("ssh-user"))
	viper.BindPFlag("ssh_private_key_path", pflag.Lookup("ssh-key-path"))
	viper.BindPFlag("ssh_passphrase", pflag.Lookup("ssh-passphrase"))

	// EC2 Provider Settings
	viper.BindPFlag("ec2_host", pflag.Lookup("ec2-host"))
	viper.BindPFlag("ec2_port", pflag.Lookup("ec2-port"))
	viper.BindPFlag("ec2_user", pflag.Lookup("ec2-user"))
	viper.BindPFlag("ec2_private_key_path", pflag.Lookup("ec2-key-path"))
	viper.BindPFlag("ec2_passphrase", pflag.Lookup("ec2-passphrase"))
	viper.BindPFlag("ec2_region", pflag.Lookup("ec2-region"))
	viper.BindPFlag("ec2_comparison_region", pflag.Lookup("comparison-region"))

	viper.SetEnvPrefix("NEWTOWNER")
	viper.AutomaticEnv()
}

// ensureMMDBFile checks if the MaxMind DB file exists, and if not, or if forceUpdate is true, downloads it.
func ensureMMDBFile(dataDir string, dbPath string, url string, forceUpdate bool) error {
	if forceUpdate {
		log.Printf("Force update requested. Removing existing MaxMind DB file: %s (if it exists)...\n", dbPath)
		if err := os.Remove(dbPath); err != nil && !os.IsNotExist(err) {
			log.Printf("Warning: could not remove existing DB file at %s: %v\n", dbPath, err)
		}
	}

	if _, err := os.Stat(dbPath); err == nil && !forceUpdate {
		log.Printf("MaxMind DB file found at %s\n", dbPath)
		return nil
	} else if !os.IsNotExist(err) && !forceUpdate {
		return fmt.Errorf("error checking for MaxMind DB file at %s: %w", dbPath, err)
	}

	log.Printf("MaxMind DB file not found at %s or update forced. Downloading...\n", dbPath)

	if err := os.MkdirAll(dataDir, 0755); err != nil {
		return fmt.Errorf("failed to create data directory %s: %w", dataDir, err)
	}

	resp, err := http.Get(url)
	if err != nil {
		return fmt.Errorf("failed to download MaxMind DB file from %s: %w", url, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("failed to download MaxMind DB file: received status code %d from %s", resp.StatusCode, url)
	}

	out, err := os.Create(dbPath)
	if err != nil {
		return fmt.Errorf("failed to create MaxMind DB file %s: %w", dbPath, err)
	}
	defer out.Close()

	_, err = io.Copy(out, resp.Body)
	if err != nil {
		return fmt.Errorf("failed to write MaxMind DB file %s: %w", dbPath, err)
	}

	log.Printf("MaxMind DB file downloaded successfully to %s\n", dbPath)
	return nil
}

// General style for each column in the side-by-side table
var columnStyle = lipgloss.NewStyle().
	Padding(0, 1). // Padding left/right
	Width(70)      // Adjust width as needed for your content and terminal

func main() {
	pflag.Parse()

	currentWorkingDir, err := os.Getwd()
	if err != nil {
		log.Fatalf("Failed to get current working directory: %v", err)
	}

	projectRootDataDir := filepath.Join(currentWorkingDir, dataDirName)
	projectRootMmdbPath := filepath.Join(projectRootDataDir, mmdbFileName)

	if err := ensureMMDBFile(projectRootDataDir, projectRootMmdbPath, mmdbURL, *updateDBFlag); err != nil {
		log.Fatalf("Failed to ensure MaxMind DB file: %v", err)
	}

	if err := util.InitGeoLiteDB(projectRootMmdbPath); err != nil {
		log.Fatalf("Failed to initialize GeoLiteDB: %v", err)
	}
	defer util.CloseGeoLiteDB()
	log.Println("GeoLiteDB initialized successfully.")

	var cfg config.Config
	if err := viper.Unmarshal(&cfg); err != nil {
		log.Fatalf("Unable to decode configuration into struct: %v", err)
	}

	// Log the final configuration values
	log.Printf("Effective configuration loaded.")
	log.Printf("  Provider: %s", viper.GetString("provider"))
	log.Printf("  URLs File: %s", viper.GetString("urlsfile"))
	log.Printf("  AWS Region: %s", viper.GetString("aws_region"))
	log.Printf("  Update DB flag: %t", *updateDBFlag)
	log.Printf("  AWS All Regions flag: %t", *awsAllRegionsFlag)
	log.Printf("  GitHub PAT present: %t", cfg.GithubPAT != "")
	log.Printf("  GitHub Owner: %s", cfg.GithubOwner)
	log.Printf("  GitHub Repo: %s", cfg.GithubRepo)
	log.Printf("  GitHub Default Branch: %s", cfg.GithubDefaultBranch)
	log.Printf("  GitLab PAT present: %t", cfg.GitlabPAT != "")
	log.Printf("  GitLab Project ID: %s", cfg.GitlabProjectID)
	log.Printf("  GitLab Pipeline Ref: %s", cfg.GitlabPipelineRef)
	log.Printf("  GitLab Artifact Job Name: %s", cfg.GitlabArtifactJobName)
	log.Printf("  GitLab Default Branch: %s", cfg.GitlabDefaultBranch)
	log.Printf("  Bitbucket Workspace Access Token present: %t", cfg.BitbucketAccessToken != "")
	log.Printf("  Bitbucket Workspace: %s", cfg.BitbucketWorkspace)
	log.Printf("  Bitbucket Repo Slug: %s", cfg.BitbucketRepoSlug)
	log.Printf("  Bitbucket Pipeline Ref: %s", cfg.BitbucketPipelineRef)
	log.Printf("  AWS Access Key ID present: %t", cfg.AWSAccessKeyID != "")
	log.Printf("  AWS Secret Access Key present: %t", cfg.AWSSecretAccessKey != "")
	log.Printf("  Cloudflare Account ID: %s", cfg.CloudflareAccountID)
	log.Printf("  Cloudflare API Token present: %t", cfg.CloudflareAPIToken != "")
	log.Printf("  Cloudflare Worker URL: %s", cfg.CloudflareWorkerURL)
	log.Printf("  SSH Host: %s", cfg.SshHost)
	log.Printf("  SSH Port: %d", cfg.SshPort)
	log.Printf("  SSH User: %s", cfg.SshUser)
	log.Printf("  SSH Key Path: %s", cfg.SshPrivateKeyPath)
	log.Printf("  SSH Key Passphrase Provided: %t", cfg.SshPassphrase != "")
	log.Printf("  EC2 Host: %s", cfg.EC2Host)
	log.Printf("  EC2 Port: %d", cfg.EC2Port)
	log.Printf("  EC2 User: %s", cfg.EC2User)
	log.Printf("  EC2 Key Path: %s", cfg.EC2PrivateKeyPath)
	log.Printf("  EC2 Key Passphrase Provided: %t", cfg.EC2Passphrase != "")

	selectedProvider := strings.ToLower(viper.GetString("provider"))
	urlsFilePath := viper.GetString("urlsfile")

	if selectedProvider == "" {
		log.Fatalf("Error: --provider flag is required. Please specify a provider.")
	}
	if urlsFilePath == "" {
		log.Fatalf("Error: --urls flag (or urlsfile in config) is required. Please specify a path to a file containing URLs.")
	}

	targetURLs, err := util.ReadURLsFromFile(urlsFilePath)
	if err != nil {
		log.Fatalf("Error reading URLs from file %s: %v", urlsFilePath, err)
	}
	if len(targetURLs) == 0 {
		log.Fatalf("No URLs found in file: %s", urlsFilePath)
	}
	log.Printf("Found %d URLs to check from %s: %v", len(targetURLs), urlsFilePath, targetURLs)

	log.Printf("Starting checks for provider: %s", selectedProvider)

	ctx := context.Background()

	switch selectedProvider {
	case "aws":
		log.Println("Initializing AWS provider...")
		awsRegion := viper.GetString("aws_region")
		if *awsAllRegionsFlag {
			log.Println("AWS --all-regions flag is set. The specific --region flag (if any) will be ignored for region iteration.")
		}

		awsProvider, err := aws.NewProvider(ctx, cfg.AWSAccessKeyID, cfg.AWSSecretAccessKey, awsRegion, *awsAllRegionsFlag)
		if err != nil {
			log.Fatalf("Error initializing AWS provider: %v", err)
		}
		log.Println("AWS provider initialized successfully.")

		awsResults, err := awsProvider.CheckURLs(targetURLs)
		if err != nil {
			log.Fatalf("Error during AWS provider URL checks: %v", err)
		}
		log.Println("AWS provider checks completed.")

		fmt.Println(display.DefaultDisplayStyles.StyleHeader.Render(fmt.Sprintf("\nAWS Provider Check Results (%d URLs):", len(awsResults))))

		for i, res := range awsResults {
			display.DisplaySingleURLCheckResult(i, res, display.DefaultDisplayStyles)
		}

	case "github":
		log.Println("Initializing GitHub provider...")
		githubProvider, err := github.NewProvider(ctx, cfg.GithubPAT, cfg.GithubOwner, cfg.GithubRepo, cfg.GithubDefaultBranch)
		if err != nil {
			log.Fatalf("Error initializing GitHub provider: %v", err)
		}
		log.Println("GitHub provider initialized successfully.")

		githubResults, err := githubProvider.CheckURLs(targetURLs)
		if err != nil {
			log.Fatalf("Error during GitHub provider URL checks: %v", err)
		}
		log.Println("GitHub provider checks completed.")

		fmt.Println(display.DefaultDisplayStyles.StyleHeader.Render(fmt.Sprintf("\nGitHub Provider Check Results (%d URLs processed):", len(githubResults))))

		for i, res := range githubResults {
			display.DisplaySingleURLCheckResult(i, res, display.DefaultDisplayStyles)
		}

	case "gitlab":
		log.Println("Initializing GitLab provider...")

		effectiveGitlabPipelineRef := cfg.GitlabPipelineRef
		if effectiveGitlabPipelineRef == "" {
			effectiveGitlabPipelineRef = cfg.GitlabDefaultBranch
		}
		if effectiveGitlabPipelineRef == "" {
			effectiveGitlabPipelineRef = "main"
		}
		log.Printf("Using effective GitLab Pipeline Reference: %s", effectiveGitlabPipelineRef)

		gitlabProvider, err := gitlab.NewGitLabProvider(ctx, cfg.GitlabPAT, cfg.GitlabProjectID, effectiveGitlabPipelineRef, cfg.GitlabArtifactJobName, cfg.GitlabPipelineTriggerToken)
		if err != nil {
			log.Fatalf("Error initializing GitLab provider: %v", err)
		}
		log.Println("GitLab provider initialized successfully.")

		gitlabResults, err := gitlabProvider.CheckURLs(targetURLs)
		if err != nil {
			log.Fatalf("Error during GitLab provider URL checks: %v", err)
		}
		log.Println("GitLab provider checks completed.")

		fmt.Println(display.DefaultDisplayStyles.StyleHeader.Render(fmt.Sprintf("\nGitLab Provider Check Results (%d URLs processed):", len(gitlabResults))))

		for i, res := range gitlabResults {
			display.DisplaySingleURLCheckResult(i, res, display.DefaultDisplayStyles)
		}

	case "bitbucket":
		log.Println("Initializing Bitbucket provider...")

		effectiveBitbucketPipelineRef := cfg.BitbucketPipelineRef
		if effectiveBitbucketPipelineRef == "" {
			effectiveBitbucketPipelineRef = "main"
		}
		log.Printf("Using effective Bitbucket Pipeline Reference: %s", effectiveBitbucketPipelineRef)

		customPipelineName := "newtowner-http-check"

		bitbucketProvider, err := bitbucket.NewBitbucketProvider(ctx, cfg.BitbucketWorkspace, cfg.BitbucketRepoSlug, effectiveBitbucketPipelineRef, cfg.BitbucketAccessToken, customPipelineName)
		if err != nil {
			log.Fatalf("Error initializing Bitbucket provider: %v", err)
		}
		log.Println("Bitbucket provider initialized successfully.")

		bitbucketResults, err := bitbucketProvider.CheckURLs(targetURLs)
		if err != nil {
			log.Fatalf("Error during Bitbucket provider URL checks: %v", err)
		}
		log.Println("Bitbucket provider checks completed.")

		fmt.Println(display.DefaultDisplayStyles.StyleHeader.Render(fmt.Sprintf("\nBitbucket Provider Check Results (%d URLs processed):", len(bitbucketResults))))

		for i, res := range bitbucketResults {
			display.DisplaySingleURLCheckResult(i, res, display.DefaultDisplayStyles)
		}

	case "ssh":
		log.Println("Initializing SSH provider...")
		sshProvider, err := ssh.NewProvider(ctx, cfg.SshHost, cfg.SshPort, cfg.SshUser, cfg.SshPrivateKeyPath, cfg.SshPassphrase)
		if err != nil {
			log.Fatalf("Error initializing SSH provider: %v", err)
		}
		defer sshProvider.Close()
		log.Println("SSH provider initialized successfully.")

		log.Println("Transferring runner script to SSH host...")
		if err := sshProvider.TransferRunnerScript(ctx); err != nil {
			log.Fatalf("Error transferring runner script to SSH host: %v", err)
		}
		log.Println("Runner script transferred successfully.")

		sshResults, err := sshProvider.CheckURLs(targetURLs)
		if err != nil {
			log.Fatalf("Error during SSH provider URL checks: %v", err)
		}
		log.Println("SSH provider checks completed.")

		fmt.Println(display.DefaultDisplayStyles.StyleHeader.Render(fmt.Sprintf("\nSSH Provider Check Results (%d URLs processed):", len(sshResults))))

		for i, res := range sshResults {
			display.DisplaySingleURLCheckResult(i, res, display.DefaultDisplayStyles)
		}

	case "ec2":
		log.Println("Initializing EC2 dual SSH provider...")

		ec2Config := aws.EC2ProviderConfig{
			EC2Host:       cfg.EC2Host,
			EC2Port:       cfg.EC2Port,
			EC2User:       cfg.EC2User,
			EC2KeyPath:    cfg.EC2PrivateKeyPath,
			EC2Passphrase: cfg.EC2Passphrase,
			SshHost:       cfg.SshHost,
			SshPort:       cfg.SshPort,
			SshUser:       cfg.SshUser,
			SshKeyPath:    cfg.SshPrivateKeyPath,
			SshPassphrase: cfg.SshPassphrase,
		}

		ec2Provider, err := aws.NewEC2Provider(ctx, ec2Config)
		if err != nil {
			log.Fatalf("Error initializing EC2 provider: %v", err)
		}
		defer ec2Provider.Close()
		log.Println("EC2 provider initialized successfully.")

		log.Println("Transferring runner script to both instances...")
		if err := ec2Provider.TransferRunnerScript(ctx); err != nil {
			log.Fatalf("Error transferring runner script: %v", err)
		}
		log.Println("Runner script transferred successfully.")

		ec2Results, err := ec2Provider.CheckURLs(targetURLs)
		if err != nil {
			log.Fatalf("Error during EC2 provider URL checks: %v", err)
		}
		log.Println("EC2 provider checks completed.")

		fmt.Println(display.DefaultDisplayStyles.StyleHeader.Render(fmt.Sprintf("\nEC2 Dual SSH Provider Check Results (%d URLs processed):", len(ec2Results))))

		for i, res := range ec2Results {
			display.DisplaySingleURLCheckResult(i, res, display.DefaultDisplayStyles)
		}

	case "cloudflare":
		log.Println("Initializing Cloudflare provider...")
		cloudflareProvider, err := cloudflare.NewProvider(ctx, cfg.CloudflareAccountID, cfg.CloudflareAPIToken, cfg.CloudflareWorkerURL)
		if err != nil {
			log.Fatalf("Error initializing Cloudflare provider: %v", err)
		}
		log.Println("Cloudflare provider initialized successfully.")

		cloudflareResults, err := cloudflareProvider.CheckURLs(targetURLs)
		if err != nil {
			log.Fatalf("Error during Cloudflare provider URL checks: %v", err)
		}
		log.Println("Cloudflare provider checks completed.")

		fmt.Println(display.DefaultDisplayStyles.StyleHeader.Render(fmt.Sprintf("\nCloudflare Provider Check Results (%d URLs processed):", len(cloudflareResults))))

		for i, res := range cloudflareResults {
			display.DisplaySingleURLCheckResult(i, res, display.DefaultDisplayStyles)
		}

	default:
		log.Fatalf("Unsupported provider: %s", selectedProvider)
	}

	log.Println("Newtowner finished.")
}

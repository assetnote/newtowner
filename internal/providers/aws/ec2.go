package aws

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"log"
	"net/url"
	"newtowner/internal/util"
	"os"
	osuser "os/user"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	scp "github.com/bramvdbogaerde/go-scp"
	"golang.org/x/crypto/ssh"
)

const (
	defaultSshPort          = 22
	defaultRemoteRunnerPath = "/tmp/http_check_runner.py"
	remoteTempFilePrefix    = "/tmp/newtowner_result_"
	localTempFilePrefix     = "newtowner_remote_result_"
	localRunnerScriptPath   = "scripts/http_check_runner.py"
	sshCommandTimeout       = 45 * time.Second
	sshConnectionTimeout    = 20 * time.Second
)

type EC2ProviderConfig struct {
	EC2Host       string
	EC2Port       int
	EC2User       string
	EC2KeyPath    string
	EC2Passphrase string

	SshHost       string
	SshPort       int
	SshUser       string
	SshKeyPath    string
	SshPassphrase string

	AllowLegacyRenegotiation bool
}

type EC2URLCheckResult struct {
	URL              string
	Error            string
	DirectRequest    util.RequestDetails // request from secondary ssh instance
	RemoteRequest    util.RequestDetails // request from primary ec2 instance
	Comparison       util.ComparisonResult
	PotentialBypass  bool
	BypassReason     string
	EC2Host          string
	EC2User          string
	EC2Port          int
	EC2Region        string
	EC2GeoLocation   string
	SshHost          string
	SshUser          string
	SshPort          int
	SshRegion        string
	SshGeoLocation   string
	TargetHostname   string
	TargetResolvedIP string
	TargetGeoCountry string
	TargetGeoRegion  string
}

func (r EC2URLCheckResult) GetURL() string { return r.URL }

func (r EC2URLCheckResult) GetTargetHostname() string { return r.TargetHostname }

func (r EC2URLCheckResult) GetTargetResolvedIP() string { return r.TargetResolvedIP }

func (r EC2URLCheckResult) GetTargetGeoCountry() string { return r.TargetGeoCountry }

func (r EC2URLCheckResult) GetTargetGeoRegion() string { return r.TargetGeoRegion }

func (r EC2URLCheckResult) GetProcessingError() string { return r.Error }

func (r EC2URLCheckResult) GetDirectRequestDetails() util.RequestDetails { return r.DirectRequest }

func (r EC2URLCheckResult) GetProviderRequestDetails() util.RequestDetails { return r.RemoteRequest }

func (r EC2URLCheckResult) GetProviderDisplayName() string {
	ec2RegionDisplay := r.EC2Region
	if r.EC2GeoLocation != "" {
		ec2RegionDisplay = fmt.Sprintf("%s [%s]", r.EC2Region, r.EC2GeoLocation)
	}

	return fmt.Sprintf("EC2/%s/%s", r.EC2Host, ec2RegionDisplay)
}

func (r EC2URLCheckResult) GetDirectDisplayName() string {
	sshRegionDisplay := r.SshRegion
	if r.SshGeoLocation != "" {
		sshRegionDisplay = fmt.Sprintf("%s [%s]", r.SshRegion, r.SshGeoLocation)
	}

	return fmt.Sprintf("SSH/%s/%s", r.SshHost, sshRegionDisplay)
}

func (r EC2URLCheckResult) GetProviderSubDetails() string {
	if r.RemoteRequest.Error != "" {
		return fmt.Sprintf("EC2 (%s): %s@%s:%d, Script Error: %s", r.EC2Region, r.EC2User, r.EC2Host, r.EC2Port, util.TruncateString(r.RemoteRequest.Error, 100))
	}
	if r.EC2Host == "" {
		return "EC2 Target: Not configured or execution failed early"
	}
	return fmt.Sprintf("EC2 (%s): %s@%s:%d, Status: %d", r.EC2Region, r.EC2User, r.EC2Host, r.EC2Port, r.RemoteRequest.StatusCode)
}

func (r EC2URLCheckResult) GetComparisonResult() util.ComparisonResult { return r.Comparison }

func (r EC2URLCheckResult) IsPotentialBypass() bool { return r.PotentialBypass }

func (r EC2URLCheckResult) GetBypassReason() string { return r.BypassReason }

func (r EC2URLCheckResult) ShouldSkipBodyDiff() bool {
	return r.Error != "" || r.DirectRequest.Error != "" || r.RemoteRequest.Error != ""
}

type EC2Provider struct {
	// primary ec2 instance configuration (ec2 prefix)
	ec2Host                   string
	ec2Port                   int
	ec2User                   string
	ec2PrivateKeyPath         string
	ec2Client                 *ssh.Client
	ec2Passphrase             string
	ec2RemotePythonRunnerPath string
	ec2Region                 string
	ec2GeoLocation            string

	// secondary ssh instance configuration (ssh prefix)
	sshHost                   string
	sshPort                   int
	sshUser                   string
	sshPrivateKeyPath         string
	sshClient                 *ssh.Client
	sshPassphrase             string
	sshRemotePythonRunnerPath string
	sshGeoLocation            string
	comparisonRegion          string
	allowLegacyRenegotiation  bool
}

// NewEC2Provider creates a new EC2 dual SSH provider instance.
func NewEC2Provider(ctx context.Context, config EC2ProviderConfig) (*EC2Provider, error) {
	if config.EC2Host == "" {
		return nil, fmt.Errorf("EC2 host must be provided")
	}
	if config.EC2User == "" {
		return nil, fmt.Errorf("EC2 user must be provided")
	}
	if config.SshHost == "" {
		return nil, fmt.Errorf("SSH host must be provided")
	}
	if config.SshUser == "" {
		return nil, fmt.Errorf("SSH user must be provided")
	}

	p := &EC2Provider{
		ec2Host:                  config.EC2Host,
		ec2Port:                  config.EC2Port,
		ec2User:                  config.EC2User,
		sshHost:                  config.SshHost,
		sshPort:                  config.SshPort,
		sshUser:                  config.SshUser,
		allowLegacyRenegotiation: config.AllowLegacyRenegotiation,
	}

	if p.ec2Port <= 0 {
		p.ec2Port = defaultSshPort
		log.Printf("[EC2Provider] EC2 port not specified or invalid, using default: %d", p.ec2Port)
	}
	if p.sshPort <= 0 {
		p.sshPort = defaultSshPort
		log.Printf("[EC2Provider] SSH port not specified or invalid, using default: %d", p.sshPort)
	}

	if err := p.detectRegions(); err != nil {
		log.Printf("[EC2Provider] Warning: Failed to auto-detect regions: %v", err)
	}

	// Configure EC2 SSH key
	if config.EC2KeyPath != "" {
		ec2KeyPath := config.EC2KeyPath
		if strings.HasPrefix(ec2KeyPath, "~/") {
			usr, err := osuser.Current()
			if err != nil {
				return nil, fmt.Errorf("failed to get current user for EC2 key path expansion: %w", err)
			}
			ec2KeyPath = filepath.Join(usr.HomeDir, ec2KeyPath[2:])
		}
		p.ec2PrivateKeyPath = ec2KeyPath
		log.Printf("[EC2Provider] Using EC2 SSH key path: %s", p.ec2PrivateKeyPath)
	} else {
		log.Println("[EC2Provider] No EC2 SSH key path provided. Will attempt SSH agent or Pageant.")
	}

	// Configure secondary SSH key
	if config.SshKeyPath != "" {
		sshKeyPath := config.SshKeyPath
		if strings.HasPrefix(sshKeyPath, "~/") {
			usr, err := osuser.Current()
			if err != nil {
				return nil, fmt.Errorf("failed to get current user for SSH key path expansion: %w", err)
			}
			sshKeyPath = filepath.Join(usr.HomeDir, sshKeyPath[2:])
		}
		p.sshPrivateKeyPath = sshKeyPath
		log.Printf("[EC2Provider] Using SSH key path: %s", p.sshPrivateKeyPath)
	} else {
		log.Println("[EC2Provider] No SSH key path provided. Will attempt SSH agent or Pageant.")
	}

	p.ec2Passphrase = config.EC2Passphrase
	p.sshPassphrase = config.SshPassphrase
	if config.EC2Passphrase != "" {
		log.Println("[EC2Provider] EC2 SSH key passphrase provided.")
	}
	if config.SshPassphrase != "" {
		log.Println("[EC2Provider] SSH key passphrase provided.")
	}

	p.ec2RemotePythonRunnerPath = defaultRemoteRunnerPath
	p.sshRemotePythonRunnerPath = defaultRemoteRunnerPath

	log.Printf("[EC2Provider] Initialized - EC2 target: %s@%s:%d, SSH target: %s@%s:%d",
		p.ec2User, p.ec2Host, p.ec2Port, p.sshUser, p.sshHost, p.sshPort)
	return p, nil
}

// getEC2SshClient establishes or returns an existing SSH client for the EC2 instance.
func (p *EC2Provider) getEC2SshClient(ctx context.Context) (*ssh.Client, error) {
	if p.ec2Client != nil {
		_, _, err := p.ec2Client.SendRequest("keepalive@newtowner.an", true, nil)
		if err == nil {
			return p.ec2Client, nil
		}
		log.Printf("[EC2Provider] EC2 SSH client keepalive failed: %v. Reconnecting...", err)
		p.ec2Client.Close()
		p.ec2Client = nil
	}

	log.Printf("[EC2Provider] Establishing new SSH connection to EC2 instance %s@%s:%d", p.ec2User, p.ec2Host, p.ec2Port)
	var authMethods []ssh.AuthMethod
	if p.ec2PrivateKeyPath != "" {
		keyAuth, err := getKeyFile(p.ec2PrivateKeyPath, p.ec2Passphrase)
		if err != nil {
			return nil, fmt.Errorf("failed to get EC2 key file for SSH connection: %w", err)
		}
		authMethods = append(authMethods, keyAuth)
	}

	config := &ssh.ClientConfig{
		User:            p.ec2User,
		Auth:            authMethods,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         sshConnectionTimeout,
	}

	sshAddr := fmt.Sprintf("%s:%d", p.ec2Host, p.ec2Port)
	client, err := ssh.Dial("tcp", sshAddr, config)
	if err != nil {
		return nil, fmt.Errorf("failed to dial EC2 SSH host %s: %w", sshAddr, err)
	}
	p.ec2Client = client
	log.Printf("[EC2Provider] EC2 SSH connection established to %s", sshAddr)
	return p.ec2Client, nil
}

// getSshClient establishes or returns an existing SSH client for the secondary SSH instance.
func (p *EC2Provider) getSshClient(ctx context.Context) (*ssh.Client, error) {
	if p.sshClient != nil {
		_, _, err := p.sshClient.SendRequest("keepalive@newtowner.an", true, nil)
		if err == nil {
			return p.sshClient, nil
		}
		log.Printf("[EC2Provider] SSH client keepalive failed: %v. Reconnecting...", err)
		p.sshClient.Close()
		p.sshClient = nil
	}

	log.Printf("[EC2Provider] Establishing new SSH connection to %s@%s:%d", p.sshUser, p.sshHost, p.sshPort)
	var authMethods []ssh.AuthMethod
	if p.sshPrivateKeyPath != "" {
		keyAuth, err := getKeyFile(p.sshPrivateKeyPath, p.sshPassphrase)
		if err != nil {
			return nil, fmt.Errorf("failed to get SSH key file for SSH connection: %w", err)
		}
		authMethods = append(authMethods, keyAuth)
	}

	config := &ssh.ClientConfig{
		User:            p.sshUser,
		Auth:            authMethods,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         sshConnectionTimeout,
	}

	sshAddr := fmt.Sprintf("%s:%d", p.sshHost, p.sshPort)
	client, err := ssh.Dial("tcp", sshAddr, config)
	if err != nil {
		return nil, fmt.Errorf("failed to dial SSH host %s: %w", sshAddr, err)
	}
	p.sshClient = client
	log.Printf("[EC2Provider] SSH connection established to %s", sshAddr)
	return p.sshClient, nil
}

func (p *EC2Provider) Close() error {
	var errors []string

	if p.ec2Client != nil {
		log.Printf("[EC2Provider] Closing EC2 SSH connection to %s@%s:%d", p.ec2User, p.ec2Host, p.ec2Port)
		if err := p.ec2Client.Close(); err != nil {
			errors = append(errors, fmt.Sprintf("EC2 client: %v", err))
		}
		p.ec2Client = nil
	}

	if p.sshClient != nil {
		log.Printf("[EC2Provider] Closing SSH connection to %s@%s:%d", p.sshUser, p.sshHost, p.sshPort)
		if err := p.sshClient.Close(); err != nil {
			errors = append(errors, fmt.Sprintf("SSH client: %v", err))
		}
		p.sshClient = nil
	}

	if len(errors) > 0 {
		return fmt.Errorf("errors closing connections: %s", strings.Join(errors, ", "))
	}
	return nil
}

// CheckURLs performs checks for the given URLs comparing between SSH and EC2 instance
func (p *EC2Provider) CheckURLs(urls []string) ([]EC2URLCheckResult, error) {
	log.Printf("[EC2Provider] Checking %d URLs - SSH/%s (%s@%s:%d) vs EC2/%s (%s@%s:%d)",
		len(urls), p.comparisonRegion, p.sshUser, p.sshHost, p.sshPort, p.ec2Region, p.ec2User, p.ec2Host, p.ec2Port)
	ctx := context.Background()
	allResults := make([]EC2URLCheckResult, 0)

	for _, rawURL := range urls {
		log.Printf("[EC2Provider] Processing URL: %s", rawURL)

		currentResult := EC2URLCheckResult{
			URL:            rawURL,
			EC2Host:        p.ec2Host,
			EC2User:        p.ec2User,
			EC2Port:        p.ec2Port,
			EC2Region:      p.ec2Region,
			EC2GeoLocation: p.ec2GeoLocation,
			SshHost:        p.sshHost,
			SshUser:        p.sshUser,
			SshPort:        p.sshPort,
			SshRegion:      p.comparisonRegion,
			SshGeoLocation: p.sshGeoLocation,
		}

		parsedURL, err := url.Parse(rawURL)
		if err != nil {
			currentResult.Error = util.AppendError(currentResult.Error, fmt.Sprintf("Error parsing URL: %v", err))
			allResults = append(allResults, currentResult)
			continue
		}
		currentResult.TargetHostname = parsedURL.Hostname()
		if currentResult.TargetHostname == "" {
			currentResult.Error = util.AppendError(currentResult.Error, "Could not extract hostname from URL.")
			allResults = append(allResults, currentResult)
			continue
		}

		geoLoc, resolvedIP, geoErr := util.ResolveHostAndGetGeoLocation(currentResult.TargetHostname)
		if geoErr != nil {
			log.Printf("[EC2Provider]   Warning: Error resolving host or getting geolocation for %s: %v", currentResult.TargetHostname, geoErr)
		} else {
			currentResult.TargetResolvedIP = resolvedIP.String()
			currentResult.TargetGeoCountry = geoLoc.CountryCode
			currentResult.TargetGeoRegion = geoLoc.RegionName
		}

		// 1. ssh request (acts as "direct" request)
		log.Printf("[EC2Provider]   Making SSH request to %s via %s@%s", rawURL, p.sshUser, p.sshHost)
		sshReqDetails, sshErr := p.executeSSHCheck(ctx, rawURL)
		if sshErr != nil {
			errStr := fmt.Sprintf("SSH check failed: %v", sshErr)
			currentResult.Error = util.AppendError(currentResult.Error, errStr)
			log.Printf("[EC2Provider]     %s", errStr)
			if sshReqDetails.URL != "" {
				currentResult.DirectRequest = sshReqDetails
			} else {
				currentResult.DirectRequest.Error = errStr
				currentResult.DirectRequest.URL = rawURL
			}
		} else {
			currentResult.DirectRequest = sshReqDetails
		}

		// 2. ec2 request (acts as "remote" request)
		log.Printf("[EC2Provider]   Making EC2 request to %s via %s@%s", rawURL, p.ec2User, p.ec2Host)
		ec2ReqDetails, ec2Err := p.executeEC2Check(ctx, rawURL)
		if ec2Err != nil {
			errStr := fmt.Sprintf("EC2 check failed: %v", ec2Err)
			currentResult.Error = util.AppendError(currentResult.Error, errStr)
			log.Printf("[EC2Provider]     %s", errStr)
			if ec2ReqDetails.URL != "" {
				currentResult.RemoteRequest = ec2ReqDetails
			} else {
				currentResult.RemoteRequest.Error = errStr
				currentResult.RemoteRequest.URL = rawURL
			}
		} else {
			currentResult.RemoteRequest = ec2ReqDetails
		}

		// 3. compare the results
		if currentResult.RemoteRequest.Error == "" && currentResult.DirectRequest.Error == "" {
			comparisonResult, potentialBypass, bypassReason := util.CompareHTTPResponses(currentResult.DirectRequest, currentResult.RemoteRequest)
			currentResult.Comparison = comparisonResult
			currentResult.PotentialBypass = potentialBypass
			currentResult.BypassReason = bypassReason
			if potentialBypass {
				log.Printf("[EC2Provider]     Potential Bypass Detected for %s: %s", rawURL, bypassReason)
			} else {
				log.Printf("[EC2Provider]     No significant differences detected for %s. Reason: %s", rawURL, bypassReason)
			}
		} else {
			log.Printf("[EC2Provider]     Skipping comparison for %s due to request errors", rawURL)
			currentResult.PotentialBypass = false
			currentResult.BypassReason = "Comparison skipped due to request errors"
			if currentResult.RemoteRequest.Error != "" {
				currentResult.BypassReason += fmt.Sprintf(". EC2 error: %s", util.TrimmedString(currentResult.RemoteRequest.Error, 100))
			}
			if currentResult.DirectRequest.Error != "" {
				currentResult.BypassReason += fmt.Sprintf(". SSH error: %s", util.TrimmedString(currentResult.DirectRequest.Error, 100))
			}
		}
		allResults = append(allResults, currentResult)
	}
	return allResults, nil
}

// executeSSHCheck executes HTTP check via the secondary SSH instance.
func (p *EC2Provider) executeSSHCheck(ctx context.Context, targetURL string) (util.RequestDetails, error) {
	return p.executeRemoteCheck(ctx, targetURL, p.getSshClient, p.sshRemotePythonRunnerPath, "SSH")
}

// executeEC2Check executes HTTP check via the primary EC2 instance.
func (p *EC2Provider) executeEC2Check(ctx context.Context, targetURL string) (util.RequestDetails, error) {
	return p.executeRemoteCheck(ctx, targetURL, p.getEC2SshClient, p.ec2RemotePythonRunnerPath, "EC2")
}

// executeRemoteCheck is a generic method to execute remote SSH checks.
func (p *EC2Provider) executeRemoteCheck(ctx context.Context, targetURL string, clientGetter func(context.Context) (*ssh.Client, error), runnerPath string, logPrefix string) (util.RequestDetails, error) {
	var details util.RequestDetails
	details.URL = targetURL

	sshClient, err := clientGetter(ctx)
	if err != nil {
		return details, fmt.Errorf("failed to get %s SSH client: %w", logPrefix, err)
	}

	// Generate a unique remote filename for the JSON output
	randomBytes := make([]byte, 8)
	_, err = rand.Read(randomBytes)
	if err != nil {
		return details, fmt.Errorf("failed to generate random suffix for %s remote temp file: %w", logPrefix, err)
	}
	remoteTempJSONPath := fmt.Sprintf("%s%x.json", remoteTempFilePrefix, randomBytes)
	log.Printf("[EC2Provider]   %s temporary JSON output file will be: %s", logPrefix, remoteTempJSONPath)

	quotedTargetURL := strconv.Quote(targetURL)
	remoteCommand := fmt.Sprintf("python3 %s %s --output_file %s", runnerPath, quotedTargetURL, remoteTempJSONPath)
	if p.allowLegacyRenegotiation {
		remoteCommand += " --legacy-renegotiation"
	}
	log.Printf("[EC2Provider]   Executing %s remote command: %s", logPrefix, remoteCommand)

	session, err := sshClient.NewSession()
	if err != nil {
		return details, fmt.Errorf("failed to create %s SSH session for command execution: %w", logPrefix, err)
	}
	defer session.Close()

	var stderrBuf bytes.Buffer
	session.Stderr = &stderrBuf

	cmdErrChan := make(chan error, 1)
	go func() {
		cmdErrChan <- session.Run(remoteCommand)
	}()

	select {
	case err = <-cmdErrChan:
	case <-time.After(sshCommandTimeout):
		p.cleanupRemoteFile(ctx, sshClient, remoteTempJSONPath, logPrefix)
		return details, fmt.Errorf("%s SSH command timed out after %v: %s", logPrefix, sshCommandTimeout, remoteCommand)
	case <-ctx.Done():
		p.cleanupRemoteFile(ctx, sshClient, remoteTempJSONPath, logPrefix)
		return details, fmt.Errorf("%s SSH command context cancelled: %w", logPrefix, ctx.Err())
	}

	stderrOutput := strings.TrimSpace(stderrBuf.String())

	if err != nil {
		errMsg := fmt.Sprintf("failed to run %s SSH command '%s': %v", logPrefix, remoteCommand, err)
		if stderrOutput != "" {
			errMsg = fmt.Sprintf("%s. Stderr: %s", errMsg, util.TruncateString(stderrOutput, 200))
		}
		details.Error = errMsg
		p.cleanupRemoteFile(ctx, sshClient, remoteTempJSONPath, logPrefix)
		return details, fmt.Errorf(details.Error)
	}

	log.Printf("[EC2Provider]   %s remote command executed. Stderr: %s", logPrefix, util.TruncateString(stderrOutput, 200))
	log.Printf("[EC2Provider]   Attempting to download %s via SCP.", remoteTempJSONPath)

	localTempFile, err := os.CreateTemp("", localTempFilePrefix+"*.json")
	if err != nil {
		p.cleanupRemoteFile(ctx, sshClient, remoteTempJSONPath, logPrefix)
		return details, fmt.Errorf("failed to create local temporary file for %s SCP: %w", logPrefix, err)
	}
	localTempFilePath := localTempFile.Name()
	defer func() {
		localTempFile.Close()
		os.Remove(localTempFilePath)
		log.Printf("[EC2Provider]   Cleaned up local temporary file: %s", localTempFilePath)
	}()

	scpClient, err := scp.NewClientBySSH(sshClient)
	if err != nil {
		p.cleanupRemoteFile(ctx, sshClient, remoteTempJSONPath, logPrefix)
		return details, fmt.Errorf("error creating %s SCP client from SSH session: %w", logPrefix, err)
	}

	scpCtx, scpCancel := context.WithTimeout(ctx, sshCommandTimeout)
	defer scpCancel()

	err = scpClient.CopyFromRemote(scpCtx, localTempFile, remoteTempJSONPath)
	localTempFile.Close()

	if err != nil {
		p.cleanupRemoteFile(ctx, sshClient, remoteTempJSONPath, logPrefix)
		details.Error = fmt.Sprintf("failed to download %s remote file %s via SCP to %s: %v", logPrefix, remoteTempJSONPath, localTempFilePath, err)
		return details, fmt.Errorf(details.Error)
	}

	log.Printf("[EC2Provider]   Successfully downloaded %s to %s", remoteTempJSONPath, localTempFilePath)

	p.cleanupRemoteFile(ctx, sshClient, remoteTempJSONPath, logPrefix)

	jsonBytes, readErr := os.ReadFile(localTempFilePath)
	if readErr != nil {
		details.Error = util.AppendError(details.Error, fmt.Sprintf("failed to read downloaded %s JSON file %s: %v", logPrefix, localTempFilePath, readErr))
		return details, fmt.Errorf(details.Error)
	}

	if len(jsonBytes) == 0 {
		details.Error = util.AppendError(details.Error, fmt.Sprintf("downloaded %s JSON file %s is empty. Stderr from script: %s", logPrefix, localTempFilePath, util.TruncateString(stderrOutput, 200)))
		return details, fmt.Errorf(details.Error)
	}

	var scriptActionResults []util.ProxiedResult
	if unmarshalErr := json.Unmarshal(jsonBytes, &scriptActionResults); unmarshalErr != nil {
		parseErrMsg := fmt.Sprintf("failed to parse %s JSON from downloaded file: %v. Content preview: '%s'", logPrefix, unmarshalErr, util.TruncateString(string(jsonBytes), 200))
		details.Error = util.AppendError(details.Error, parseErrMsg)
		return details, fmt.Errorf(details.Error)
	}

	if len(scriptActionResults) == 0 {
		details.Error = util.AppendError(details.Error, fmt.Sprintf("%s JSON array from script is empty", logPrefix))
		return details, fmt.Errorf(details.Error)
	}

	scriptResult := scriptActionResults[0]

	details.URL = scriptResult.URL
	details.StatusCode = scriptResult.StatusCode
	details.Body = scriptResult.Body
	details.BodySHA256 = scriptResult.BodySHA256
	if scriptResult.Error != "" {
		details.Error = util.AppendError(details.Error, fmt.Sprintf("%s remote script error: %s", logPrefix, scriptResult.Error))
	}
	details.ResponseTime = scriptResult.ResponseTimeMs
	details.BodyBase64 = scriptResult.BodyBase64
	details.Headers = scriptResult.Headers
	details.SSLCertificatePEM = scriptResult.SSLCertificatePEM
	details.SSLCertificateError = scriptResult.SSLCertificateError

	log.Printf("[EC2Provider]   %s check processed. Script Status: %d, Script Error: %s, BodySHA: %s", logPrefix, scriptResult.StatusCode, scriptResult.Error, scriptResult.BodySHA256)

	if details.Error != "" {
		return details, fmt.Errorf(details.Error)
	}

	return details, nil
}

// cleanupRemoteFile attempts to delete a file on the remote server.
func (p *EC2Provider) cleanupRemoteFile(ctx context.Context, client *ssh.Client, remotePath string, logPrefix string) {
	log.Printf("[EC2Provider]   Attempting to clean up %s remote file: %s", logPrefix, remotePath)
	cleanupSession, err := client.NewSession()
	if err != nil {
		log.Printf("[EC2Provider]     Failed to create %s session for remote cleanup of %s: %v", logPrefix, remotePath, err)
		return
	}
	defer cleanupSession.Close()

	quotedRemotePath := strconv.Quote(remotePath)
	cleanupCommand := fmt.Sprintf("rm -f %s", quotedRemotePath)

	var stderrBuf bytes.Buffer
	cleanupSession.Stderr = &stderrBuf

	cleanupCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	errChan := make(chan error, 1)
	go func() {
		errChan <- cleanupSession.Run(cleanupCommand)
	}()

	select {
	case err = <-errChan:
		if err != nil {
			stderr := strings.TrimSpace(stderrBuf.String())
			log.Printf("[EC2Provider]     Failed to delete %s remote file %s: %v. Stderr: %s", logPrefix, remotePath, err, util.TruncateString(stderr, 100))
		} else {
			log.Printf("[EC2Provider]     Successfully deleted %s remote file: %s", logPrefix, remotePath)
		}
	case <-cleanupCtx.Done():
		log.Printf("[EC2Provider]     Timeout during %s remote file cleanup of %s: %v", logPrefix, remotePath, cleanupCtx.Err())
	}
}

// TransferRunnerScript copies the http_check_runner.py script to both SSH instances over scp
func (p *EC2Provider) TransferRunnerScript(ctx context.Context) error {
	if err := p.transferRunnerScriptToTarget(ctx, p.getEC2SshClient, p.ec2RemotePythonRunnerPath, "EC2"); err != nil {
		return fmt.Errorf("failed to transfer script to EC2 instance: %w", err)
	}

	if err := p.transferRunnerScriptToTarget(ctx, p.getSshClient, p.sshRemotePythonRunnerPath, "SSH"); err != nil {
		return fmt.Errorf("failed to transfer script to SSH instance: %w", err)
	}

	return nil
}

func (p *EC2Provider) transferRunnerScriptToTarget(ctx context.Context, clientGetter func(context.Context) (*ssh.Client, error), targetPath string, logPrefix string) error {
	log.Printf("[EC2Provider] Attempting to transfer local script '%s' to %s instance at path: %s", localRunnerScriptPath, logPrefix, targetPath)

	scriptBytes, err := os.ReadFile(localRunnerScriptPath)
	if err != nil {
		return fmt.Errorf("failed to read local runner script from '%s': %w", localRunnerScriptPath, err)
	}

	if len(scriptBytes) == 0 {
		return fmt.Errorf("local runner script '%s' is empty", localRunnerScriptPath)
	}

	sshClient, err := clientGetter(ctx)
	if err != nil {
		return fmt.Errorf("failed to get %s SSH client for SCP: %w", logPrefix, err)
	}

	scpClient, err := scp.NewClientBySSH(sshClient)
	if err != nil {
		return fmt.Errorf("error creating %s SCP client from SSH session: %w", logPrefix, err)
	}

	scriptReader := bytes.NewReader(scriptBytes)
	scriptSize := int64(len(scriptBytes))

	copyCtx, cancel := context.WithTimeout(ctx, sshCommandTimeout)
	defer cancel()

	log.Printf("[EC2Provider] Starting SCP transfer of runner script (%d bytes) to %s instance", scriptSize, logPrefix)
	err = scpClient.Copy(copyCtx, scriptReader, targetPath, "0755", scriptSize)
	if err != nil {
		return fmt.Errorf("error copying script via SCP to %s instance: %w", logPrefix, err)
	}

	log.Printf("[EC2Provider] Successfully transferred script to %s instance at %s", logPrefix, targetPath)
	return nil
}

func getKeyFile(keyPath string, passphrase string) (ssh.AuthMethod, error) {
	buf, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read ssh key file %s: %w", keyPath, err)
	}

	var signer ssh.Signer
	if passphrase != "" {
		signer, err = ssh.ParsePrivateKeyWithPassphrase(buf, []byte(passphrase))
		if err != nil {
			return nil, fmt.Errorf("failed to parse passphrase-protected ssh private key from %s: %w", keyPath, err)
		}
	} else {
		signer, err = ssh.ParsePrivateKey(buf)
		if err != nil {
			return nil, fmt.Errorf("failed to parse ssh private key from %s: %w", keyPath, err)
		}
	}
	return ssh.PublicKeys(signer), nil
}

// detectRegions attempts to automatically detect geographic regions for both EC2 and SSH hosts
// using IP geolocation and AWS region mapping.
func (p *EC2Provider) detectRegions() error {
	var errors []string

	if p.ec2Region == "" {
		log.Printf("[EC2Provider] Auto-detecting region for EC2 host: %s", p.ec2Host)
		geoLoc, resolvedIP, err := util.ResolveHostAndGetGeoLocation(p.ec2Host)
		if err != nil {
			errMsg := fmt.Sprintf("failed to resolve/geolocate EC2 host %s: %v", p.ec2Host, err)
			errors = append(errors, errMsg)
			log.Printf("[EC2Provider] %s", errMsg)
		} else {
			p.ec2GeoLocation = fmt.Sprintf("%s, %s (%s)", geoLoc.RegionName, geoLoc.CountryName, geoLoc.CountryCode)
			log.Printf("[EC2Provider] EC2 host %s resolved to %s, location: %s", p.ec2Host, resolvedIP.String(), p.ec2GeoLocation)

			awsRegion, err := util.GetAWSRegionFromGeo(geoLoc.CountryCode, geoLoc.RegionName, "")
			if err != nil {
				log.Printf("[EC2Provider] Could not map EC2 host location to AWS region: %v", err)
				p.ec2Region = fmt.Sprintf("unknown-%s", geoLoc.CountryCode)
			} else {
				p.ec2Region = awsRegion
				log.Printf("[EC2Provider] Detected EC2 AWS region: %s", p.ec2Region)
			}
		}
	} else {
		log.Printf("[EC2Provider] Using configured EC2 region: %s", p.ec2Region)
	}

	if p.comparisonRegion == "" {
		log.Printf("[EC2Provider] Auto-detecting region for SSH host: %s", p.sshHost)
		geoLoc, resolvedIP, err := util.ResolveHostAndGetGeoLocation(p.sshHost)
		if err != nil {
			errMsg := fmt.Sprintf("failed to resolve/geolocate SSH host %s: %v", p.sshHost, err)
			errors = append(errors, errMsg)
			log.Printf("[EC2Provider] %s", errMsg)
		} else {
			p.sshGeoLocation = fmt.Sprintf("%s, %s (%s)", geoLoc.RegionName, geoLoc.CountryName, geoLoc.CountryCode)
			log.Printf("[EC2Provider] SSH host %s resolved to %s, location: %s", p.sshHost, resolvedIP.String(), p.sshGeoLocation)

			// Map to AWS region for comparison purposes
			awsRegion, err := util.GetAWSRegionFromGeo(geoLoc.CountryCode, geoLoc.RegionName, "")
			if err != nil {
				log.Printf("[EC2Provider] Could not map SSH host location to AWS region: %v", err)
				p.comparisonRegion = fmt.Sprintf("unknown-%s", geoLoc.CountryCode)
			} else {
				p.comparisonRegion = awsRegion
				log.Printf("[EC2Provider] Detected SSH comparison region: %s", p.comparisonRegion)
			}
		}
	} else {
		log.Printf("[EC2Provider] Using configured comparison region: %s", p.comparisonRegion)
	}

	log.Printf("[EC2Provider] Region comparison setup: EC2 (%s) vs SSH (%s)", p.ec2Region, p.comparisonRegion)
	if p.ec2GeoLocation != "" && p.sshGeoLocation != "" {
		log.Printf("[EC2Provider] Geographic comparison: EC2 [%s] vs SSH [%s]", p.ec2GeoLocation, p.sshGeoLocation)
	}

	if len(errors) > 0 {
		return fmt.Errorf("region detection errors: %s", strings.Join(errors, "; "))
	}
	return nil
}

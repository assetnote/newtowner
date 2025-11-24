package ssh

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
	defaultRemoteRunnerPath = "/tmp/http_check_runner.py"    // Default path for the python script on the remote server
	remoteTempFilePrefix    = "/tmp/newtowner_result_"       // Prefix for temporary JSON output files on remote
	localTempFilePrefix     = "newtowner_remote_result_"     // Prefix for temporary local files after SCP
	localRunnerScriptPath   = "scripts/http_check_runner.py" // Hardcoded path to the local runner script
	sshCommandTimeout       = 45 * time.Second               // Timeout for the entire SSH command execution
	sshConnectionTimeout    = 20 * time.Second               // Timeout for establishing the SSH connection
)

// URLCheckResult holds all information for a single URL check.
type URLCheckResult struct {
	URL              string
	Error            string
	DirectRequest    util.RequestDetails
	RemoteSshRequest util.RequestDetails
	Comparison       util.ComparisonResult
	PotentialBypass  bool
	BypassReason     string
	SshHost          string
	SshUser          string
	SshPort          int
	TargetHostname   string
	TargetResolvedIP string
	TargetGeoCountry string
	TargetGeoRegion  string
}

func (r URLCheckResult) GetURL() string { return r.URL }

func (r URLCheckResult) GetTargetHostname() string { return r.TargetHostname }

func (r URLCheckResult) GetTargetResolvedIP() string { return r.TargetResolvedIP }

func (r URLCheckResult) GetTargetGeoCountry() string { return r.TargetGeoCountry }

func (r URLCheckResult) GetTargetGeoRegion() string { return r.TargetGeoRegion }

func (r URLCheckResult) GetProcessingError() string { return r.Error }

func (r URLCheckResult) GetDirectRequestDetails() util.RequestDetails { return r.DirectRequest }

func (r URLCheckResult) GetDirectDisplayName() string {
	return "Direct Request Details"
}

func (r URLCheckResult) GetProviderRequestDetails() util.RequestDetails { return r.RemoteSshRequest }

func (r URLCheckResult) GetProviderDisplayName() string {
	return fmt.Sprintf("Direct vs SSH Remote (%s@%s:%d)", r.SshUser, r.SshHost, r.SshPort)
}

func (r URLCheckResult) GetProviderSubDetails() string {
	if r.RemoteSshRequest.Error != "" {
		return fmt.Sprintf("SSH Target: %s@%s:%d, Remote Script Error: %s", r.SshUser, r.SshHost, r.SshPort, util.TruncateString(r.RemoteSshRequest.Error, 100))
	}
	if r.SshHost == "" {
		return "SSH Target: Not configured or execution failed early."
	}
	return fmt.Sprintf("SSH Target: %s@%s:%d, Remote Status: %d", r.SshUser, r.SshHost, r.SshPort, r.RemoteSshRequest.StatusCode)
}

func (r URLCheckResult) GetComparisonResult() util.ComparisonResult { return r.Comparison }

func (r URLCheckResult) IsPotentialBypass() bool { return r.PotentialBypass }

func (r URLCheckResult) GetBypassReason() string { return r.BypassReason }

func (r URLCheckResult) ShouldSkipBodyDiff() bool {
	return r.Error != "" || r.DirectRequest.Error != "" || r.RemoteSshRequest.Error != ""
}

// Provider struct holds SSH configuration.
type Provider struct {
	sshHost                  string
	sshPort                  int
	sshUser                  string
	sshPrivateKeyPath        string
	remotePythonRunnerPath   string
	sshClient                *ssh.Client
	sshPassphrase            string
	allowLegacyRenegotiation bool
}

// NewProvider creates a new SSH Comparison provider instance.
func NewProvider(ctx context.Context, host string, port int, user string, keyPath string, passphrase string, allowLegacyRenegotiation bool) (*Provider, error) {
	if host == "" {
		return nil, fmt.Errorf("SSH host must be provided")
	}
	if user == "" {
		return nil, fmt.Errorf("SSH user must be provided")
	}

	p := &Provider{
		sshHost:                  host,
		sshPort:                  port,
		sshUser:                  user,
		allowLegacyRenegotiation: allowLegacyRenegotiation,
	}

	if p.sshPort <= 0 {
		p.sshPort = defaultSshPort
		log.Printf("[SSH Provider] SSH port not specified or invalid, using default: %d", p.sshPort)
	}

	if keyPath != "" {
		if strings.HasPrefix(keyPath, "~/") {
			usr, err := osuser.Current()
			if err != nil {
				return nil, fmt.Errorf("failed to get current user for key path expansion: %w", err)
			}
			keyPath = filepath.Join(usr.HomeDir, keyPath[2:])
		}
		p.sshPrivateKeyPath = keyPath
		log.Printf("[SSH Provider] Using SSH key path: %s", p.sshPrivateKeyPath)
	} else {
		log.Println("[SSH Provider] No SSH key path provided. Will attempt SSH agent or Pageant.")
	}

	p.sshPassphrase = passphrase
	if passphrase != "" {
		log.Println("[SSH Provider] SSH key passphrase provided.")
	}

	p.remotePythonRunnerPath = defaultRemoteRunnerPath
	log.Printf("[SSH Provider] Remote Python runner script path: %s", p.remotePythonRunnerPath)
	log.Printf("[SSH Provider] Local Python runner script will be read from hardcoded path: %s", localRunnerScriptPath)

	log.Printf("[SSH Provider] Initialized for SSH target: %s@%s:%d", p.sshUser, p.sshHost, p.sshPort)
	return p, nil
}

// getSshClient establishes or returns an existing SSH client for the provider.
// It centralizes SSH connection logic.
func (p *Provider) getSshClient(ctx context.Context) (*ssh.Client, error) {
	if p.sshClient != nil {
		_, _, err := p.sshClient.SendRequest("keepalive@newtowner.beer", true, nil)
		if err == nil {
			return p.sshClient, nil
		}
		log.Printf("[SSH Provider] SSH client keepalive failed: %v. Reconnecting...", err)
		p.sshClient.Close()
		p.sshClient = nil
	}

	log.Printf("[SSH Provider] Establishing new SSH connection to %s@%s:%d", p.sshUser, p.sshHost, p.sshPort)
	var authMethods []ssh.AuthMethod
	if p.sshPrivateKeyPath != "" {
		keyAuth, err := getKeyFile(p.sshPrivateKeyPath, p.sshPassphrase)
		if err != nil {
			return nil, fmt.Errorf("failed to get key file for SSH connection: %w", err)
		}
		authMethods = append(authMethods, keyAuth)
	} else {
		log.Println("[SSH Provider] No SSH key path provided. Attempting agent-based or other available SSH authentication methods.")
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
	log.Printf("[SSH Provider] SSH connection established to %s", sshAddr)
	return p.sshClient, nil
}

func (p *Provider) Close() error {
	if p.sshClient != nil {
		log.Printf("[SSH Provider] Closing SSH connection to %s@%s:%d", p.sshUser, p.sshHost, p.sshPort)
		err := p.sshClient.Close()
		p.sshClient = nil
		return err
	}
	return nil
}

func (p *Provider) CheckURLs(urls []string) ([]URLCheckResult, error) {
	log.Printf("[SSH Provider] Checking %d URLs against direct scan vs remote SSH host %s@%s:%d", len(urls), p.sshUser, p.sshHost, p.sshPort)
	ctx := context.Background()
	allResults := make([]URLCheckResult, 0)

	for _, rawURL := range urls {
		log.Printf("[SSH Provider] Processing URL: %s", rawURL)

		currentResult := URLCheckResult{
			URL:     rawURL,
			SshHost: p.sshHost,
			SshUser: p.sshUser,
			SshPort: p.sshPort,
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
			log.Printf("[SSH Provider]   Warning: Error resolving host or getting geolocation for %s: %v", currentResult.TargetHostname, geoErr)
		} else {
			currentResult.TargetResolvedIP = resolvedIP.String()
			currentResult.TargetGeoCountry = geoLoc.CountryCode
			currentResult.TargetGeoRegion = geoLoc.RegionName
		}

		// 1. Direct Request
		log.Printf("[SSH Provider]   Making direct request to %s", rawURL)
		currentResult.DirectRequest = util.MakeHTTPRequest(ctx, "GET", rawURL, false)
		if currentResult.DirectRequest.Error != "" {
			log.Printf("[SSH Provider]     Direct request error: %s", currentResult.DirectRequest.Error)
		}

		// 2. Remote SSH Request
		log.Printf("[SSH Provider]   Making remote request to %s via SSH host %s", rawURL, p.sshHost)
		remoteReqDetails, remoteErr := p.executeRemoteSshCheck(ctx, rawURL)
		if remoteErr != nil {
			errStr := fmt.Sprintf("Remote SSH check failed: %v", remoteErr)
			currentResult.Error = util.AppendError(currentResult.Error, errStr)
			log.Printf("[SSH Provider]     %s", errStr)
			if remoteReqDetails.URL != "" {
				currentResult.RemoteSshRequest = remoteReqDetails
			} else {
				currentResult.RemoteSshRequest.Error = errStr
				currentResult.RemoteSshRequest.URL = rawURL
			}
		} else {
			currentResult.RemoteSshRequest = remoteReqDetails
		}

		// 3. Comparison
		if currentResult.RemoteSshRequest.Error == "" {
			comparisonResult, potentialBypass, bypassReason := util.CompareHTTPResponses(currentResult.DirectRequest, currentResult.RemoteSshRequest)
			currentResult.Comparison = comparisonResult
			currentResult.PotentialBypass = potentialBypass
			currentResult.BypassReason = bypassReason
			if potentialBypass {
				log.Printf("[SSH Provider]     Potential Bypass Detected for %s: %s", rawURL, bypassReason)
			} else {
				log.Printf("[SSH Provider]     No significant differences detected or comparison inconclusive for %s. Reason: %s", rawURL, bypassReason)
			}
		} else {
			// Remote SSH request itself failed, so no comparison is possible.
			log.Printf("[SSH Provider]     Skipping comparison for %s due to remote SSH request error: %s", rawURL, currentResult.RemoteSshRequest.Error)
			currentResult.PotentialBypass = false
			currentResult.BypassReason = fmt.Sprintf("Comparison skipped: Remote SSH request failed: %s", util.TrimmedString(currentResult.RemoteSshRequest.Error, 150))
			if currentResult.DirectRequest.Error != "" {
				currentResult.BypassReason += fmt.Sprintf(". Direct request also failed: %s", util.TrimmedString(currentResult.DirectRequest.Error, 100))
			}
			if currentResult.Error == "" {
				currentResult.Error = util.AppendError(currentResult.Error, "Remote SSH request failed, comparison skipped.")
			}
		}
		allResults = append(allResults, currentResult)
	}
	return allResults, nil
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

// executeRemoteSshCheck connects to the remote server, runs the http_check_runner.py script (saving output to a temp file),
// downloads the temp file via SCP, parses it, and then cleans up the remote temp file.
func (p *Provider) executeRemoteSshCheck(ctx context.Context, targetURL string) (util.RequestDetails, error) {
	var details util.RequestDetails
	details.URL = targetURL

	sshClient, err := p.getSshClient(ctx)
	if err != nil {
		return details, fmt.Errorf("failed to get SSH client: %w", err)
	}

	// Generate a unique remote filename for the JSON output
	randomBytes := make([]byte, 8)
	_, err = rand.Read(randomBytes)
	if err != nil {
		return details, fmt.Errorf("failed to generate random suffix for remote temp file: %w", err)
	}
	remoteTempJSONPath := fmt.Sprintf("%s%x.json", remoteTempFilePrefix, randomBytes)
	log.Printf("[SSH Provider]   Remote temporary JSON output file will be: %s", remoteTempJSONPath)

	quotedTargetURL := strconv.Quote(targetURL)
	remoteCommand := fmt.Sprintf("python3 %s %s --output_file %s", p.remotePythonRunnerPath, quotedTargetURL, remoteTempJSONPath)
	if p.allowLegacyRenegotiation {
		remoteCommand += " --legacy-renegotiation"
	}
	log.Printf("[SSH Provider]   Executing remote command: %s", remoteCommand)

	session, err := sshClient.NewSession()
	if err != nil {
		return details, fmt.Errorf("failed to create SSH session for command execution: %w", err)
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
		p.cleanupRemoteFile(ctx, sshClient, remoteTempJSONPath)
		return details, fmt.Errorf("SSH command timed out after %v: %s", sshCommandTimeout, remoteCommand)
	case <-ctx.Done():
		p.cleanupRemoteFile(ctx, sshClient, remoteTempJSONPath)
		return details, fmt.Errorf("SSH command context cancelled: %w", ctx.Err())
	}

	stderrOutput := strings.TrimSpace(stderrBuf.String())

	if err != nil {
		errMsg := fmt.Sprintf("failed to run SSH command '%s': %v", remoteCommand, err)
		if stderrOutput != "" {
			errMsg = fmt.Sprintf("%s. Stderr: %s", errMsg, util.TruncateString(stderrOutput, 200))
		}
		details.Error = errMsg
		p.cleanupRemoteFile(ctx, sshClient, remoteTempJSONPath) // Attempt cleanup
		return details, fmt.Errorf(details.Error)
	}

	log.Printf("[SSH Provider]   Remote command executed. Stderr: %s", util.TruncateString(stderrOutput, 200))
	log.Printf("[SSH Provider]   Attempting to download %s via SCP.", remoteTempJSONPath)

	// Create a temporary local file to store the SCP'd result
	localTempFile, err := os.CreateTemp("", localTempFilePrefix+"*.json")
	if err != nil {
		p.cleanupRemoteFile(ctx, sshClient, remoteTempJSONPath) // Attempt cleanup
		return details, fmt.Errorf("failed to create local temporary file for SCP: %w", err)
	}
	localTempFilePath := localTempFile.Name()
	defer func() {
		localTempFile.Close()
		os.Remove(localTempFilePath)
		log.Printf("[SSH Provider]   Cleaned up local temporary file: %s", localTempFilePath)
	}()

	scpClient, err := scp.NewClientBySSH(sshClient)
	if err != nil {
		p.cleanupRemoteFile(ctx, sshClient, remoteTempJSONPath)
		p.sshClient.Close()
		p.sshClient = nil
		return details, fmt.Errorf("error creating SCP client from SSH session: %w. SSH client has been reset", err)
	}

	scpCtx, scpCancel := context.WithTimeout(ctx, sshCommandTimeout)
	defer scpCancel()

	err = scpClient.CopyFromRemote(scpCtx, localTempFile, remoteTempJSONPath)
	localTempFile.Close()

	if err != nil {
		p.cleanupRemoteFile(ctx, sshClient, remoteTempJSONPath)
		details.Error = fmt.Sprintf("failed to download remote file %s via SCP to %s: %v", remoteTempJSONPath, localTempFilePath, err)
		return details, fmt.Errorf(details.Error)
	}

	log.Printf("[SSH Provider]   Successfully downloaded %s to %s", remoteTempJSONPath, localTempFilePath)

	p.cleanupRemoteFile(ctx, sshClient, remoteTempJSONPath)

	jsonBytes, readErr := os.ReadFile(localTempFilePath)
	if readErr != nil {
		details.Error = util.AppendError(details.Error, fmt.Sprintf("failed to read downloaded JSON file %s: %v", localTempFilePath, readErr))
		return details, fmt.Errorf(details.Error)
	}

	if len(jsonBytes) == 0 {
		details.Error = util.AppendError(details.Error, fmt.Sprintf("downloaded JSON file %s is empty. Stderr from script: %s", localTempFilePath, util.TruncateString(stderrOutput, 200)))
		return details, fmt.Errorf(details.Error)
	}

	var scriptActionResults []util.ProxiedResult
	if unmarshalErr := json.Unmarshal(jsonBytes, &scriptActionResults); unmarshalErr != nil {
		parseErrMsg := fmt.Sprintf("failed to parse JSON from downloaded file: %v. Content preview: '%s'", unmarshalErr, util.TruncateString(string(jsonBytes), 200))
		details.Error = util.AppendError(details.Error, parseErrMsg)
		return details, fmt.Errorf(details.Error)
	}

	if len(scriptActionResults) == 0 {
		details.Error = util.AppendError(details.Error, fmt.Sprintf("JSON array from script is empty. Stderr: %s", "<stderr_placeholder>"))
		return details, fmt.Errorf(details.Error)
	}

	scriptResult := scriptActionResults[0]

	details.URL = scriptResult.URL
	details.StatusCode = scriptResult.StatusCode
	details.Body = scriptResult.Body
	details.BodySHA256 = scriptResult.BodySHA256
	if scriptResult.Error != "" {
		details.Error = util.AppendError(details.Error, fmt.Sprintf("Remote script error: %s", scriptResult.Error))
	}
	details.ResponseTime = scriptResult.ResponseTimeMs
	details.BodyBase64 = scriptResult.BodyBase64

	details.Headers = scriptResult.Headers

	details.SSLCertificatePEM = scriptResult.SSLCertificatePEM
	details.SSLCertificateError = scriptResult.SSLCertificateError

	log.Printf("[SSH Provider]   Remote check processed. Script Status: %d, Script Error: %s, BodySHA: %s", scriptResult.StatusCode, scriptResult.Error, scriptResult.BodySHA256)

	if details.Error != "" {
		return details, fmt.Errorf(details.Error)
	}

	return details, nil
}

// cleanupRemoteFile attempts to delete a file on the remote server.
func (p *Provider) cleanupRemoteFile(ctx context.Context, client *ssh.Client, remotePath string) {
	log.Printf("[SSH Provider]   Attempting to clean up remote file: %s", remotePath)
	cleanupSession, err := client.NewSession()
	if err != nil {
		log.Printf("[SSH Provider]     Failed to create session for remote cleanup of %s: %v", remotePath, err)
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
			log.Printf("[SSH Provider]     Failed to delete remote file %s: %v. Stderr: %s", remotePath, err, util.TruncateString(stderr, 100))
		} else {
			log.Printf("[SSH Provider]     Successfully deleted remote file: %s", remotePath)
		}
	case <-cleanupCtx.Done():
		log.Printf("[SSH Provider]     Timeout during remote file cleanup of %s: %v", remotePath, cleanupCtx.Err())
	}
}

// TransferRunnerScript copies the http_check_runner.py script (from a hardcoded local path)
// to the remote server at the path specified by p.remotePythonRunnerPath using SCP, reusing the provider's SSH connection.
func (p *Provider) TransferRunnerScript(ctx context.Context) error {
	log.Printf("[SSH Provider] Attempting to transfer local script '%s' to %s@%s:%s", localRunnerScriptPath, p.sshUser, p.sshHost, p.remotePythonRunnerPath)

	scriptBytes, err := os.ReadFile(localRunnerScriptPath) // Use hardcoded path
	if err != nil {
		return fmt.Errorf("failed to read local runner script from '%s': %w", localRunnerScriptPath, err)
	}

	if len(scriptBytes) == 0 {
		return fmt.Errorf("local runner script '%s' is empty", localRunnerScriptPath)
	}

	sshClient, err := p.getSshClient(ctx)
	if err != nil {
		return fmt.Errorf("failed to get SSH client for SCP: %w", err)
	}

	scpClient, err := scp.NewClientBySSH(sshClient)
	if err != nil {
		p.sshClient.Close()
		p.sshClient = nil
		return fmt.Errorf("error creating SCP client from SSH session: %w. SSH client has been reset, try again", err)
	}

	scriptReader := bytes.NewReader(scriptBytes)
	scriptSize := int64(len(scriptBytes))

	copyCtx, cancel := context.WithTimeout(ctx, sshCommandTimeout)
	defer cancel()

	log.Printf("[SSH Provider] Starting SCP transfer of runner script (%d bytes) from '%s' to %s on %s using existing SSH connection", scriptSize, localRunnerScriptPath, p.remotePythonRunnerPath, p.sshHost)
	err = scpClient.Copy(copyCtx, scriptReader, p.remotePythonRunnerPath, "0755", scriptSize)
	if err != nil {
		return fmt.Errorf("error copying script via SCP to %s on %s: %w", p.remotePythonRunnerPath, p.sshHost, err)
	}

	log.Printf("[SSH Provider] Successfully transferred local script '%s' to %s@%s:%s", localRunnerScriptPath, p.sshUser, p.sshHost, p.remotePythonRunnerPath)
	return nil
}

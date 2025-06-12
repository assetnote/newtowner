package cloudflare

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"newtowner/internal/util"
	"strings"
	"time"
)

const (
	cloudflareAPIBaseURL     = "https://api.cloudflare.com/client/v4"
	defaultWorkerName        = "newtowner-worker"
	defaultWorkerScript      = "newtowner-worker"
	httpRequestTimeout       = 60 * time.Second
	maxURLsPerRequest        = 20
	workerDeploymentTimeout  = 5 * time.Minute
)

// URLCheckResult stores the result of a check for a single URL via Cloudflare Workers.
type URLCheckResult struct {
	URL             string
	Error           string
	DirectRequest   util.RequestDetails
	ProviderRequest util.RequestDetails
	Comparison      util.ComparisonResult
	PotentialBypass bool
	BypassReason    string

	ProviderWorkerDetails struct {
		WorkerURL    string // URL of the deployed worker
		WorkerName   string // Name of the worker
		Region       string // Cloudflare region (if available)
		RequestID    string // Request ID for debugging
	}
}

// Implement the required interface methods
func (r URLCheckResult) GetURL() string { return r.URL }
func (r URLCheckResult) GetError() string { return r.Error }
func (r URLCheckResult) GetDirectRequest() util.RequestDetails { return r.DirectRequest }
func (r URLCheckResult) GetProviderRequest() util.RequestDetails { return r.ProviderRequest }

// Additional methods required by ProviderResultDisplay interface
func (r URLCheckResult) GetTargetHostname() string {
	// Extract hostname from URL
	if r.URL != "" {
		if idx := strings.Index(r.URL, "://"); idx != -1 {
			urlPart := r.URL[idx+3:]
			if idx := strings.Index(urlPart, "/"); idx != -1 {
				return urlPart[:idx]
			}
			return urlPart
		}
	}
	return ""
}

func (r URLCheckResult) GetTargetResolvedIP() string {
	// Cloudflare Workers don't provide resolved IP information
	return "N/A (Cloudflare Edge)"
}

func (r URLCheckResult) GetTargetGeoCountry() string {
	// Cloudflare Workers run globally, specific location not available
	return "Global (Cloudflare)"
}

func (r URLCheckResult) GetTargetGeoRegion() string {
	// Cloudflare Workers run globally, specific region not available
	return "Cloudflare Edge Network"
}

func (r URLCheckResult) GetProcessingError() string {
	return r.Error
}

func (r URLCheckResult) GetDirectRequestDetails() util.RequestDetails {
	return r.DirectRequest
}

func (r URLCheckResult) GetDirectDisplayName() string {
	return "Direct Request Details"
}

func (r URLCheckResult) GetProviderRequestDetails() util.RequestDetails {
	return r.ProviderRequest
}

func (r URLCheckResult) GetProviderDisplayName() string {
	return "Cloudflare Worker Request"
}

func (r URLCheckResult) GetProviderSubDetails() string {
	if r.ProviderWorkerDetails.WorkerURL == "" {
		return "Worker URL: N/A (deployment or execution failed)"
	}
	details := fmt.Sprintf("Worker: %s", r.ProviderWorkerDetails.WorkerName)
	if r.ProviderWorkerDetails.Region != "" {
		details += fmt.Sprintf(", Region: %s", r.ProviderWorkerDetails.Region)
	}
	if r.ProviderWorkerDetails.RequestID != "" {
		details += fmt.Sprintf(", Request ID: %s", r.ProviderWorkerDetails.RequestID)
	}
	return details
}

func (r URLCheckResult) GetComparisonResult() util.ComparisonResult { return r.Comparison }
func (r URLCheckResult) IsPotentialBypass() bool { return r.PotentialBypass }
func (r URLCheckResult) GetBypassReason() string { return r.BypassReason }
func (r URLCheckResult) ShouldSkipBodyDiff() bool {
	return r.Error != "" || r.DirectRequest.Error != "" || r.ProviderRequest.Error != ""
}

// Provider implements the Newtowner provider interface for Cloudflare Workers.
type Provider struct {
	client      *http.Client
	AccountID   string // Cloudflare Account ID
	APIToken    string // Cloudflare API Token
	WorkerURL   string // Optional: Custom worker URL (if already deployed)
	WorkerName  string // Name of the worker to deploy/use
}

// NewProvider creates and initializes a new Cloudflare Provider.
func NewProvider(ctx context.Context, accountID, apiToken, workerURL string) (*Provider, error) {
	if accountID == "" {
		return nil, fmt.Errorf("Cloudflare Account ID is required")
	}
	if apiToken == "" {
		return nil, fmt.Errorf("Cloudflare API Token is required")
	}

	client := &http.Client{
		Timeout: httpRequestTimeout,
	}

	workerName := defaultWorkerName
	if workerURL == "" {
		log.Printf("No custom worker URL provided, will deploy worker: %s", workerName)
	} else {
		log.Printf("Using custom worker URL: %s", workerURL)
	}

	provider := &Provider{
		client:     client,
		AccountID:  accountID,
		APIToken:   apiToken,
		WorkerURL:  workerURL,
		WorkerName: workerName,
	}

	// Verify API token
	if err := provider.verifyAPIToken(ctx); err != nil {
		return nil, fmt.Errorf("failed to verify Cloudflare API token: %w", err)
	}

	// If no custom worker URL is provided, deploy the worker
	if workerURL == "" {
		deployedURL, err := provider.deployWorker(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to deploy Cloudflare Worker: %w", err)
		}
		provider.WorkerURL = deployedURL
		log.Printf("Successfully deployed Cloudflare Worker at: %s", deployedURL)
	}

	log.Printf("Cloudflare Provider initialized successfully. Worker URL: %s", provider.WorkerURL)
	return provider, nil
}

// verifyAPIToken verifies that the API token is valid and has the necessary permissions.
func (p *Provider) verifyAPIToken(ctx context.Context) error {
	url := fmt.Sprintf("%s/accounts/%s/tokens/verify", cloudflareAPIBaseURL, p.AccountID)
	
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return fmt.Errorf("failed to create token verification request: %w", err)
	}
	
	req.Header.Set("Authorization", "Bearer "+p.APIToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := p.client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to verify token: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("token verification failed with status %d: %s", resp.StatusCode, string(body))
	}

	var result struct {
		Success bool `json:"success"`
		Result  struct {
			Status string `json:"status"`
		} `json:"result"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return fmt.Errorf("failed to decode token verification response: %w", err)
	}

	if !result.Success || result.Result.Status != "active" {
		return fmt.Errorf("API token is not active or valid")
	}

	log.Printf("Cloudflare API token verified successfully")
	return nil
}

// deployWorker deploys the Cloudflare Worker script and returns the worker URL.
func (p *Provider) deployWorker(ctx context.Context) (string, error) {
	// Read the worker script from the embedded file or local file
	workerScript, err := p.getWorkerScript()
	if err != nil {
		return "", fmt.Errorf("failed to get worker script: %w", err)
	}

	// Deploy the worker
	url := fmt.Sprintf("%s/accounts/%s/workers/scripts/%s", cloudflareAPIBaseURL, p.AccountID, p.WorkerName)
	
	req, err := http.NewRequestWithContext(ctx, "PUT", url, strings.NewReader(workerScript))
	if err != nil {
		return "", fmt.Errorf("failed to create worker deployment request: %w", err)
	}
	
	req.Header.Set("Authorization", "Bearer "+p.APIToken)
	req.Header.Set("Content-Type", "application/javascript")

	resp, err := p.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to deploy worker: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("worker deployment failed with status %d: %s", resp.StatusCode, string(body))
	}

	var result struct {
		Success bool `json:"success"`
	}

	if err := json.Unmarshal(body, &result); err != nil {
		return "", fmt.Errorf("failed to decode worker deployment response: %w", err)
	}

	if !result.Success {
		return "", fmt.Errorf("worker deployment was not successful: %s", string(body))
	}

	// Construct the worker URL
	workerURL := fmt.Sprintf("https://%s.%s.workers.dev", p.WorkerName, p.AccountID)
	
	log.Printf("Worker deployed successfully: %s", workerURL)
	return workerURL, nil
}

// getWorkerScript returns the JavaScript code for the Cloudflare Worker.
// In a production environment, this could be embedded or read from a file.
func (p *Provider) getWorkerScript() (string, error) {
	// For now, we'll return a simple inline script
	// In production, this should read from .cloudflare/newtowner_worker.js
	script := `
/**
 * Newtowner Cloudflare Worker
 * Performs HTTP checks from Cloudflare's edge network
 */

// Helper function to calculate SHA256 hash
async function sha256(data) {
  const encoder = new TextEncoder();
  const dataBuffer = encoder.encode(data);
  const hashBuffer = await crypto.subtle.digest('SHA-256', dataBuffer);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}

// Helper function to encode binary data to base64
function arrayBufferToBase64(buffer) {
  const bytes = new Uint8Array(buffer);
  let binary = '';
  for (let i = 0; i < bytes.byteLength; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
}

// Main function to make HTTP request and return details
async function makeRequest(targetUrl) {
  const details = {
    url: targetUrl,
    status_code: null,
    headers: {},
    body_sha256: null,
    response_time_ms: null,
    error: null,
    body: null,
    body_base64: null,
    ssl_certificate_pem: null,
    ssl_certificate_error: null,
  };

  const startTime = Date.now();

  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 30000);

    const response = await fetch(targetUrl, {
      method: 'GET',
      redirect: 'follow',
      signal: controller.signal,
    });

    clearTimeout(timeoutId);
    details.status_code = response.status;

    const parsedHeaders = {};
    for (const [key, value] of response.headers.entries()) {
      parsedHeaders[key] = [value];
    }
    details.headers = parsedHeaders;

    const responseArrayBuffer = await response.arrayBuffer();
    const responseText = new TextDecoder('utf-8', { fatal: false }).decode(responseArrayBuffer);
    
    details.body_sha256 = await sha256(responseText);

    if (responseArrayBuffer.byteLength > 0) {
      try {
        details.body = responseText;
        if (responseText.includes('\uFFFD')) {
          details.body_base64 = arrayBufferToBase64(responseArrayBuffer);
        }
      } catch (e) {
        details.body = "Error decoding body as UTF-8";
        details.body_base64 = arrayBufferToBase64(responseArrayBuffer);
      }
    } else {
      details.body = "";
    }

    details.ssl_certificate_error = "SSL certificate details not available in Cloudflare Workers runtime";

  } catch (error) {
    if (error.name === 'AbortError') {
      details.error = "Request timed out after 30 seconds";
    } else {
      details.error = "Request failed: " + error.message;
    }
  } finally {
    const endTime = Date.now();
    details.response_time_ms = endTime - startTime;
  }

  return details;
}

const corsHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, Authorization',
};

export default {
  async fetch(request, env, ctx) {
    if (request.method === 'OPTIONS') {
      return new Response(null, { status: 200, headers: corsHeaders });
    }

    if (request.method !== 'GET' && request.method !== 'POST') {
      return new Response('Method not allowed', { status: 405, headers: corsHeaders });
    }

    try {
      let targetUrls = [];

      if (request.method === 'GET') {
        const url = new URL(request.url);
        const urlParam = url.searchParams.get('urls');
        if (!urlParam) {
          return new Response(JSON.stringify({ error: 'Missing urls parameter' }), {
            status: 400, headers: { ...corsHeaders, 'Content-Type': 'application/json' }
          });
        }
        targetUrls = urlParam.split(',').map(u => u.trim()).filter(u => u);
      } else if (request.method === 'POST') {
        const body = await request.json();
        if (!body.urls) {
          return new Response(JSON.stringify({ error: 'Missing urls in request body' }), {
            status: 400, headers: { ...corsHeaders, 'Content-Type': 'application/json' }
          });
        }
        if (Array.isArray(body.urls)) {
          targetUrls = body.urls;
        } else if (typeof body.urls === 'string') {
          targetUrls = body.urls.split(',').map(u => u.trim()).filter(u => u);
        }
      }

      if (targetUrls.length === 0) {
        return new Response(JSON.stringify([]), {
          status: 200, headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
      }

      if (targetUrls.length > 20) {
        return new Response(JSON.stringify({ error: 'Too many URLs. Maximum 20 URLs per request.' }), {
          status: 400, headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
      }

      const results = [];
      for (const url of targetUrls) {
        const result = await makeRequest(url);
        results.push(result);
      }

      return new Response(JSON.stringify(results), {
        status: 200, headers: { ...corsHeaders, 'Content-Type': 'application/json' }
      });

    } catch (error) {
      return new Response(JSON.stringify({ error: "Worker error: " + error.message }), {
        status: 500, headers: { ...corsHeaders, 'Content-Type': 'application/json' }
      });
    }
  },
};`

	return script, nil
}

// CheckURLs performs HTTP checks for the provided URLs using the Cloudflare Worker.
func (p *Provider) CheckURLs(urls []string) ([]URLCheckResult, error) {
	if len(urls) == 0 {
		return []URLCheckResult{}, nil
	}

	log.Printf("Cloudflare Provider: Checking %d URLs using worker at %s", len(urls), p.WorkerURL)

	var allResults []URLCheckResult

	// Process URLs in batches to respect worker limits
	for i := 0; i < len(urls); i += maxURLsPerRequest {
		end := i + maxURLsPerRequest
		if end > len(urls) {
			end = len(urls)
		}
		batchURLs := urls[i:end]

		log.Printf("Processing batch %d/%d with %d URLs", (i/maxURLsPerRequest)+1,
			(len(urls)+maxURLsPerRequest-1)/maxURLsPerRequest, len(batchURLs))

		batchResults, err := p.processBatch(batchURLs)
		if err != nil {
			log.Printf("Error processing batch: %v", err)
			// Create error results for this batch
			for _, url := range batchURLs {
				result := URLCheckResult{
					URL:   url,
					Error: fmt.Sprintf("Batch processing error: %v", err),
				}
				allResults = append(allResults, result)
			}
			continue
		}

		allResults = append(allResults, batchResults...)
	}

	log.Printf("Cloudflare Provider: Completed processing %d URLs, generated %d results",
		len(urls), len(allResults))

	return allResults, nil
}

// processBatch processes a batch of URLs through the Cloudflare Worker.
func (p *Provider) processBatch(urls []string) ([]URLCheckResult, error) {
	ctx, cancel := context.WithTimeout(context.Background(), httpRequestTimeout)
	defer cancel()

	var results []URLCheckResult

	// First, make direct requests for comparison
	directResults := make(map[string]util.RequestDetails)
	for _, url := range urls {
		log.Printf("Making direct request to: %s", url)
		directResult := util.MakeHTTPRequest(ctx, "GET", url, false)
		if directResult.Error != "" {
			log.Printf("Direct request failed for %s: %s", url, directResult.Error)
		}
		directResults[url] = directResult
	}

	// Make request to Cloudflare Worker
	workerResults, err := p.makeWorkerRequest(ctx, urls)
	if err != nil {
		return nil, fmt.Errorf("worker request failed: %w", err)
	}

	// Combine results and perform comparisons
	for _, url := range urls {
		directResult := directResults[url]

		// Find corresponding worker result
		var workerResult util.RequestDetails
		found := false
		for _, wr := range workerResults {
			if wr.URL == url {
				workerResult = wr
				found = true
				break
			}
		}

		if !found {
			workerResult = util.RequestDetails{
				URL:   url,
				Error: "No result returned from worker for this URL",
			}
		}

		// Create URLCheckResult
		result := URLCheckResult{
			URL:             url,
			DirectRequest:   directResult,
			ProviderRequest: workerResult,
			ProviderWorkerDetails: struct {
				WorkerURL    string
				WorkerName   string
				Region       string
				RequestID    string
			}{
				WorkerURL:  p.WorkerURL,
				WorkerName: p.WorkerName,
				Region:     "Cloudflare Edge", // Cloudflare doesn't expose specific edge location
			},
		}

		// Set overall error if either request failed
		if directResult.Error != "" && workerResult.Error != "" {
			result.Error = fmt.Sprintf("Both requests failed - Direct: %s, Worker: %s",
				directResult.Error, workerResult.Error)
		} else if directResult.Error != "" {
			result.Error = fmt.Sprintf("Direct request failed: %s", directResult.Error)
		} else if workerResult.Error != "" {
			result.Error = fmt.Sprintf("Worker request failed: %s", workerResult.Error)
		}

		// Perform comparison if both requests succeeded
		if result.Error == "" {
			comparison, bypass, reason := util.CompareHTTPResponses(directResult, workerResult)
			result.Comparison = comparison
			result.PotentialBypass = bypass
			result.BypassReason = reason
		}

		results = append(results, result)
	}

	return results, nil
}

// makeWorkerRequest sends a request to the Cloudflare Worker with the specified URLs.
func (p *Provider) makeWorkerRequest(ctx context.Context, urls []string) ([]util.RequestDetails, error) {
	// Prepare request body
	requestBody := map[string]interface{}{
		"urls": urls,
	}

	jsonBody, err := json.Marshal(requestBody)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request body: %w", err)
	}

	// Create HTTP request
	req, err := http.NewRequestWithContext(ctx, "POST", p.WorkerURL, bytes.NewReader(jsonBody))
	if err != nil {
		return nil, fmt.Errorf("failed to create worker request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "Newtowner/1.0")

	// Make the request
	resp, err := p.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("worker request failed: %w", err)
	}
	defer resp.Body.Close()

	// Read response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read worker response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("worker returned status %d: %s", resp.StatusCode, string(body))
	}

	// Parse response
	var results []util.RequestDetails
	if err := json.Unmarshal(body, &results); err != nil {
		return nil, fmt.Errorf("failed to parse worker response: %w", err)
	}

	log.Printf("Worker returned %d results for %d URLs", len(results), len(urls))
	return results, nil
}

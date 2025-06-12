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
    // Make the HTTP request with timeout
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 30000); // 30 second timeout

    const response = await fetch(targetUrl, {
      method: 'GET',
      redirect: 'follow',
      signal: controller.signal,
      // Note: Cloudflare Workers don't support disabling SSL verification
      // This is actually a security feature
    });

    clearTimeout(timeoutId);

    details.status_code = response.status;

    // Convert headers to the expected format (map[string][]string)
    const parsedHeaders = {};
    for (const [key, value] of response.headers.entries()) {
      parsedHeaders[key] = [value];
    }
    details.headers = parsedHeaders;

    // Get response body
    const responseArrayBuffer = await response.arrayBuffer();
    const responseText = new TextDecoder('utf-8', { fatal: false }).decode(responseArrayBuffer);
    
    // Calculate SHA256 of the body
    details.body_sha256 = await sha256(responseText);

    // Handle body encoding
    if (responseArrayBuffer.byteLength > 0) {
      try {
        details.body = responseText;
        // If the text contains replacement characters, also provide base64
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

    // SSL certificate handling
    // Note: Cloudflare Workers don't provide direct access to SSL certificates
    // This is a limitation of the Workers runtime environment
    details.ssl_certificate_error = "SSL certificate details not available in Cloudflare Workers runtime";

  } catch (error) {
    if (error.name === 'AbortError') {
      details.error = "Request timed out after 30 seconds";
    } else if (error.message.includes('fetch')) {
      details.error = `Fetch error: ${error.message}`;
    } else {
      details.error = `Request failed: ${error.message}`;
    }
  } finally {
    const endTime = Date.now();
    details.response_time_ms = endTime - startTime;
  }

  return details;
}

// CORS headers for responses
const corsHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, Authorization',
};

export default {
  async fetch(request, env, ctx) {
    // Handle CORS preflight requests
    if (request.method === 'OPTIONS') {
      return new Response(null, {
        status: 200,
        headers: corsHeaders,
      });
    }

    // Only allow GET and POST methods
    if (request.method !== 'GET' && request.method !== 'POST') {
      return new Response('Method not allowed', {
        status: 405,
        headers: corsHeaders,
      });
    }

    try {
      let targetUrls = [];

      if (request.method === 'GET') {
        // Extract URLs from query parameters
        const url = new URL(request.url);
        const urlParam = url.searchParams.get('urls');
        if (!urlParam) {
          return new Response(JSON.stringify({ error: 'Missing urls parameter' }), {
            status: 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' },
          });
        }
        targetUrls = urlParam.split(',').map(u => u.trim()).filter(u => u);
      } else if (request.method === 'POST') {
        // Extract URLs from JSON body
        const body = await request.json();
        if (!body.urls) {
          return new Response(JSON.stringify({ error: 'Missing urls in request body' }), {
            status: 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' },
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
          status: 200,
          headers: { ...corsHeaders, 'Content-Type': 'application/json' },
        });
      }

      // Limit the number of URLs to prevent abuse
      if (targetUrls.length > 20) {
        return new Response(JSON.stringify({ error: 'Too many URLs. Maximum 20 URLs per request.' }), {
          status: 400,
          headers: { ...corsHeaders, 'Content-Type': 'application/json' },
        });
      }

      // Process all URLs
      const results = [];
      for (const url of targetUrls) {
        console.log(`Processing URL: ${url}`);
        const result = await makeRequest(url);
        results.push(result);
      }

      return new Response(JSON.stringify(results), {
        status: 200,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
      });

    } catch (error) {
      console.error('Worker error:', error);
      return new Response(JSON.stringify({ error: `Worker error: ${error.message}` }), {
        status: 500,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
      });
    }
  },
};

from http.server import HTTPServer, BaseHTTPRequestHandler
import json
import os
import time
from datetime import datetime
from collections import defaultdict
import urllib.request
import urllib.error
import urllib.parse
import base64
import hmac
import hashlib

# Config from environment
SECRET_TOKEN = os.environ.get('WEBHOOK_SECRET')
WOOCOMMERCE_SECRET = os.environ.get('WOOCOMMERCE_WEBHOOK_SECRET', '')  # WooCommerce webhook secret
WEBHOOK_MODE = os.environ.get('WEBHOOK_MODE', 'custom').lower()  # 'custom' or 'woocommerce'
NGROK_URL = os.environ.get('NGROK_URL', '')  # Manually set ngrok URL (fallback)
ALLOWED_IPS = os.environ.get('ALLOWED_IPS', '').split(',')  # comma-separated, empty = allow all
RATE_LIMIT = int(os.environ.get('RATE_LIMIT', 10))  # requests per minute
MAX_PAYLOAD_SIZE = int(os.environ.get('MAX_PAYLOAD_SIZE', 1_000_000))  # 1MB default
PORT = int(os.environ.get('PORT', 5001))

# Jenkins config from environment
JENKINS_URL = os.environ.get('JENKINS_URL', '').rstrip('/')
JENKINS_USER = os.environ.get('JENKINS_USER', '')
JENKINS_API_TOKEN = os.environ.get('JENKINS_API_TOKEN', '')
JENKINS_JOB_NAME = os.environ.get('JENKINS_JOB_NAME', '')

# Validate required configuration based on webhook mode
if WEBHOOK_MODE == 'woocommerce':
    if not WOOCOMMERCE_SECRET:
        raise ValueError("WOOCOMMERCE_WEBHOOK_SECRET environment variable is required when WEBHOOK_MODE=woocommerce")
elif not SECRET_TOKEN:
    raise ValueError("WEBHOOK_SECRET environment variable is required when WEBHOOK_MODE=custom")

rate_tracker = defaultdict(list)

def get_ngrok_url():
    """
    Fetch ngrok public URL from ngrok API or environment variable.
    Returns the HTTPS URL if available, otherwise HTTP URL.
    Tries multiple endpoints to work both on host and in Docker.
    """
    # First, check if manually set via environment variable
    if NGROK_URL:
        return NGROK_URL
    
    # Try multiple endpoints:
    # 1. host.docker.internal (works on Docker Desktop for Mac/Windows/Linux)
    # 2. 172.17.0.1 (default Docker bridge gateway on Linux)
    # 3. localhost (works if running directly on host, not in Docker)
    endpoints = [
        'http://host.docker.internal:4040/api/tunnels',  # Docker Desktop (Mac/Windows/Linux)
        'http://172.17.0.1:4040/api/tunnels',              # Docker bridge gateway (Linux)
        'http://localhost:4040/api/tunnels',                # Direct host access
    ]
    
    for endpoint in endpoints:
        try:
            req = urllib.request.Request(endpoint)
            with urllib.request.urlopen(req, timeout=2) as response:
                data = json.loads(response.read().decode())
                tunnels = data.get('tunnels', [])
                # Prefer HTTPS tunnel
                for tunnel in tunnels:
                    if tunnel.get('proto') == 'https':
                        return tunnel.get('public_url', '')
                # Fallback to HTTP if HTTPS not available
                for tunnel in tunnels:
                    if tunnel.get('proto') == 'http':
                        return tunnel.get('public_url', '')
        except urllib.error.HTTPError as e:
            # 401/403 might mean ngrok is accessible but requires auth - try next endpoint
            if e.code in [401, 403]:
                continue
            # Other HTTP errors - try next endpoint
            continue
        except (urllib.error.URLError, ConnectionRefusedError):
            # Connection refused - try next endpoint
            continue
        except Exception:
            # Any other error - try next endpoint
            continue
    return None

def verify_woocommerce_signature(payload, signature, secret):
    """
    Verify WooCommerce webhook signature using HMAC SHA256.
    
    Args:
        payload: Raw request body (bytes)
        signature: Signature from X-WC-Webhook-Signature header
        secret: WooCommerce webhook secret
    
    Returns:
        bool: True if signature is valid
    """
    if not secret or not signature:
        return False
    
    # Calculate expected signature
    expected_signature = hmac.new(
        secret.encode('utf-8'),
        payload,
        hashlib.sha256
    ).hexdigest()
    
    # Use constant-time comparison to prevent timing attacks
    return hmac.compare_digest(expected_signature, signature)

def get_jenkins_crumb(jenkins_url, auth_header):
    """
    Get Jenkins CSRF protection crumb token.
    
    Args:
        jenkins_url: Base URL of Jenkins server
        auth_header: Basic auth header value
    
    Returns:
        tuple: (crumb_name, crumb_value) or (None, None) if not required
    """
    try:
        crumb_url = f"{jenkins_url}/crumbIssuer/api/xml?xpath=concat(//crumbRequestField,\":\",//crumb)"
        req = urllib.request.Request(crumb_url)
        req.add_header('Authorization', f'Basic {auth_header}')
        
        with urllib.request.urlopen(req, timeout=10) as response:
            crumb_data = response.read().decode().strip()
            if ':' in crumb_data:
                crumb_name, crumb_value = crumb_data.split(':', 1)
                return crumb_name, crumb_value
    except (urllib.error.HTTPError, urllib.error.URLError):
        # CSRF protection might not be enabled, or endpoint doesn't exist
        pass
    except Exception:
        pass
    return None, None

def trigger_jenkins_job(job_name, jenkins_url, username, api_token, params=None):
    """
    Trigger a Jenkins job via API.
    
    Args:
        job_name: Name of the Jenkins job
        jenkins_url: Base URL of Jenkins server
        username: Jenkins username
        api_token: Jenkins API token
        params: Optional dict of parameters to pass to the job
    
    Returns:
        tuple: (success: bool, message: str, build_number: int or None)
    """
    if not all([jenkins_url, username, api_token, job_name]):
        return False, "Jenkins configuration incomplete", None
    
    # Create basic auth header
    credentials = f"{username}:{api_token}".encode()
    auth_header = base64.b64encode(credentials).decode()
    
    # Get CSRF crumb if required
    crumb_name, crumb_value = get_jenkins_crumb(jenkins_url, auth_header)
    
    # Helper function to make the request
    def make_request(url, use_params=False):
        # Jenkins requires POST method for triggering builds
        if use_params and params:
            data = urllib.parse.urlencode(params).encode()
            req = urllib.request.Request(url, data=data, method='POST')
            req.add_header('Content-Type', 'application/x-www-form-urlencoded')
        else:
            # For non-parameterized builds, use POST with empty body
            req = urllib.request.Request(url, method='POST')
        
        req.add_header('Authorization', f'Basic {auth_header}')
        
        # Add CSRF crumb if available
        if crumb_name and crumb_value:
            req.add_header(crumb_name, crumb_value)
        
        with urllib.request.urlopen(req, timeout=30) as response:
            status_code = response.getcode()
            
            # Jenkins returns 201 for successful trigger, or 200 in some cases
            if status_code in [200, 201]:
                # Try to get build number from Location header
                location = response.headers.get('Location', '')
                build_number = None
                if location:
                    # Extract build number from location like: /job/name/123/
                    parts = location.rstrip('/').split('/')
                    if parts:
                        try:
                            build_number = int(parts[-1])
                        except ValueError:
                            pass
                
                return True, f"Jenkins job triggered successfully (HTTP {status_code})", build_number
            else:
                return False, f"Unexpected response code: {status_code}", None
    
    # Try parameterized build first if params are provided
    if params:
        try:
            url = f"{jenkins_url}/job/{job_name}/buildWithParameters"
            return make_request(url, use_params=True)
        except urllib.error.HTTPError as e:
            error_body = e.read().decode() if e.fp else "No error details"
            # If job is not parameterized (400 error), try regular build
            if e.code == 400 and "not parameterized" in error_body.lower():
                print(f"Job is not parameterized, trying regular build endpoint...")
                try:
                    url = f"{jenkins_url}/job/{job_name}/build"
                    return make_request(url, use_params=False)
                except urllib.error.HTTPError as retry_e:
                    retry_error = retry_e.read().decode() if retry_e.fp else "No error details"
                    return False, f"HTTP error {retry_e.code}: {retry_error[:200]}", None
                except urllib.error.URLError as retry_e:
                    return False, f"URL error: {str(retry_e)}", None
                except Exception as retry_e:
                    return False, f"Unexpected error: {str(retry_e)}", None
            else:
                return False, f"HTTP error {e.code}: {error_body[:200]}", None
        except urllib.error.URLError as e:
            return False, f"URL error: {str(e)}", None
        except Exception as e:
            return False, f"Unexpected error: {str(e)}", None
    else:
        # No parameters, use regular build endpoint
        try:
            url = f"{jenkins_url}/job/{job_name}/build"
            return make_request(url, use_params=False)
        except urllib.error.HTTPError as e:
            error_body = e.read().decode() if e.fp else "No error details"
            return False, f"HTTP error {e.code}: {error_body[:200]}", None
        except urllib.error.URLError as e:
            return False, f"URL error: {str(e)}", None
        except Exception as e:
            return False, f"Unexpected error: {str(e)}", None

class WebhookHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        client_ip = self.client_address[0]
        
        # IP allowlist check
        if ALLOWED_IPS[0] and client_ip not in ALLOWED_IPS:
            self.send_error_response(403, 'Forbidden')
            print(f"[{datetime.now()}] Blocked IP: {client_ip}")
            return
        
        # Rate limiting
        now = time.time()
        rate_tracker[client_ip] = [t for t in rate_tracker[client_ip] if now - t < 60]
        if len(rate_tracker[client_ip]) >= RATE_LIMIT:
            self.send_error_response(429, 'Too many requests')
            print(f"[{datetime.now()}] Rate limited: {client_ip}")
            return
        rate_tracker[client_ip].append(now)
        
        # Payload size check (before reading)
        content_length = int(self.headers.get('Content-Length', 0))
        if content_length > MAX_PAYLOAD_SIZE:
            self.send_error_response(413, 'Payload too large')
            return
        
        if content_length == 0:
            self.send_error_response(400, 'Empty payload')
            return
        
        # Read raw payload for signature verification
        raw_data = self.rfile.read(content_length)
        
        # Auth check - different for WooCommerce vs custom webhooks
        if WEBHOOK_MODE == 'woocommerce':
            # WooCommerce signature verification
            if not WOOCOMMERCE_SECRET:
                self.send_error_response(500, 'WooCommerce secret not configured')
                print(f"[{datetime.now()}] WooCommerce secret not configured")
                return
            
            signature = self.headers.get('X-WC-Webhook-Signature', '')
            if not verify_woocommerce_signature(raw_data, signature, WOOCOMMERCE_SECRET):
                self.send_error_response(401, 'Invalid WooCommerce signature')
                print(f"[{datetime.now()}] Invalid WooCommerce signature from: {client_ip}")
                return
        else:
            # Custom webhook token check
            token = self.headers.get('X-Webhook-Secret')
            if not token or token != SECRET_TOKEN:
                self.send_error_response(401, 'Unauthorized')
                print(f"[{datetime.now()}] Invalid token from: {client_ip}")
                return
        
        # Parse JSON
        try:
            data = json.loads(raw_data.decode('utf-8'))
        except json.JSONDecodeError:
            self.send_error_response(400, 'Invalid JSON')
            return
        
        # Validate expected fields based on webhook mode
        if WEBHOOK_MODE == 'woocommerce':
            # WooCommerce webhook - validate it's an order or event
            if not isinstance(data, dict):
                self.send_error_response(400, 'Invalid WooCommerce webhook format')
                return
            # WooCommerce webhooks can have various structures, so we're lenient
        else:
            # Custom webhook - validate required fields
            required_fields = ['to', 'subject', 'message']
            if not all(field in data for field in required_fields):
                self.send_error_response(400, 'Missing required fields')
                return
        
        # Log the webhook
        print(f"\n{'='*50}")
        print(f"Webhook received at {datetime.now()}")
        print(f"Mode: {WEBHOOK_MODE}")
        print(f"From IP: {client_ip}")
        print(f"{'='*50}")
        
        if WEBHOOK_MODE == 'woocommerce':
            # Log WooCommerce webhook details
            webhook_source = self.headers.get('X-WC-Webhook-Source', 'Unknown')
            webhook_event = self.headers.get('X-WC-Webhook-Event', 'Unknown')
            print(f"WooCommerce Source: {webhook_source}")
            print(f"WooCommerce Event: {webhook_event}")
            if 'id' in data:
                print(f"Order/Resource ID: {data.get('id')}")
            if 'status' in data:
                print(f"Status: {data.get('status')}")
            print(f"Payload keys: {list(data.keys())[:10]}...")  # Show first 10 keys
        else:
            # Log custom webhook details (email details removed for privacy)
            pass
        
        print(f"{'='*50}\n")
        
        # Trigger Jenkins job if configured
        jenkins_status = None
        if JENKINS_URL and JENKINS_USER and JENKINS_API_TOKEN and JENKINS_JOB_NAME:
            print(f"Triggering Jenkins job: {JENKINS_JOB_NAME}")
            
            # Prepare parameters to pass to Jenkins job (optional)
            # You can customize this to pass webhook data to Jenkins
            if WEBHOOK_MODE == 'woocommerce':
                # WooCommerce webhook parameters
                jenkins_params = {
                    'WEBHOOK_MODE': 'woocommerce',
                    'WEBHOOK_EVENT': self.headers.get('X-WC-Webhook-Event', 'unknown'),
                    'ORDER_ID': str(data.get('id', '')),
                    'ORDER_STATUS': data.get('status', ''),
                    'WEBHOOK_TIMESTAMP': datetime.now().isoformat(),
                }
            else:
                # Custom webhook parameters
                jenkins_params = {
                    'WEBHOOK_MODE': 'custom',
                    'WEBHOOK_TO': data.get('to', ''),
                    'WEBHOOK_SUBJECT': data.get('subject', ''),
                    'WEBHOOK_MESSAGE': data.get('message', ''),
                    'WEBHOOK_TIMESTAMP': datetime.now().isoformat(),
                }
            
            success, message, build_number = trigger_jenkins_job(
                JENKINS_JOB_NAME,
                JENKINS_URL,
                JENKINS_USER,
                JENKINS_API_TOKEN,
                params=jenkins_params
            )
            
            jenkins_status = {
                'triggered': success,
                'message': message,
                'build_number': build_number
            }
            
            if success:
                print(f"✅ Jenkins job triggered successfully")
                if build_number:
                    print(f"   Build number: {build_number}")
            else:
                print(f"❌ Failed to trigger Jenkins job: {message}")
        else:
            print("⚠️  Jenkins not configured, skipping job trigger")
        
        # Success response
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
        
        response_data = {'status': 'received'}
        if jenkins_status:
            response_data['jenkins'] = jenkins_status
        
        self.wfile.write(json.dumps(response_data).encode())
    
    def send_error_response(self, code, message):
        self.send_response(code)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
        self.wfile.write(json.dumps({'error': message}).encode())
    
    def log_message(self, format, *args):
        pass  # Suppress default logging

if __name__ == '__main__':
    print(f"Starting webhook server on port {PORT}")
    print(f"Webhook mode: {WEBHOOK_MODE}")
    print(f"Rate limit: {RATE_LIMIT} requests/minute")
    print(f"Max payload: {MAX_PAYLOAD_SIZE} bytes")
    print(f"IP allowlist: {'All IPs allowed' if not ALLOWED_IPS[0] else ALLOWED_IPS}")
    print(f"\n{'='*60}")
    print(f"📍 WEBHOOK URLS")
    print(f"{'='*60}")
    
    # Local URL
    print(f"🔵 Local URL: http://localhost:{PORT}")
    
    # Try to get ngrok URL
    ngrok_url = get_ngrok_url()
    if ngrok_url:
        print(f"🟢 Testing URL (ngrok): {ngrok_url}")
        print(f"   ✅ Use this URL for WooCommerce webhook testing")
    else:
        print(f"🟡 Testing URL (ngrok): Not available")
        print(f"   💡 To enable: Run 'ngrok http {PORT}' in another terminal")
        print(f"   💡 Or uncomment ngrok service in docker-compose.yml")
    
    # Production URL
    print(f"🔴 Production URL: https://<your-domain.com>:{PORT}")
    print(f"   💡 Deploy to a server with public domain for production")
    print(f"   💡 Use HTTPS in production (required for WooCommerce)")
    
    if WEBHOOK_MODE == 'woocommerce':
        print(f"\n⚠️  WOOCOMMERCE REQUIRES PUBLIC URL!")
        if ngrok_url:
            print(f"   ✅ Use ngrok URL for testing: {ngrok_url}")
        else:
            print(f"   ❌ No public URL available - WooCommerce cannot reach localhost")
            print(f"   📝 Steps:")
            print(f"      1. Run: ngrok http {PORT}")
            print(f"      2. Copy the ngrok URL")
            print(f"      3. Use it in WooCommerce webhook settings")
    
    print(f"{'='*60}\n")
    
    # Jenkins configuration status
    if JENKINS_URL and JENKINS_USER and JENKINS_API_TOKEN and JENKINS_JOB_NAME:
        print(f"Jenkins integration: ✅ Enabled")
        print(f"  Jenkins URL: {JENKINS_URL}")
        print(f"  Job name: {JENKINS_JOB_NAME}")
        print(f"  User: {JENKINS_USER}")
    else:
        print(f"Jenkins integration: ⚠️  Disabled (set JENKINS_URL, JENKINS_USER, JENKINS_API_TOKEN, JENKINS_JOB_NAME)")
    
    server = HTTPServer(('0.0.0.0', PORT), WebhookHandler)
    server.serve_forever()

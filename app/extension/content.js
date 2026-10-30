chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === "BLOCK_PAGE") {
    injectBlockOverlay(request.data);
  } else if (request.action === "EXTRACT_DOM_SIGNALS") {
    sendResponse(extractDomSignals());
  }
});

function extractDomSignals() {
  let hiddenIframes = 0;
  document.querySelectorAll('iframe').forEach(iframe => {
    const style = window.getComputedStyle(iframe);
    if (style.display === 'none' || style.visibility === 'hidden' || style.opacity === '0' || iframe.width === '0' || iframe.height === '0') {
      hiddenIframes++;
    }
  });

  const passwordInputs = document.querySelectorAll('input[type="password"]').length;
  
  // Right-click check
  let rightClickDisabled = false;
  if (document.body && document.body.oncontextmenu !== null) {
    rightClickDisabled = true;
  }
  
  return {
    hidden_iframes: hiddenIframes,
    password_inputs: passwordInputs,
    right_click_disabled: rightClickDisabled
  };
}

function injectBlockOverlay(data) {
  // Prevent multiple injections
  if (document.getElementById('phishguard-block-overlay')) return;

  const overlay = document.createElement('div');
  overlay.id = 'phishguard-block-overlay';
  
  // Style the overlay to cover the whole page and block interaction
  overlay.style.position = 'fixed';
  overlay.style.top = '0';
  overlay.style.left = '0';
  overlay.style.width = '100vw';
  overlay.style.height = '100vh';
  overlay.style.backgroundColor = 'rgba(2, 6, 23, 0.95)'; // slate-950 with opacity
  overlay.style.backdropFilter = 'blur(10px)';
  overlay.style.zIndex = '2147483647'; // Max z-index
  overlay.style.display = 'flex';
  overlay.style.flexDirection = 'column';
  overlay.style.alignItems = 'center';
  overlay.style.justifyContent = 'center';
  overlay.style.fontFamily = 'system-ui, -apple-system, sans-serif';
  overlay.style.color = '#f8fafc';
  
  // Create content
  overlay.innerHTML = `
    <div style="background: rgba(15, 23, 42, 0.8); border: 2px solid #ef4444; border-radius: 12px; padding: 40px; max-width: 600px; text-align: center; box-shadow: 0 0 50px rgba(239, 68, 68, 0.2);">
      <svg xmlns="http://www.w3.org/2000/svg" width="80" height="80" viewBox="0 0 24 24" fill="none" stroke="#ef4444" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="margin: 0 auto 20px;"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path><line x1="12" y1="8" x2="12" y2="12"></line><line x1="12" y1="16" x2="12.01" y2="16"></line></svg>
      <h1 style="color: #ef4444; font-size: 32px; font-weight: 900; margin: 0 0 10px; text-transform: uppercase;">Phishing Detected</h1>
      <h2 style="color: #f8fafc; font-size: 18px; margin: 0 0 20px;">Access to this webpage has been blocked by PhishGuard-X.</h2>
      
      <div style="background: rgba(0,0,0,0.3); border-radius: 8px; padding: 15px; margin-bottom: 20px; display: flex; justify-content: space-around;">
        <div style="text-align: center;">
          <div style="font-size: 12px; color: #94a3b8; text-transform: uppercase; letter-spacing: 1px;">Risk Score</div>
          <div style="font-size: 24px; font-weight: bold; color: #ef4444; font-family: monospace;">${data.risk_profile.score}/100</div>
        </div>
        <div style="text-align: center;">
          <div style="font-size: 12px; color: #94a3b8; text-transform: uppercase; letter-spacing: 1px;">Severity</div>
          <div style="font-size: 24px; font-weight: bold; color: #ef4444;">${data.risk_profile.tier}</div>
        </div>
      </div>

      <p style="color: #94a3b8; font-size: 14px; line-height: 1.5; margin: 0 0 30px;">
        This website was flagged by our Quad-Modal AI Engine for credential harvesting behaviors and structural anomalies. Continuing to this site puts your sensitive information at risk.
      </p>

      <div style="display: flex; gap: 15px; justify-content: center;">
        <button id="phishguard-close-btn" style="background: transparent; border: 1px solid #334155; color: #94a3b8; padding: 12px 24px; border-radius: 6px; cursor: pointer; font-weight: bold; transition: all 0.2s;">
          Close Tab (Recommended)
        </button>
        <button id="phishguard-ignore-btn" style="background: transparent; border: none; color: #ef4444; text-decoration: underline; padding: 12px 24px; cursor: pointer; font-size: 12px;">
          Proceed anyway (Unsafe)
        </button>
      </div>
    </div>
  `;

  // Disable scrolling on the body
  document.body.style.overflow = 'hidden';
  
  document.documentElement.appendChild(overlay);

  // Add event listeners
  document.getElementById('phishguard-close-btn').addEventListener('click', () => {
    window.location.href = "about:blank"; // Fallback if close tab fails due to permissions
  });

  document.getElementById('phishguard-ignore-btn').addEventListener('click', () => {
    overlay.remove();
    document.body.style.overflow = '';
  });
}

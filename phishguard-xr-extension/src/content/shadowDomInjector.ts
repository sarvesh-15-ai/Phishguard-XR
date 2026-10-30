import { AnalysisResponse } from '../types/extension';

/**
 * PhishGuard-XR Isolated Shadow DOM Overlay Injector
 * Prevents host page CSS from overriding or tampering with the warning UI.
 */
export function injectShadowDomWarning(data: AnalysisResponse) {
  const existingOverlay = document.getElementById('phishguard-xr-shadow-host');
  if (existingOverlay) return;

  const shadowHost = document.createElement('div');
  shadowHost.id = 'phishguard-xr-shadow-host';
  shadowHost.style.position = 'fixed';
  shadowHost.style.top = '0';
  shadowHost.style.left = '0';
  shadowHost.style.width = '100vw';
  shadowHost.style.height = '100vh';
  shadowHost.style.zIndex = '2147483647';
  shadowHost.style.pointerEvents = 'auto';

  const shadowRoot = shadowHost.attachShadow({ mode: 'closed' });

  const container = document.createElement('div');
  container.innerHTML = `
    <style>
      :host { all: initial; }
      .phishguard-overlay {
        position: fixed;
        inset: 0;
        background: rgba(2, 6, 23, 0.95);
        backdrop-filter: blur(12px);
        display: flex;
        align-items: center;
        justify-content: center;
        font-family: system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
        color: #f8fafc;
        box-sizing: border-box;
        padding: 20px;
      }
      .phishguard-card {
        background: #0f172a;
        border: 2px solid rgba(239, 68, 68, 0.4);
        border-radius: 16px;
        max-width: 600px;
        width: 100%;
        padding: 32px;
        box-shadow: 0 25px 50px -12px rgba(0, 0, 0, 0.5);
      }
      .phishguard-badge {
        display: inline-block;
        padding: 4px 12px;
        background: rgba(239, 68, 68, 0.15);
        border: 1px solid rgba(239, 68, 68, 0.4);
        color: #f87171;
        font-size: 12px;
        font-weight: 700;
        text-transform: uppercase;
        border-radius: 6px;
        margin-bottom: 16px;
      }
      .phishguard-title {
        font-size: 24px;
        font-weight: 800;
        color: #ffffff;
        margin: 0 0 12px 0;
      }
      .phishguard-desc {
        font-size: 14px;
        color: #94a3b8;
        line-height: 1.6;
        margin-bottom: 24px;
      }
      .phishguard-evidence-list {
        background: rgba(2, 6, 23, 0.6);
        border: 1px solid #1e293b;
        border-radius: 8px;
        padding: 16px;
        margin-bottom: 24px;
      }
      .phishguard-evidence-item {
        font-size: 13px;
        color: #f1f5f9;
        margin-bottom: 8px;
        display: flex;
        align-items: center;
      }
      .phishguard-evidence-item:last-child { margin-bottom: 0; }
      .phishguard-btn-group {
        display: flex;
        gap: 12px;
      }
      .phishguard-btn-primary {
        flex: 1;
        background: #2563eb;
        color: #ffffff;
        border: none;
        padding: 12px 20px;
        font-weight: 700;
        font-size: 14px;
        border-radius: 8px;
        cursor: pointer;
        transition: background 0.2s;
      }
      .phishguard-btn-primary:hover { background: #1d4ed8; }
      .phishguard-btn-secondary {
        background: transparent;
        color: #94a3b8;
        border: 1px solid #334155;
        padding: 12px 20px;
        font-weight: 600;
        font-size: 14px;
        border-radius: 8px;
        cursor: pointer;
      }
      .phishguard-btn-secondary:hover { color: #f8fafc; border-color: #475569; }
    </style>

    <div class="phishguard-overlay">
      <div class="phishguard-card">
        <span class="phishguard-badge">${data.severity} RISK DETECTED (${data.risk_score}/100)</span>
        <h1 class="phishguard-title">Phishing Warning: Do Not Submit Credentials</h1>
        <p class="phishguard-desc">
          PhishGuard-XR identified critical security anomalies on this page. Entering passwords or sensitive data on this website puts your account at immediate risk of compromise.
        </p>

        <div class="phishguard-evidence-list">
          ${(data.evidence.url_evidence || []).map(e => `<div class="phishguard-evidence-item">⚠️ ${e}</div>`).join('')}
          ${(data.evidence.dom_evidence || []).map(e => `<div class="phishguard-evidence-item">⚠️ ${e}</div>`).join('')}
        </div>

        <div class="phishguard-btn-group">
          <button id="pg-leave-btn" class="phishguard-btn-primary">Leave Site (Recommended)</button>
          <button id="pg-report-btn" class="phishguard-btn-secondary">Report False Positive</button>
        </div>
      </div>
    </div>
  `;

  shadowRoot.appendChild(container);
  document.body.appendChild(shadowHost);

  shadowRoot.getElementById('pg-leave-btn')?.addEventListener('click', () => {
    window.location.href = 'about:blank';
  });

  shadowRoot.getElementById('pg-report-btn')?.addEventListener('click', () => {
    chrome.runtime.sendMessage({
      type: 'SUBMIT_FALSE_POSITIVE',
      domain: window.location.hostname
    });
    alert('Thank you. False positive feedback report submitted to security analysts.');
    shadowHost.remove();
  });
}

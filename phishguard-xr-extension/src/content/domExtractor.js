/**
 * PhishGuard-XR Privacy-Preserving DOM Feature Extractor & AI Security Chatbot Card
 */
function extractDomFeatures() {
  const pageOrigin = window.location.origin;

  const passwordInputs = document.querySelectorAll('input[type="password"]');
  const hasPasswordField = passwordInputs.length > 0;

  const forms = Array.from(document.forms);
  const formCount = forms.length;
  let formMethod = 'NONE';
  let formOriginMismatch = false;

  if (forms.length > 0) {
    const primaryForm = forms[0];
    formMethod = (primaryForm.method || 'GET').toUpperCase();

    if (primaryForm.action) {
      try {
        const actionOrigin = new URL(primaryForm.action, pageOrigin).origin;
        if (actionOrigin !== pageOrigin) formOriginMismatch = true;
      } catch (e) {
        formOriginMismatch = true;
      }
    }
  }

  const scripts = Array.from(document.querySelectorAll('script[src]'));
  let externalScriptCount = 0;
  scripts.forEach(script => {
    try {
      const srcOrigin = new URL(script.src, pageOrigin).origin;
      if (srcOrigin !== pageOrigin) externalScriptCount++;
    } catch (e) {}
  });

  const iframes = Array.from(document.querySelectorAll('iframe'));
  let crossOriginIframeCount = 0;
  iframes.forEach(iframe => {
    try {
      if (iframe.src) {
        const iframeOrigin = new URL(iframe.src, pageOrigin).origin;
        if (iframeOrigin !== pageOrigin) crossOriginIframeCount++;
      }
    } catch (e) {
      crossOriginIframeCount++;
    }
  });

  let suspiciousOverlayCount = 0;
  document.querySelectorAll('div, section').forEach(el => {
    const style = window.getComputedStyle(el);
    if ((style.position === 'fixed' || style.position === 'absolute') && parseInt(style.zIndex, 10) > 9999) {
      suspiciousOverlayCount++;
    }
  });

  const pageTitle = (document.title || '').toLowerCase();
  const h1Text = Array.from(document.querySelectorAll('h1')).map(h => (h.textContent || '').toLowerCase()).join(' ');
  const combinedText = `${pageTitle} ${h1Text}`;
  const loginKeywords = ['login', 'sign in', 'verify account', 'update billing', 'security alert', 'password reset'];
  const loginTextIndicator = loginKeywords.some(keyword => combinedText.includes(keyword));

  let rightClickDisabled = false;
  if (document.body && document.body.getAttribute('oncontextmenu') !== null) {
    rightClickDisabled = true;
  }

  return {
    has_password_field: hasPasswordField,
    form_count: formCount,
    form_method: formMethod,
    form_origin_mismatch: formOriginMismatch,
    external_script_count: externalScriptCount,
    cross_origin_iframe_count: crossOriginIframeCount,
    suspicious_overlay_count: suspiciousOverlayCount,
    login_text_indicator: loginTextIndicator,
    right_click_disabled: rightClickDisabled
  };
}

function showRichSecurityCard(data) {
  let toast = document.getElementById('phishguard-xr-toast-card');
  if (!toast) {
    toast = document.createElement('div');
    toast.id = 'phishguard-xr-toast-card';
    toast.style.position = 'fixed';
    toast.style.top = '20px';
    toast.style.right = '20px';
    toast.style.zIndex = '2147483647';
    toast.style.fontFamily = 'system-ui, -apple-system, sans-serif';
    toast.style.transition = 'all 0.3s ease';
    
    if (document.body) {
      document.body.appendChild(toast);
    } else if (document.documentElement) {
      document.documentElement.appendChild(toast);
    }
  }

  const severity = (data.severity || 'safe').toLowerCase();
  const riskScore = data.risk_score || 0;
  const isHigh = severity === 'critical' || severity === 'high';
  const isSuspicious = severity === 'suspicious';
  
  const statusColor = isHigh ? '#ef4444' : (isSuspicious ? '#f59e0b' : '#10b981');
  const title = isHigh ? 'PHISHGUARD-XR: THREAT DETECTED' : (isSuspicious ? 'PHISHGUARD-XR: SUSPICIOUS PAGE' : 'PHISHGUARD-XR: SAFE PAGE');

  const urlEvidence = (data.evidence && data.evidence.url_evidence) || [];
  const domEvidence = (data.evidence && data.evidence.dom_evidence) || [];
  const allEvidence = [...urlEvidence, ...domEvidence];

  let evidenceHtml = '';
  if (allEvidence.length > 0 && (isHigh || isSuspicious)) {
    evidenceHtml = `
      <div style="background: rgba(2, 6, 23, 0.7); border: 1px solid #334155; border-radius: 8px; padding: 10px 12px; margin-top: 10px; font-size: 12px; color: #cbd5e1;">
        <div style="font-weight: 700; color: #f8fafc; margin-bottom: 6px; text-transform: uppercase; font-size: 10px; letter-spacing: 0.5px;">Why this site was flagged as risk:</div>
        ${allEvidence.map(item => `<div style="margin-bottom: 4px; display: flex; align-items: center; gap: 6px;"><span style="color: ${statusColor};">⚠️</span> ${item}</div>`).join('')}
      </div>
    `;
  }

  let nextStepsHtml = '';
  if (isHigh) {
    nextStepsHtml = `
      <div style="margin-top: 10px; background: rgba(239, 68, 68, 0.1); border-left: 3px solid #ef4444; padding: 8px 10px; font-size: 12px; color: #fca5a5;">
        <strong>💡 Next Steps:</strong> Do NOT enter passwords, OTPs, or credit cards. Close this tab immediately or return to a verified domain.
      </div>
    `;
  } else if (isSuspicious) {
    nextStepsHtml = `
      <div style="margin-top: 10px; background: rgba(245, 158, 11, 0.1); border-left: 3px solid #f59e0b; padding: 8px 10px; font-size: 12px; color: #fde68a;">
        <strong>💡 Next Steps:</strong> Verify the address bar domain carefully before typing login credentials.
      </div>
    `;
  }

  const reportBtnHtml = (isHigh || isSuspicious) ? `
    <button id="pg-report-website-btn" style="margin-top: 10px; width: 100%; background: rgba(239, 68, 68, 0.2); border: 1px solid rgba(239, 68, 68, 0.5); color: #f87171; padding: 8px 12px; font-size: 12px; font-weight: 700; border-radius: 6px; cursor: pointer; transition: all 0.2s;">
      🚩 Report Phishing Website
    </button>
  ` : '';

  // AI Security Chatbot Panel HTML
  const chatbotPanelHtml = `
    <div style="margin-top: 12px; border-top: 1px solid #334155; padding-top: 10px;">
      <button id="pg-toggle-chatbot-btn" style="width: 100%; background: #1e293b; border: 1.5px solid #3b82f6; color: #60a5fa; padding: 10px; font-size: 13px; font-weight: 800; border-radius: 8px; cursor: pointer; display: flex; align-items: center; justify-content: center; gap: 8px;">
        🤖 Ask AI Security Assistant
      </button>

      <div id="pg-chatbot-box" style="display: none; margin-top: 10px; background: #020617; border: 1.5px solid #3b82f6; border-radius: 10px; padding: 12px; font-size: 12px;">
        <div id="pg-chat-history" style="max-height: 160px; overflow-y: auto; margin-bottom: 10px; color: #94a3b8; font-size: 12px; padding-right: 4px;">
          <div style="color: #60a5fa; margin-bottom: 6px;"><strong>AI Assistant:</strong> Hello! Ask me anything about this security threat or what to do next.</div>
        </div>

        <div style="display: flex; gap: 6px; margin-bottom: 10px; flex-wrap: wrap;">
          <button class="pg-quick-q" data-q="Why is this site dangerous?" style="background: #1e293b; border: 1px solid #475569; color: #cbd5e1; font-size: 11px; padding: 5px 8px; border-radius: 6px; cursor: pointer; font-weight: 600;">Why is this dangerous?</button>
          <button class="pg-quick-q" data-q="What should I do next?" style="background: #1e293b; border: 1px solid #475569; color: #cbd5e1; font-size: 11px; padding: 5px 8px; border-radius: 6px; cursor: pointer; font-weight: 600;">What should I do next?</button>
        </div>

        <div style="display: flex; flex-direction: column; gap: 8px;">
          <textarea id="pg-chat-input" placeholder="Type your question for the AI Security Assistant..." style="width: 100%; background: #0f172a; border: 2px solid #3b82f6; color: #ffffff; padding: 10px 12px; border-radius: 8px; font-size: 13px; min-height: 52px; resize: vertical; box-sizing: border-box; outline: none; font-family: inherit; line-height: 1.4;"></textarea>
          <button id="pg-chat-send" style="width: 100%; background: #2563eb; color: white; border: none; padding: 10px; border-radius: 8px; font-weight: 800; cursor: pointer; font-size: 13px; display: flex; align-items: center; justify-content: center; gap: 6px;">
            🚀 Send Question
          </button>
        </div>
      </div>
    </div>
  `;

  toast.innerHTML = `
    <div style="background: #0f172a; border: 2px solid ${statusColor}; border-radius: 14px; padding: 18px; box-shadow: 0 15px 35px rgba(0,0,0,0.8); color: #f8fafc; width: 360px; max-width: 90vw;">
      <div style="display: flex; align-items: center; justify-content: space-between; gap: 12px; margin-bottom: 6px;">
        <div style="display: flex; align-items: center; gap: 10px;">
          <div style="width: 12px; height: 12px; border-radius: 50%; background: ${statusColor}; box-shadow: 0 0 12px ${statusColor}; flex-shrink: 0;"></div>
          <div style="font-size: 11px; font-weight: 800; color: ${statusColor}; letter-spacing: 0.5px;">${title}</div>
        </div>
        <button id="pg-toast-close" style="background: transparent; border: none; color: #64748b; font-size: 18px; cursor: pointer; padding: 0 4px; line-height: 1;">✕</button>
      </div>

      <div style="font-size: 13px; color: #94a3b8; margin-bottom: 4px;">
        Risk Score: <strong style="color: #f8fafc; font-size: 15px; font-family: monospace;">${riskScore}/100</strong>
      </div>

      ${evidenceHtml}
      ${nextStepsHtml}
      ${reportBtnHtml}
      <div id="pg-report-status" style="display: none; margin-top: 8px; font-size: 11px; color: #10b981; text-align: center; font-weight: bold;"></div>
      ${chatbotPanelHtml}
    </div>
  `;

  document.getElementById('pg-toast-close')?.addEventListener('click', () => { toast.remove(); });

  // Handle Report Button Click
  document.getElementById('pg-report-website-btn')?.addEventListener('click', () => {
    const reportBtn = document.getElementById('pg-report-website-btn');
    const reportStatus = document.getElementById('pg-report-status');
    if (reportBtn) reportBtn.style.display = 'none';
    if (reportStatus) {
      reportStatus.style.display = 'block';
      reportStatus.textContent = '✓ Reported to SOC Analysts!';
    }
    chrome.runtime.sendMessage({ type: 'SUBMIT_FALSE_POSITIVE', domain: window.location.hostname });
  });

  // Handle Chatbot Toggle & Messaging
  const toggleChatBtn = document.getElementById('pg-toggle-chatbot-btn');
  const chatBox = document.getElementById('pg-chatbot-box');
  const chatInput = document.getElementById('pg-chat-input');
  const chatSend = document.getElementById('pg-chat-send');
  const chatHistory = document.getElementById('pg-chat-history');

  let autoDismissTimer = null;
  if (severity === 'safe') {
    autoDismissTimer = setTimeout(() => { if (toast) toast.remove(); }, 8000);
  }

  function cancelAutoDismiss() {
    if (autoDismissTimer) {
      clearTimeout(autoDismissTimer);
      autoDismissTimer = null;
    }
  }

  toggleChatBtn?.addEventListener('click', () => {
    cancelAutoDismiss();
    if (chatBox) chatBox.style.display = chatBox.style.display === 'none' ? 'block' : 'none';
  });

  chatInput?.addEventListener('focus', cancelAutoDismiss);
  chatInput?.addEventListener('keydown', cancelAutoDismiss);

  function getLocalSecurityAnswer(userQuery, data) {
    const q = userQuery.toLowerCase();
    const riskVal = (data && data.risk_score !== undefined) ? data.risk_score : 10;
    const isPageSafe = (data && data.severity === 'safe') || riskVal < 35;
    
    if (q.includes('enter') || q.includes('detail') || q.includes('type') || q.includes('fill') || q.includes('submit') || q.includes('credentials') || q.includes('password') || q.includes('login') || q.includes('can i')) {
      if (isPageSafe) {
        return `✅ Yes! This page is evaluated as SAFE (Risk Score: ${riskVal}/100). No origin mismatches or threat indicators were detected on this domain.`;
      } else {
        return `🚫 ABSOLUTELY NOT! Do NOT enter your details, email, or password on this page. This page has been flagged for high risk (${riskVal}/100) and potential credential theft.`;
      }
    } else if (q.includes('safe') || q.includes('legit') || q.includes('real') || q.includes('fake') || q.includes('trust') || q.includes('genuine')) {
      if (isPageSafe) {
        return `✅ Yes, this website appears SAFE. Risk Score is ${riskVal}/100. Always verify the domain name in the address bar.`;
      } else {
        return `⚠️ NO, this website is NOT safe (Risk Score: ${riskVal}/100). It exhibits deceptive indicators attempting to harvest your account credentials.`;
      }
    } else if (q.includes('why') || q.includes('risk') || q.includes('dangerous') || q.includes('flagged') || q.includes('reason')) {
      if (isPageSafe) {
        return `🛡️ This page was evaluated as SAFE because no form origin mismatches, suspicious subdomains, or punycode encodings were detected.`;
      } else {
        return `PhishGuard-XR flagged this page because it exhibits risk indicators (Risk Score: ${riskVal}/100), such as form origin mismatch or suspicious domain structure.`;
      }
    } else if (q.includes('already') || q.includes('typed') || q.includes('entered') || q.includes('submitted') || q.includes('stolen')) {
      return "🚨 URGENT ACTION: If you submitted credentials on an unverified site, open the OFFICIAL website in a clean tab, change your password immediately, and enable 2FA!";
    } else if (q.includes('origin') || q.includes('mismatch')) {
      return "An Origin Mismatch occurs when a webpage form sends your password to a different, unverified web server rather than the page host.";
    } else if (q.includes('next') || q.includes('do') || q.includes('action') || q.includes('should')) {
      if (isPageSafe) {
        return "💡 Recommendation: You can safely continue using this site. Always verify official URLs before submitting sensitive passwords.";
      } else {
        return "💡 Recommended Action: 1) Do NOT enter any credentials. 2) Close this tab immediately. 3) Report the site using the button above.";
      }
    } else {
      if (isPageSafe) {
        return `🛡️ Security Status: This page is evaluated as SAFE (Risk Score: ${riskVal}/100).`;
      } else {
        return `🛡️ Security Status: This page is flagged as HIGH RISK (Risk Score: ${riskVal}/100). Close this browser tab for your safety.`;
      }
    }
  }

  function sendChatMessage(query) {
    cancelAutoDismiss();
    if (!query || !query.trim()) return;
    
    // Append User Query
    const userMsg = document.createElement('div');
    userMsg.style.cssText = 'color: #f8fafc; margin-bottom: 6px; font-weight: 600; font-size: 12px;';
    userMsg.innerHTML = `<strong style="color: #cbd5e1;">You:</strong> ${query}`;
    chatHistory.appendChild(userMsg);
    if (chatInput) chatInput.value = '';

    // Append Immediate Context-Aware Response
    const aiMsg = document.createElement('div');
    aiMsg.style.cssText = 'color: #60a5fa; margin-bottom: 8px; background: rgba(30,41,59,0.7); padding: 8px 10px; border-radius: 6px; line-height: 1.4; border-left: 3px solid #3b82f6; font-size: 12px;';
    aiMsg.innerHTML = `<strong>AI Assistant:</strong> ${getLocalSecurityAnswer(query, data)}`;
    chatHistory.appendChild(aiMsg);
    chatHistory.scrollTop = chatHistory.scrollHeight;

    // Fetch updated response from API asynchronously
    fetch('http://localhost:8007/api/v1/assistant/chat', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ user_query: query, risk_score: data.risk_score, severity: data.severity })
    })
    .then(res => res.json())
    .then(resData => {
      if (resData && resData.response_text) {
        aiMsg.innerHTML = `<strong>AI Assistant:</strong> ${resData.response_text}`;
      }
    })
    .catch(() => {});
  }

  chatSend?.addEventListener('click', () => {
    sendChatMessage(chatInput.value);
  });

  chatInput?.addEventListener('keydown', (e) => {
    cancelAutoDismiss();
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      sendChatMessage(chatInput.value);
    }
  });

  document.querySelectorAll('.pg-quick-q').forEach(btn => {
    btn.addEventListener('click', (e) => {
      cancelAutoDismiss();
      const q = e.target.getAttribute('data-q');
      sendChatMessage(q);
    });
  });
}

function initDomScan() {
  const domFeatures = extractDomFeatures();
  chrome.runtime.sendMessage({
    type: 'DOM_FEATURES_EXTRACTED',
    payload: domFeatures,
    url: window.location.href
  });
}

if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', initDomScan);
} else {
  initDomScan();
}

chrome.runtime.onMessage.addListener((message) => {
  if (message.type === 'ANALYSIS_COMPLETE') {
    showRichSecurityCard(message.payload);
  } else if (message.type === 'TRIGGER_DOM_EXTRACTION') {
    initDomScan();
  }
});

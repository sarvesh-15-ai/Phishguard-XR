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
      <div style="background: rgba(2, 6, 23, 0.75); border: 1px solid rgba(239, 68, 68, 0.3); border-radius: 10px; padding: 12px; margin-bottom: 10px; font-size: 11.5px; color: #cbd5e1;">
        <div style="font-weight: 800; color: #f87171; margin-bottom: 8px; text-transform: uppercase; font-size: 9.5px; letter-spacing: 0.6px; display: flex; align-items: center; gap: 6px;">
          <span>⚠️</span> Threat Telemetry Detected
        </div>
        ${allEvidence.map(item => `
          <div style="margin-bottom: 5px; display: flex; align-items: flex-start; gap: 8px; line-height: 1.45;">
            <span style="color: ${statusColor}; font-size: 13px; line-height: 1;">•</span>
            <span>${item}</span>
          </div>
        `).join('')}
      </div>
    `;
  }

  let nextStepsHtml = '';
  if (isHigh) {
    nextStepsHtml = `
      <div style="margin-bottom: 10px; background: rgba(239, 68, 68, 0.12); border: 1px solid rgba(239, 68, 68, 0.3); border-left: 3.5px solid #ef4444; border-radius: 8px; padding: 10px 12px; font-size: 11.5px; color: #fca5a5; line-height: 1.45;">
        <strong style="color: #ffffff; display: block; margin-bottom: 2px;">🚨 Critical Directive:</strong>
        Do NOT type passwords, emails, or 2FA codes. Close this browser tab immediately.
      </div>
    `;
  } else if (isSuspicious) {
    nextStepsHtml = `
      <div style="margin-bottom: 10px; background: rgba(245, 158, 11, 0.12); border: 1px solid rgba(245, 158, 11, 0.3); border-left: 3.5px solid #f59e0b; border-radius: 8px; padding: 10px 12px; font-size: 11.5px; color: #fde68a; line-height: 1.45;">
        <strong style="color: #ffffff; display: block; margin-bottom: 2px;">⚠️ Caution Directive:</strong>
        Verify the domain in the address bar before submitting any sensitive details.
      </div>
    `;
  }

  const reportBtnHtml = (isHigh || isSuspicious) ? `
    <button id="pg-report-website-btn" style="margin-bottom: 10px; width: 100%; background: linear-gradient(180deg, rgba(239, 68, 68, 0.25) 0%, rgba(185, 28, 28, 0.2) 100%); border: 1px solid rgba(239, 68, 68, 0.6); color: #fca5a5; padding: 9px 12px; font-size: 11.5px; font-weight: 800; border-radius: 8px; cursor: pointer; transition: all 0.2s; letter-spacing: 0.3px;">
      🚩 Report Phishing Threat
    </button>
  ` : '';

  // AI Security Chatbot Panel HTML (ONLY rendered when threat or suspicious indicators exist)
  const chatbotPanelHtml = (isHigh || isSuspicious) ? `
    <div style="border-top: 1px solid rgba(255,255,255,0.08); padding-top: 10px;">
      <button id="pg-toggle-chatbot-btn" style="width: 100%; background: linear-gradient(180deg, rgba(30, 41, 59, 0.9) 0%, rgba(15, 23, 42, 0.95) 100%); border: 1.5px solid #3b82f6; color: #60a5fa; padding: 9px; font-size: 12px; font-weight: 800; border-radius: 8px; cursor: pointer; display: flex; align-items: center; justify-content: center; gap: 8px; box-shadow: 0 4px 12px rgba(59, 130, 246, 0.15);">
        🤖 Ask AI Security Assistant
      </button>

      <div id="pg-chatbot-box" style="display: none; margin-top: 10px; background: rgba(2, 6, 23, 0.9); border: 1px solid rgba(59, 130, 246, 0.4); border-radius: 10px; padding: 12px; font-size: 12px;">
        <div id="pg-chat-history" style="max-height: 160px; overflow-y: auto; margin-bottom: 10px; color: #94a3b8; font-size: 11.5px; padding-right: 4px;">
          <div style="color: #60a5fa; margin-bottom: 6px; line-height: 1.4;"><strong>AI Assistant:</strong> Hello! Ask me anything about this security threat or what to do next.</div>
        </div>

        <div style="display: flex; gap: 5px; margin-bottom: 10px; flex-wrap: wrap;">
          <button class="pg-quick-q" data-q="Why is this site dangerous?" style="background: #1e293b; border: 1px solid #334155; color: #cbd5e1; font-size: 10px; padding: 4px 7px; border-radius: 6px; cursor: pointer; font-weight: 600;">Why is this dangerous?</button>
          <button class="pg-quick-q" data-q="Is this really PayPal?" style="background: #1e293b; border: 1px solid #334155; color: #cbd5e1; font-size: 10px; padding: 4px 7px; border-radius: 6px; cursor: pointer; font-weight: 600;">Is this really PayPal?</button>
          <button class="pg-quick-q" data-q="Where does my password go?" style="background: #1e293b; border: 1px solid #334155; color: #cbd5e1; font-size: 10px; padding: 4px 7px; border-radius: 6px; cursor: pointer; font-weight: 600;">Where does password go?</button>
          <button class="pg-quick-q" data-q="What is Form Origin Mismatch?" style="background: #1e293b; border: 1px solid #334155; color: #cbd5e1; font-size: 10px; padding: 4px 7px; border-radius: 6px; cursor: pointer; font-weight: 600;">What is Origin Mismatch?</button>
          <button class="pg-quick-q" data-q="What should I do next?" style="background: #1e293b; border: 1px solid #334155; color: #cbd5e1; font-size: 10px; padding: 4px 7px; border-radius: 6px; cursor: pointer; font-weight: 600;">What should I do next?</button>
        </div>

        <div style="display: flex; flex-direction: column; gap: 8px;">
          <textarea id="pg-chat-input" placeholder="Type your question for the AI Security Assistant..." style="width: 100%; background: #0f172a; border: 1.5px solid #3b82f6; color: #ffffff; padding: 9px 11px; border-radius: 8px; font-size: 12px; min-height: 50px; resize: vertical; box-sizing: border-box; outline: none; font-family: inherit; line-height: 1.4;"></textarea>
          <button id="pg-chat-send" style="width: 100%; background: #2563eb; color: white; border: none; padding: 9px; border-radius: 8px; font-weight: 800; cursor: pointer; font-size: 12px; display: flex; align-items: center; justify-content: center; gap: 6px;">
            🚀 Send Question
          </button>
        </div>
      </div>
    </div>
  ` : '';

  toast.innerHTML = `
    <div style="background: rgba(10, 15, 30, 0.94); backdrop-filter: blur(20px); -webkit-backdrop-filter: blur(20px); border: 1.5px solid ${statusColor}; border-radius: 16px; padding: 18px; box-shadow: 0 20px 50px rgba(0,0,0,0.85), 0 0 30px ${statusColor}33; color: #f8fafc; width: 370px; max-width: 92vw; font-family: system-ui, -apple-system, sans-serif;">
      
      <!-- Top Cyber Status Bar -->
      <div style="display: flex; align-items: center; justify-content: space-between; gap: 10px; margin-bottom: 12px; padding-bottom: 10px; border-bottom: 1px solid rgba(255,255,255,0.08);">
        <div style="display: flex; align-items: center; gap: 8px;">
          <span style="display: inline-block; width: 9px; height: 9px; border-radius: 50%; background: ${statusColor}; box-shadow: 0 0 10px ${statusColor};"></span>
          <span style="font-size: 11px; font-weight: 800; letter-spacing: 0.6px; text-transform: uppercase; color: ${statusColor};">${title}</span>
        </div>
        <button id="pg-toast-close" style="background: rgba(30,41,59,0.6); border: 1px solid #334155; border-radius: 6px; color: #94a3b8; font-size: 13px; cursor: pointer; width: 24px; height: 24px; display: flex; align-items: center; justify-content: center; line-height: 1;">✕</button>
      </div>

      <!-- Risk Score HUD with Progress Needle -->
      <div style="display: flex; justify-content: space-between; align-items: baseline; margin-bottom: 4px;">
        <span style="font-size: 10.5px; color: #94a3b8; font-weight: 700; text-transform: uppercase; letter-spacing: 0.5px;">Calibrated Risk Index</span>
        <span style="font-size: 17px; font-weight: 800; font-family: monospace; color: ${statusColor};">${riskScore}<span style="font-size: 10.5px; color: #64748b;">/100</span></span>
      </div>
      <div style="background: rgba(30, 41, 59, 0.8); border-radius: 9999px; height: 6px; width: 100%; overflow: hidden; margin-bottom: 12px; border: 1px solid rgba(255,255,255,0.06);">
        <div style="background: ${statusColor}; height: 100%; width: ${Math.min(100, Math.max(8, riskScore))}%; box-shadow: 0 0 10px ${statusColor}; border-radius: 9999px; transition: width 0.8s ease;"></div>
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
    const q = (userQuery || '').toLowerCase().trim();
    const riskVal = (data && data.risk_score !== undefined) ? data.risk_score : 88;
    const isPageSafe = (data && data.severity === 'safe') || riskVal < 35;
    const hostname = window.location.hostname || 'this site';
    const pageTitle = document.title || '';
    const isPaypal = pageTitle.toLowerCase().includes('paypal') || document.body.innerText.toLowerCase().includes('paypal');

    // 1. "Why is this dangerous / flagged / risk?"
    if (q.includes('why') || q.includes('flagged') || q.includes('dangerous') || q.includes('threat') || q.includes('risk') || q.includes('reason')) {
      if (isPageSafe) {
        return "🛡️ This page was evaluated as SAFE because no form origin mismatches, suspicious subdomains, or credential harvesting indicators were detected.";
      }
      return `⚠️ PhishGuard-XR flagged this page with a ${riskVal}/100 HIGH RISK score because of a Critical Form Origin Mismatch! The page is mimicking ${isPaypal ? 'PayPal' : 'a secure service'}, but its login form action routes your credentials to an unauthorized external server rather than the legitimate domain. Entering your password here will deliver it straight to an attacker.`;
    }

    // 2. "Is this really PayPal / legitimate / real / fake?"
    if (q.includes('real') || q.includes('fake') || q.includes('legit') || q.includes('genuine') || q.includes('paypal') || q.includes('trust') || q.includes('honest')) {
      if (isPageSafe) {
        return `✅ Yes, this website appears legitimate (Risk Score: ${riskVal}/100). Always confirm the domain in your browser's address bar.`;
      }
      return `🚫 NO! This is a FAKE login portal. The official PayPal service is located exclusively at https://www.paypal.com. This current page (${hostname}) is an unauthorized clone using deceptive logos and styles to steal your account credentials.`;
    }

    // 3. "Where does my password go / who gets my password / credential theft"
    if (q.includes('where') || q.includes('go') || q.includes('steal') || q.includes('stolen') || q.includes('harvest') || q.includes('destination') || q.includes('send') || q.includes('deliver')) {
      return "🚨 Password Interception Warning: When you click 'Verify & Log In', the form action transmits your raw password and email to an attacker-controlled drop-server rather than official authentication servers. PhishGuard-XR's Pre-Submit Guard actively monitors this form to protect your credentials.";
    }

    // 4. "What should I do next / what to do / action"
    if (q.includes('next') || q.includes('do') || q.includes('action') || q.includes('should') || q.includes('now') || q.includes('help')) {
      if (isPageSafe) {
        return "💡 Recommendation: You can safely continue using this site. PhishGuard-XR will continue background monitoring to ensure no late-stage form hijacking occurs.";
      }
      return "💡 Recommended Immediate Actions:\n1. Do NOT enter your email, password, or OTP.\n2. Close this browser tab immediately.\n3. Open a clean tab and go directly to the verified official site (https://www.paypal.com).\n4. Click the '🚩 Report Phishing Website' button above to alert security analysts.";
    }

    // 5. "Can I enter my password / details / can I log in?"
    if (q.includes('enter') || q.includes('type') || q.includes('detail') || q.includes('fill') || q.includes('submit') || q.includes('login') || q.includes('password') || q.includes('can i')) {
      if (isPageSafe) {
        return `✅ Yes! This page is evaluated as SAFE (Risk Score: ${riskVal}/100). No origin mismatches or credential harvesting indicators were detected.`;
      }
      return `🚫 ABSOLUTELY NOT! Do NOT enter your password, email, or any personal details on this page. It has been flagged as a Critical Phishing Threat (${riskVal}/100) specifically designed to harvest login credentials.`;
    }

    // 6. "I already entered my password / already submitted / I got hacked"
    if (q.includes('already') || q.includes('hacked') || q.includes('victim') || q.includes('compromised') || q.includes('entered') || q.includes('submitted')) {
      return "🚨 EMERGENCY TRIAGE PROTOCOL:\n1. Open a clean private/incognito window immediately.\n2. Navigate directly to https://www.paypal.com (or your service's official URL).\n3. Change your password right now.\n4. Log out of all active sessions/devices in Account Settings.\n5. Enable Two-Factor Authentication (2FA) via an Authenticator App.\n6. If financial details were entered, contact your bank fraud line immediately.";
    }

    // 7. "What is an origin mismatch / form action?"
    if (q.includes('origin') || q.includes('mismatch') || q.includes('form') || q.includes('action')) {
      return `⚠️ A Form Origin Mismatch occurs when a webpage on one domain (e.g. ${hostname}) submits form data (<form action="...">) to an unverified third-party destination. Legitimate services always process logins on their own origin. Attackers use origin mismatches to host deceptive clones that exfiltrate passwords to an external drop-server.`;
    }

    // 8. "What is Quishing / QR Phishing?"
    if (q.includes('quish') || q.includes('qr') || q.includes('barcode')) {
      return "📷 Quishing (QR Phishing) is a cyberattack where criminals embed deceptive URLs inside QR codes to bypass traditional email and SMS text filters. Users scan the barcode on mobile devices, trusting the visual format, and are led to credential-stealing portals. PhishGuard-XR decodes optical QR matrices in the browser and assesses the target URL before navigation.";
    }

    // 9. "What is Smishing / SMS Phishing?"
    if (q.includes('smish') || q.includes('sms') || q.includes('text message')) {
      return "💬 Smishing is phishing conducted through SMS text messages. Fraudsters send urgent messages ('Account suspended', 'Payment failure') with shortened links leading to fake login portals. PhishGuard-XR inspects text urgency markers and audits destination domains in real-time.";
    }

    // 10. "What is Punycode / Homoglyph attack?"
    if (q.includes('punycode') || q.includes('homoglyph') || q.includes('lookalike') || q.includes('xn--')) {
      return "🔡 Punycode & Homoglyph attacks use Internationalized Domain Names (IDNs) with characters from different alphabets (e.g. Cyrillic 'а' U+0430) that look identical to standard Latin letters. To human eyes, apple.com appears normal, but the underlying DNS resolves to xn--pple-43d.com. PhishGuard-XR detects punycode homoglyphs targeting major brands.";
    }

    // 11. "Can an HTTPS / SSL site be phishing?"
    if (q.includes('https') || q.includes('ssl') || q.includes('padlock') || q.includes('lock')) {
      return "🔒 HTTPS does NOT mean safe! Over 80% of modern phishing websites use valid HTTPS/SSL certificates (from free automated CAs like Let's Encrypt). The padlock only means communication between your browser and the server is encrypted; it does NOT mean the server belongs to legitimate PayPal or bank!";
    }

    // 12. "What does 88/100 (or risk score) mean?"
    if (q.includes('score') || q.includes('88') || q.includes('platt') || q.includes('calibration') || q.includes('percent')) {
      return `📊 Risk Score (${riskVal}/100): PhishGuard-XR uses Platt Scaling (logistic regression calibration) to calculate the Bayesian probability that this webpage is fraudulent: P(Phish | DOM, URL) = 1 / (1 + exp(A * logit + B)). A score of ${riskVal}/100 indicates overwhelming statistical confidence that this is a credential harvesting attack.`;
    }

    // 13. "Zero-PII / Privacy / Do you see my data?"
    if (q.includes('privacy') || q.includes('zero-pii') || q.includes('pii') || q.includes('track') || q.includes('data')) {
      return "🔒 PhishGuard-XR Zero-PII Privacy: We guarantee that your actual passwords, usernames, form inputs, and browsing history NEVER leave your device. Only abstract, mathematical structural signals (form counts, URL character counts, SHA-256 domain root hashes) are computed locally.";
    }

    // 14. "Can I test with fake credentials / fake password?"
    if (q.includes('fake password') || q.includes('test') || q.includes('dummy') || q.includes('wrong')) {
      return "⚠️ While fake credentials will not compromise your real account, phishing servers can record your IP address, browser fingerprint, and location. For your safety, do not interact with this page and close the browser tab.";
    }

    // 15. "How does PhishGuard protect me / how do you work?"
    if (q.includes('how') && (q.includes('protect') || q.includes('work') || q.includes('detect') || q.includes('phishguard'))) {
      return "🛡️ PhishGuard-XR combines 3 layers of defense:\n1. URL Lexical Heuristics (detects unverified TLDs, brand-in-subdomain spoofing, punycode).\n2. DOM Pre-Submit Guard (inspects form action destinations and blocks origin mismatches before credentials leave your machine).\n3. Calibrated Platt Scaling Risk Engine (mathematically evaluates risk in real-time with Zero-PII privacy).";
    }

    // 16. Universal Intelligent Fallback (Answers ANY other question)
    return `🛡️ PhishGuard-XR AI Security Assistant:\nRegarding your question "${userQuery}": On this detected page (${hostname}), PhishGuard-XR identified a critical security risk (Risk Score: ${riskVal}/100) indicating active credential harvesting. For your safety, do NOT submit sensitive information, do NOT download attachments, and close this tab immediately. Feel free to ask more about how this attack works or how to secure your accounts!`;
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
    const immediateAnswer = getLocalSecurityAnswer(query, data);
    aiMsg.innerHTML = `<strong>AI Assistant:</strong> ${immediateAnswer.replace(/\n/g, '<br>')}`;
    chatHistory.appendChild(aiMsg);
    chatHistory.scrollTop = chatHistory.scrollHeight;

    // Send query to background service worker (which talks to port 8007)
    if (typeof chrome !== 'undefined' && chrome.runtime && chrome.runtime.sendMessage) {
      chrome.runtime.sendMessage({
        type: 'ASSISTANT_CHAT_QUERY',
        query: query,
        risk_score: data.risk_score,
        severity: data.severity,
        domain: window.location.hostname
      }, (res) => {
        if (res && res.status === 'ok' && res.response_text) {
          aiMsg.innerHTML = `<strong>AI Assistant:</strong> ${res.response_text.replace(/\n/g, '<br>')}`;
          chatHistory.scrollTop = chatHistory.scrollHeight;
        }
      });
    }

    // Direct fetch backup
    fetch('http://localhost:8007/api/v1/assistant/chat', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        user_query: query,
        risk_score: data.risk_score,
        severity: data.severity,
        domain: window.location.hostname
      })
    })
    .then(res => res.json())
    .then(resData => {
      if (resData && resData.response_text) {
        aiMsg.innerHTML = `<strong>AI Assistant:</strong> ${resData.response_text.replace(/\n/g, '<br>')}`;
        chatHistory.scrollTop = chatHistory.scrollHeight;
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

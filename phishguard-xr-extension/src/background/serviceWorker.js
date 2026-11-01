const API_ENDPOINT = 'http://localhost:8007/api/v1/analyze/page';
const API_TIMEOUT_MS = 2500;

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.type === 'DOM_FEATURES_EXTRACTED') {
    handlePageAnalysis(message.url, message.payload, sender.tab ? sender.tab.id : null);
  } else if (message.type === 'CREDENTIAL_SUBMIT_MISMATCH_DETECTED') {
    handleCredentialSubmitMismatch(message.payload, sender.tab ? sender.tab.id : null);
  } else if (message.type === 'SUBMIT_FALSE_POSITIVE') {
    handleFalsePositiveSubmission(message.domain);
  } else if (message.type === 'ASSISTANT_CHAT_QUERY') {
    fetch('http://localhost:8007/api/v1/assistant/chat', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        user_query: message.query,
        risk_score: message.risk_score || 88,
        severity: message.severity || 'high',
        domain: message.domain || ''
      })
    })
    .then(res => res.json())
    .then(data => sendResponse({ status: 'ok', response_text: data.response_text }))
    .catch(() => sendResponse({ status: 'error' }));
    return true; // Keep sendResponse open
  }
  return true;
});

function parseUrlFeatures(rawUrl) {
  let hostname = '';
  try {
    hostname = new URL(rawUrl).hostname.toLowerCase();
  } catch (e) {
    hostname = 'unknown-domain.invalid';
  }

  const parts = hostname.split('.');
  const subdomainCount = parts.length > 2 ? parts.length - 2 : 0;
  const publicSuffix = parts.length > 1 ? parts[parts.length - 1] : 'unknown';
  const hasIpHost = /^(\d{1,3}\.){3}\d{1,3}$/.test(hostname);
  const isPunycode = hostname.includes('xn--');
  
  const knownBrands = ['paypal', 'microsoft', 'google', 'apple', 'amazon', 'netflix'];
  const subdomainsStr = parts.slice(0, Math.max(0, parts.length - 2)).join('.');
  const brandInSubdomain = knownBrands.some(b => subdomainsStr.includes(b));

  return {
    url_length: rawUrl.length,
    subdomain_count: subdomainCount,
    special_char_count: (rawUrl.match(/[@%&=_\-\?\#]/g) || []).length,
    has_ip_host: hasIpHost,
    is_punycode: isPunycode,
    suspicious_encoding: /%[0-9a-f]{2}/i.test(rawUrl),
    brand_in_subdomain: brandInSubdomain,
    excessive_separators: (hostname.match(/[\-]/g) || []).length > 3,
    suspicious_port: false,
    public_suffix: publicSuffix,
    is_shortened: false,
    domain_root_hash: 'local_hash'
  };
}

async function handlePageAnalysis(rawUrl, domFeatures, tabId) {
  if (!tabId || rawUrl.startsWith('chrome://') || rawUrl.startsWith('about:')) return;

  const urlFeatures = parseUrlFeatures(rawUrl);

  try {
    const response = await fetch(API_ENDPOINT, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        url_features: urlFeatures,
        dom_features: domFeatures
      })
    });

    if (response.ok) {
      const data = await response.json();
      processSecurityDecision(data, tabId);
    }
  } catch (error) {
    const fallbackData = {
      decision: domFeatures && domFeatures.form_origin_mismatch ? 'block_credentials' : 'allow',
      risk_score: domFeatures && domFeatures.form_origin_mismatch ? 88 : 10,
      severity: domFeatures && domFeatures.form_origin_mismatch ? 'high' : 'safe',
      confidence: 0.85,
      uncertainty_statement: 'Offline Fallback Engine Evaluation.',
      evidence: { url_evidence: [], dom_evidence: domFeatures && domFeatures.form_origin_mismatch ? ['Form origin mismatch'] : [] }
    };
    processSecurityDecision(fallbackData, tabId);
  }
}

function handleCredentialSubmitMismatch(payload, tabId) {
  if (!tabId) return;
  const mismatchResponse = {
    decision: 'block_credentials',
    risk_score: 95,
    severity: 'critical',
    confidence: 0.99,
    uncertainty_statement: 'High confidence pre-submit origin mismatch.',
    evidence: {
      url_evidence: [],
      dom_evidence: [`Password form target origin (${payload.targetActionOrigin}) does not match page origin (${payload.pageOrigin}).`]
    }
  };
  processSecurityDecision(mismatchResponse, tabId);
}

function processSecurityDecision(data, tabId) {
  // 1. Update Action Badge
  if (data.severity === 'critical' || data.severity === 'high') {
    chrome.action.setBadgeBackgroundColor({ tabId, color: '#EF4444' });
    chrome.action.setBadgeText({ tabId, text: 'HIGH' });
  } else if (data.severity === 'suspicious') {
    chrome.action.setBadgeBackgroundColor({ tabId, color: '#F59E0B' });
    chrome.action.setBadgeText({ tabId, text: 'WARN' });
  } else {
    chrome.action.setBadgeBackgroundColor({ tabId, color: '#10B981' });
    chrome.action.setBadgeText({ tabId, text: 'SAFE' });
  }

  // 2. Dispatch response back to content script tab
  chrome.tabs.sendMessage(tabId, {
    type: 'ANALYSIS_COMPLETE',
    payload: data
  });
}

function handleFalsePositiveSubmission(domain) {
  fetch('http://localhost:8005/api/v1/feedback', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ reported_domain: domain, feedback_type: 'false_positive' })
  }).catch(() => {});
}

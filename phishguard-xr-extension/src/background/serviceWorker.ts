import { AnalysisResponse, DomFeatures, UrlFeatures } from '../types/extension';
import { extractUrlFeatures } from '../utils/urlParser';
import { evaluateLocalRules } from './localRulesEngine';

const API_ENDPOINT = 'http://localhost:8005/api/v1/analyze/page';
const API_TIMEOUT_MS = 2500;

// Listen for messages from Content Scripts and Popup
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.type === 'DOM_FEATURES_EXTRACTED') {
    handlePageAnalysis(message.url, message.payload, sender.tab?.id);
  } else if (message.type === 'CREDENTIAL_SUBMIT_MISMATCH_DETECTED') {
    handleCredentialSubmitMismatch(message.payload, sender.tab?.id);
  } else if (message.type === 'SUBMIT_FALSE_POSITIVE') {
    handleFalsePositiveSubmission(message.domain);
  }
  return true;
});

async function handlePageAnalysis(rawUrl: string, domFeatures: DomFeatures, tabId?: number) {
  if (!tabId || rawUrl.startsWith('chrome://') || rawUrl.startsWith('about:')) return;

  const urlFeatures = await extractUrlFeatures(rawUrl);

  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), API_TIMEOUT_MS);

    const response = await fetch(API_ENDPOINT, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': 'Bearer demo-tenant-jwt-token'
      },
      body: JSON.stringify({
        url_features: urlFeatures,
        dom_features: domFeatures
      }),
      signal: controller.signal
    });

    clearTimeout(timeoutId);

    if (response.ok) {
      const data: AnalysisResponse = await response.json();
      processSecurityDecision(data, tabId);
    } else {
      throw new Error(`API returned HTTP ${response.status}`);
    }

  } catch (error) {
    // API Failed or Timed Out -> Fail Safe using Local Rules Engine
    const fallbackResult = evaluateLocalRules(urlFeatures, domFeatures);
    processSecurityDecision(fallbackResult, tabId);
  }
}

function handleCredentialSubmitMismatch(payload: { pageOrigin: string; targetActionOrigin: string }, tabId?: number) {
  if (!tabId) return;
  const mismatchResponse: AnalysisResponse = {
    decision: 'block_credentials',
    risk_score: 95,
    severity: 'critical',
    confidence: 0.99,
    uncertainty_statement: 'High confidence pre-submit origin mismatch.',
    evidence: {
      url_evidence: [],
      dom_evidence: [`Password form target origin (${payload.targetActionOrigin}) does not match page origin (${payload.pageOrigin}).`],
      redirect_evidence: [],
      threat_intel_evidence: ['Pre-Submit Interceptor Guard']
    },
    model_version: 'v1.0.0-pre-submit-guard',
    timestamp: new Date().toISOString()
  };

  processSecurityDecision(mismatchResponse, tabId);
}

function processSecurityDecision(data: AnalysisResponse, tabId: number) {
  // Update Extension Action Badge
  if (data.severity === 'critical' || data.severity === 'high') {
    chrome.action.setBadgeBackgroundColor({ tabId, color: '#EF4444' });
    chrome.action.setBadgeText({ tabId, text: 'HIGH' });

    // Execute Scripting injection to display Shadow DOM Overlay
    chrome.scripting.executeScript({
      target: { tabId },
      func: (analysisData) => {
        // Shadow DOM Injector is called directly
        const shadowHost = document.createElement('div');
        shadowHost.id = 'phishguard-xr-overlay-trigger';
        shadowHost.dataset.analysis = JSON.stringify(analysisData);
        document.body.appendChild(shadowHost);
      },
      args: [data]
    });

  } else if (data.severity === 'suspicious') {
    chrome.action.setBadgeBackgroundColor({ tabId, color: '#F59E0B' });
    chrome.action.setBadgeText({ tabId, text: 'WARN' });
  } else {
    chrome.action.setBadgeText({ tabId, text: '' });
  }
}

async function handleFalsePositiveSubmission(domain: string) {
  try {
    await fetch('http://localhost:8000/api/v1/feedback', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': 'Bearer demo-tenant-jwt-token'
      },
      body: JSON.stringify({
        reported_domain: domain,
        feedback_type: 'false_positive',
        comments: 'User reported false positive via Shadow DOM Warning interface.'
      })
    });
  } catch (e) {
    // Fail silently for user
  }
}

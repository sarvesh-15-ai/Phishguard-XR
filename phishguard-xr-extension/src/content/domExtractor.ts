import { DomFeatures } from '../types/extension';

/**
 * PhishGuard-XR Privacy-Preserving DOM Feature Extractor
 * ZERO-PII GUARANTEE: Never accesses or reads input `.value` properties, cookies, 
 * session tokens, or user keystrokes.
 */
export function extractDomFeatures(): DomFeatures {
  const pageOrigin = window.location.origin;

  // 1. Password Field Count
  const passwordInputs = document.querySelectorAll('input[type="password"]');
  const hasPasswordField = passwordInputs.length > 0;

  // 2. Form Count & Primary Form Method
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
        if (actionOrigin !== pageOrigin) {
          formOriginMismatch = true;
        }
      } catch (e) {
        formOriginMismatch = true;
      }
    }
  }

  // 3. External Script Count
  const scripts = Array.from(document.querySelectorAll('script[src]'));
  let externalScriptCount = 0;
  scripts.forEach(script => {
    try {
      const srcOrigin = new URL((script as HTMLScriptElement).src, pageOrigin).origin;
      if (srcOrigin !== pageOrigin) {
        externalScriptCount++;
      }
    } catch (e) {
      // Ignore parsing errors
    }
  });

  // 4. Cross-Origin IFrame Count
  const iframes = Array.from(document.querySelectorAll('iframe'));
  let crossOriginIframeCount = 0;
  iframes.forEach(iframe => {
    try {
      if (iframe.src) {
        const iframeOrigin = new URL(iframe.src, pageOrigin).origin;
        if (iframeOrigin !== pageOrigin) {
          crossOriginIframeCount++;
        }
      }
    } catch (e) {
      crossOriginIframeCount++;
    }
  });

  // 5. Suspicious Full-Screen Overlay Count (Fixed/Absolute Z-Index > 999)
  let suspiciousOverlayCount = 0;
  const divElements = document.querySelectorAll('div, section');
  divElements.forEach(el => {
    const style = window.getComputedStyle(el);
    if ((style.position === 'fixed' || style.position === 'absolute') && parseInt(style.zIndex, 10) > 9999) {
      suspiciousOverlayCount++;
    }
  });

  // 6. Login Text Indicators (Page Title & Main Heading text only)
  const pageTitle = (document.title || '').toLowerCase();
  const h1Text = Array.from(document.querySelectorAll('h1')).map(h => (h.textContent || '').toLowerCase()).join(' ');
  const combinedText = `${pageTitle} ${h1Text}`;
  
  const loginKeywords = ['login', 'sign in', 'verify account', 'update billing', 'security alert', 'password reset'];
  const loginTextIndicator = loginKeywords.some(keyword => combinedText.includes(keyword));

  // 7. Right-Click Disabled Check
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

// Auto-run extractor and send telemetry payload to background script
if (typeof window !== 'undefined') {
  window.addEventListener('DOMContentLoaded', () => {
    const domFeatures = extractDomFeatures();
    chrome.runtime.sendMessage({
      type: 'DOM_FEATURES_EXTRACTED',
      payload: domFeatures,
      url: window.location.href
    });
  });
}

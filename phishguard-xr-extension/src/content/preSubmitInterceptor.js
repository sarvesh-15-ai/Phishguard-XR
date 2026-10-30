/**
 * PhishGuard-XR Synchronous Pre-Submit Origin Interceptor (JavaScript)
 * Listens to form submission events on forms containing password inputs.
 * Guarantees zero access to form input values.
 */
function initPreSubmitProtection() {
  document.addEventListener('submit', (event) => {
    const form = event.target;
    if (!form) return;

    // 1. Check if form contains password field
    const hasPasswordInput = form.querySelector('input[type="password"]') !== null;
    if (!hasPasswordInput) return;

    // 2. Check Origin Alignment
    const pageOrigin = window.location.origin;
    let targetActionOrigin = pageOrigin;

    if (form.action) {
      try {
        targetActionOrigin = new URL(form.action, pageOrigin).origin;
      } catch (e) {
        targetActionOrigin = 'invalid://origin';
      }
    }

    // 3. Origin Mismatch Enforcement
    if (pageOrigin !== targetActionOrigin) {
      // Synchronously halt submission before network dispatch
      event.preventDefault();
      event.stopPropagation();

      // Dispatch warning trigger message to Background Service Worker
      chrome.runtime.sendMessage({
        type: 'CREDENTIAL_SUBMIT_MISMATCH_DETECTED',
        payload: {
          pageOrigin: pageOrigin,
          targetActionOrigin: targetActionOrigin
        }
      });
    }
  }, true);
}

if (typeof window !== 'undefined') {
  initPreSubmitProtection();
}

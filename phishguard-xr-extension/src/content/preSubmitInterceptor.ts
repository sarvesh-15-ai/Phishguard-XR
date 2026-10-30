/**
 * PhishGuard-XR Synchronous Pre-Submit Origin Interceptor
 * Listens to form submission events on forms containing password inputs.
 * Guarantees zero access to form input values.
 */
export function initPreSubmitProtection() {
  document.addEventListener('submit', (event: Event) => {
    const form = event.target as HTMLFormElement | null;
    if (!form) return;

    // 1. Check if the submitting form contains a password field
    const hasPasswordInput = form.querySelector('input[type="password"]') !== null;
    if (!hasPasswordInput) return; // Do not inspect non-credential forms

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
  }, true); // Use Capture phase to run before site JS submission handlers
}

// Initialize pre-submit interceptor
if (typeof window !== 'undefined') {
  initPreSubmitProtection();
}

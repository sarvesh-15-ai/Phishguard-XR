// PhishGuard-X Background Service Worker
chrome.runtime.onInstalled.addListener(() => {
  console.log("PhishGuard-X Enterprise Extension Installed.");
});

// We could listen to webNavigation events here in the future
// to automatically trigger scans on every page load.

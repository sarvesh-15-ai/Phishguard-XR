document.addEventListener('DOMContentLoaded', () => {
  const domainDisplay = document.getElementById('domainDisplay');
  const reScanBtn = document.getElementById('reScanBtn');

  chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
    if (tabs[0] && tabs[0].url) {
      try {
        const url = new URL(tabs[0].url);
        if (domainDisplay) domainDisplay.textContent = url.hostname;
      } catch (e) {
        if (domainDisplay) domainDisplay.textContent = 'Special Page';
      }
    }
  });

  if (reScanBtn) {
    reScanBtn.addEventListener('click', () => {
      chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
        if (tabs[0] && tabs[0].id) {
          chrome.tabs.sendMessage(tabs[0].id, { type: 'TRIGGER_DOM_EXTRACTION' });
          window.close();
        }
      });
    });
  }
});

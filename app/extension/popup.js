document.addEventListener('DOMContentLoaded', async () => {
  const currentUrlEl = document.getElementById('currentUrl');
  const scanBtn = document.getElementById('scanBtn');
  const loadingState = document.getElementById('loadingState');
  const resultState = document.getElementById('resultState');
  const apiStatus = document.getElementById('apiStatus');
  
  let targetUrl = '';

  // Get current tab URL
  chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
    if (tabs[0] && tabs[0].url) {
      targetUrl = tabs[0].url;
      currentUrlEl.textContent = targetUrl;
    }
  });

  // Check API status
  try {
    const res = await fetch('http://localhost:8000/api/analyze', { method: 'OPTIONS' });
    if (res.ok) {
      apiStatus.textContent = 'API Connected';
      apiStatus.classList.add('connected');
    }
  } catch (e) {
    apiStatus.textContent = 'API Offline';
  }

  scanBtn.addEventListener('click', async () => {
    if (!targetUrl) return;
    
    scanBtn.classList.add('hidden');
    loadingState.classList.remove('hidden');
    resultState.classList.add('hidden');

    try {
      // 1. Extract live DOM signals from the active tab
      let domSignals = { hidden_iframes: 0, password_inputs: 0, right_click_disabled: false };
      
      const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
      if (tabs[0] && tabs[0].id) {
        try {
          const response = await chrome.tabs.sendMessage(tabs[0].id, { action: "EXTRACT_DOM_SIGNALS" });
          if (response) domSignals = response;
        } catch (err) {
          console.warn("Could not extract DOM signals from page (might be a restricted chrome:// URL).", err);
        }
      }

      // 2. Send Quad-Modal payload to the API
      const response = await fetch('http://localhost:8000/api/analyze', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ 
          content: targetUrl, 
          type: 'url',
          dom_signals: domSignals
        })
      });

      if (!response.ok) throw new Error("API Error");
      const data = await response.json();
      
      renderResult(data);
    } catch (error) {
      alert("Failed to connect to PhishGuard API. Ensure python server.py is running on port 8000.");
      scanBtn.classList.remove('hidden');
      loadingState.classList.add('hidden');
    }
  });

  function renderResult(data) {
    loadingState.classList.add('hidden');
    resultState.classList.remove('hidden');
    
    const riskCircle = document.getElementById('riskCircle');
    const riskScore = document.getElementById('riskScore');
    const severityTier = document.getElementById('severityTier');
    const verdictText = document.getElementById('verdictText');
    const reportContent = document.getElementById('reportContent');
    const resultCard = document.getElementById('resultCard');
    
    riskScore.textContent = data.risk_profile.score;
    severityTier.textContent = data.risk_profile.tier;
    verdictText.textContent = data.is_phishing ? "PHISHING DETECTED" : "NO THREATS";
    
    if (data.is_phishing) {
      resultCard.classList.remove('safe');
    } else {
      resultCard.classList.add('safe');
    }

    reportContent.innerHTML = data.investigation_report.split('\n\n').map(p => `<p>${p}</p>`).join('');

    // Trigger content script injection if CRITICAL
    if (data.is_phishing && (data.risk_profile.tier === 'CRITICAL' || data.risk_profile.tier === 'HIGH')) {
      chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
        chrome.tabs.sendMessage(tabs[0].id, { action: "BLOCK_PAGE", data: data });
      });
    }
  }
});

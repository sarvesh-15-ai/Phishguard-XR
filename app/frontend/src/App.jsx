import React, { useState } from 'react';
import axios from 'axios';
import Scanner from './components/Scanner';
import ResultsDashboard from './components/ResultsDashboard';
import './index.css';

function App() {
  const [isLoading, setIsLoading] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState(null);

  const handleScan = async (payload) => {
    setIsLoading(true);
    setError(null);
    setResult(null);
    try {
      const response = await axios.post('http://localhost:8000/api/analyze', payload);
      setResult(response.data);
    } catch (err) {
      console.error(err);
      setError('Failed to reach the PhishGuard API. Ensure the backend is running.');
    }
    setIsLoading(false);
  };

  return (
    <div className="app-container">
      <header className="header">
        <h1>PhishGuard</h1>
        <p>A Hybrid Transformer–Attention Fusion Framework for Explainable Phishing URL, SMS, and QR Detection.</p>
      </header>
      
      <main>
        <Scanner onScan={handleScan} isLoading={isLoading} />
        {error && <div className="glass-panel" style={{color: 'var(--danger)', marginBottom: '2rem'}}>{error}</div>}
        <ResultsDashboard result={result} />
      </main>
    </div>
  );
}

export default App;

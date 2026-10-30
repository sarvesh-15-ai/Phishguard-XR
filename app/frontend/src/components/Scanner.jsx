import React, { useState, useRef } from 'react';
import { Search, MessageSquare, QrCode, Upload } from 'lucide-react';

const Scanner = ({ onScan, isLoading }) => {
  const [activeTab, setActiveTab] = useState('url'); // url, sms, qr
  const [url, setUrl] = useState('');
  const [smsText, setSmsText] = useState('');
  const [qrFile, setQrFile] = useState(null);
  
  const fileInputRef = useRef(null);

  const handleSubmit = (e) => {
    e.preventDefault();
    if (activeTab === 'url' && url) {
      onScan({ type: 'url', content: url });
    } else if (activeTab === 'sms' && smsText) {
      onScan({ type: 'sms', content: smsText });
    } else if (activeTab === 'qr' && qrFile) {
      // Convert to base64 for the mock
      const reader = new FileReader();
      reader.onloadend = () => {
        onScan({ type: 'qr', content: reader.result });
      };
      reader.readAsDataURL(qrFile);
    }
  };

  const handleFileChange = (e) => {
    if (e.target.files && e.target.files[0]) {
      setQrFile(e.target.files[0]);
    }
  };

  return (
    <div className="scanner-container glass-panel">
      <h2>Analyze Input</h2>
      <p>Test URLs, SMS messages, or QR codes against the PhishGuard model.</p>
      
      <div className="tabs">
        <button 
          className={`tab-btn ${activeTab === 'url' ? 'active' : ''}`}
          onClick={() => setActiveTab('url')}
        >
          <Search size={16} /> URL
        </button>
        <button 
          className={`tab-btn ${activeTab === 'sms' ? 'active' : ''}`}
          onClick={() => setActiveTab('sms')}
        >
          <MessageSquare size={16} /> SMS
        </button>
        <button 
          className={`tab-btn ${activeTab === 'qr' ? 'active' : ''}`}
          onClick={() => setActiveTab('qr')}
        >
          <QrCode size={16} /> QR Code
        </button>
      </div>

      <form onSubmit={handleSubmit} className="scan-form">
        {activeTab === 'url' && (
          <input
            type="url"
            className="input-field"
            placeholder="https://example.com"
            value={url}
            onChange={(e) => setUrl(e.target.value)}
            required
          />
        )}
        
        {activeTab === 'sms' && (
          <textarea
            className="input-field textarea"
            placeholder="Paste suspicious SMS message here..."
            value={smsText}
            onChange={(e) => setSmsText(e.target.value)}
            required
            rows={4}
          />
        )}

        {activeTab === 'qr' && (
          <div 
            className="file-upload-area" 
            onClick={() => fileInputRef.current.click()}
          >
            <input 
              type="file" 
              ref={fileInputRef} 
              style={{ display: 'none' }} 
              accept="image/*"
              onChange={handleFileChange}
            />
            <Upload size={32} style={{marginBottom: '1rem', color: 'var(--accent-color)'}} />
            {qrFile ? (
              <p style={{color: 'var(--text-main)', fontWeight: 'bold'}}>{qrFile.name}</p>
            ) : (
              <p>Click to upload a QR code image</p>
            )}
          </div>
        )}

        <button type="submit" className="btn" disabled={isLoading || (activeTab==='qr' && !qrFile)}>
          {isLoading ? 'Analyzing...' : (
            <>
              <Search size={20} />
              Scan {activeTab.toUpperCase()}
            </>
          )}
        </button>
      </form>
    </div>
  );
};

export default Scanner;

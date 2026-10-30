import React from 'react';
import { ShieldCheck, AlertTriangle, Info, Activity, Network, FileText } from 'lucide-react';
import ThreatGraph from './ThreatGraph';

const ResultsDashboard = ({ result }) => {
  if (!result) return null;

  const { url, extracted_from, is_phishing, risk_profile, shap_values, raw_features, threat_graph, investigation_report } = result;
  const isLegit = !is_phishing;
  
  // Phase 5: Prepare SHAP data for charting
  const shapEntries = shap_values ? Object.entries(shap_values).sort((a, b) => Math.abs(b[1]) - Math.abs(a[1])) : [];
  
  // Find max absolute SHAP value to scale the bars correctly
  const maxShap = shapEntries.length > 0 ? Math.max(...shapEntries.map(e => Math.abs(e[1]))) : 1;

  // Determine tier CSS class
  const tierClass = risk_profile ? `tier-${risk_profile.tier.replace(' ', '')}` : '';

  return (
    <div className="results-container">
      <div className="dashboard-grid">
        
        {/* Main Risk Card */}
        <div className="glass-panel prediction-card" style={{gridColumn: '1 / -1'}}>
          <h3>Overall Risk Analysis</h3>
          {extracted_from && (
            <div style={{marginBottom: '1rem', color: 'var(--accent-color)', fontSize: '0.9rem', background: 'rgba(56, 189, 248, 0.1)', padding: '0.25rem 0.75rem', borderRadius: '12px'}}>
              Extracted from {extracted_from}
            </div>
          )}
          
          <div className="risk-container">
            <div className={`risk-score ${tierClass}`} style={{background: 'none', border: 'none'}}>
              {risk_profile ? risk_profile.score : '?'}
              <span style={{fontSize: '1.5rem', color: 'var(--text-muted)'}}>/100</span>
            </div>
            <div className={`risk-tier ${tierClass}`}>
              {risk_profile ? risk_profile.tier : (isLegit ? 'SAFE' : 'CRITICAL')}
            </div>
            <p className="risk-recommendation">
              {risk_profile ? risk_profile.recommendation : 'No recommendation available.'}
            </p>
          </div>
        </div>
        
        {/* Phase 8: AI Investigation Report Card */}
        {investigation_report && (
          <div className="glass-panel" style={{gridColumn: '1 / -1'}}>
            <h3><FileText size={18} style={{verticalAlign: 'middle', marginRight: '8px'}} /> AI Investigation Report</h3>
            <div className="ai-report-content">
              {investigation_report.split('\n\n').map((paragraph, idx) => (
                <p key={idx}>{paragraph}</p>
              ))}
            </div>
          </div>
        )}

        {/* SHAP Explainer Card */}
        <div className="glass-panel explainability-card" style={{gridColumn: '1 / -1'}}>
          <h3><Activity size={18} style={{verticalAlign: 'middle', marginRight: '8px'}} /> SHAP Feature Explanations</h3>
          <p style={{fontSize: '0.85rem', color: 'var(--text-muted)', marginBottom: '1.5rem'}}>
            SHapley Additive exPlanations. Red bars pushed the risk score higher (towards Phishing). Green bars lowered the risk score (towards Legitimate).
          </p>
          
          <div className="shap-chart">
            {shapEntries.slice(0, 8).map(([feature, value]) => {
              // Calculate width as percentage of max (max bar width is 50% of the track)
              const widthPct = (Math.abs(value) / maxShap) * 50;
              const isPositive = value > 0;
              
              return (
                <div key={feature} className="shap-bar-container">
                  <div className="shap-label">{feature}</div>
                  <div className="shap-track">
                    <div 
                      className={`shap-bar ${isPositive ? 'shap-positive' : 'shap-negative'}`}
                      style={{
                        width: `${widthPct}%`,
                        marginLeft: isPositive ? '50%' : `${50 - widthPct}%`
                      }}
                    >
                      {value > 0 ? '+' : ''}{value.toFixed(3)}
                    </div>
                  </div>
                </div>
              );
            })}
          </div>
        </div>

        {/* Phase 6: Threat Intelligence Graph Card */}
        {threat_graph && (
          <div className="glass-panel" style={{gridColumn: '1 / -1'}}>
            <h3><Network size={18} style={{verticalAlign: 'middle', marginRight: '8px'}} /> Threat Infrastructure Graph</h3>
            <p style={{fontSize: '0.85rem', color: 'var(--text-muted)', marginBottom: '1.5rem'}}>
              GraphSAGE analyzes the shared infrastructure (IPs, ASNs, Registrars). Malicious nodes (red) propagate risk to the target URL.
            </p>
            <ThreatGraph graphData={threat_graph} />
          </div>
        )}

        {/* Raw Features Table */}
        <div className="glass-panel raw-features" style={{gridColumn: '1 / -1'}}>
          <h4><Info size={16} style={{verticalAlign: 'middle', marginRight: '6px'}}/> Extracted Attributes</h4>
          <div className="feature-grid">
            {raw_features && Object.entries(raw_features).map(([key, val]) => (
              <div key={key} className="feature-item">
                <span className="feature-key">{key}</span>
                <span className="feature-value">
                  {typeof val === 'number' && !Number.isInteger(val) ? val.toFixed(3) : val}
                </span>
              </div>
            ))}
          </div>
        </div>

      </div>
    </div>
  );
};

export default ResultsDashboard;

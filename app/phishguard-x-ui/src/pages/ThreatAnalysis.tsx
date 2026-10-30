import React, { useState } from 'react';
import { Shield, QrCode, MessageSquare, Globe, ArrowRight, Loader2, AlertTriangle, ShieldCheck } from 'lucide-react';
import { api } from '../services/api';
import { AnalysisResponse, SourceType } from '../types/api';

const ThreatAnalysis: React.FC = () => {
  const [activeTab, setActiveTab] = useState<SourceType>('url');
  const [inputValue, setInputValue] = useState('');
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [result, setResult] = useState<AnalysisResponse | null>(null);

  const handleAnalyze = async () => {
    if (!inputValue.trim()) return;
    
    setIsAnalyzing(true);
    setResult(null);
    
    try {
      const response = await api.analyze({ target: inputValue, source: activeTab });
      setResult(response);
    } catch (error) {
      console.error("Analysis failed:", error);
    } finally {
      setIsAnalyzing(false);
    }
  };

  return (
    <div className="max-w-6xl mx-auto space-y-6">
      <div>
        <h1 className="text-2xl font-bold tracking-tight">Threat Analysis</h1>
        <p className="text-slate-400 mt-1">Analyze websites, QR codes, and suspicious messages using multi-modal AI.</p>
      </div>

      {!result && !isAnalyzing && (
        <div className="glass-panel overflow-hidden">
          {/* Tabs */}
          <div className="flex border-b border-slate-800">
            <button
              onClick={() => setActiveTab('url')}
              className={`flex-1 py-4 px-6 text-sm font-medium flex items-center justify-center transition-colors ${activeTab === 'url' ? 'bg-slate-800/50 text-blue-400 border-b-2 border-blue-500' : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/30'}`}
            >
              <Globe className="w-5 h-5 mr-2" /> WEBSITE / URL
            </button>
            <button
              onClick={() => setActiveTab('qr')}
              className={`flex-1 py-4 px-6 text-sm font-medium flex items-center justify-center transition-colors ${activeTab === 'qr' ? 'bg-slate-800/50 text-blue-400 border-b-2 border-blue-500' : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/30'}`}
            >
              <QrCode className="w-5 h-5 mr-2" /> QR CODE
            </button>
            <button
              onClick={() => setActiveTab('sms')}
              className={`flex-1 py-4 px-6 text-sm font-medium flex items-center justify-center transition-colors ${activeTab === 'sms' ? 'bg-slate-800/50 text-blue-400 border-b-2 border-blue-500' : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/30'}`}
            >
              <MessageSquare className="w-5 h-5 mr-2" /> SMS / MESSAGE
            </button>
          </div>

          {/* Input Area */}
          <div className="p-8">
            {activeTab === 'url' && (
              <div className="space-y-4">
                <label className="block text-sm font-medium text-slate-300">Enter a suspicious URL</label>
                <div className="relative">
                  <input
                    type="text"
                    value={inputValue}
                    onChange={(e) => setInputValue(e.target.value)}
                    placeholder="https://example.com"
                    className="w-full bg-slate-950 border border-slate-700 rounded-lg py-4 pl-4 pr-12 text-lg font-mono text-slate-100 placeholder-slate-600 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent transition-all shadow-inner"
                  />
                </div>
                <div className="flex justify-between items-center mt-6">
                  <span className="text-xs text-slate-500 flex items-center">
                    <Shield className="w-4 h-4 mr-1 text-blue-500" />
                    Analysis runs in a controlled, isolated environment.
                  </span>
                  <button
                    onClick={handleAnalyze}
                    disabled={!inputValue.trim()}
                    className="px-6 py-3 bg-blue-600 hover:bg-blue-500 disabled:opacity-50 disabled:cursor-not-allowed text-white rounded-lg font-medium shadow-lg shadow-blue-500/20 transition-all flex items-center"
                  >
                    Analyze Threat <ArrowRight className="w-4 h-4 ml-2" />
                  </button>
                </div>
              </div>
            )}
            
            {activeTab === 'qr' && (
              <div className="border-2 border-dashed border-slate-700 rounded-xl p-12 text-center hover:border-blue-500/50 transition-colors bg-slate-900/30">
                <QrCode className="w-12 h-12 text-slate-500 mx-auto mb-4" />
                <h3 className="text-lg font-medium text-slate-200 mb-2">Upload or scan a QR code</h3>
                <p className="text-sm text-slate-400 mb-6">Drag and drop an image file here, or click to browse.</p>
                <button className="px-6 py-2 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded-lg font-medium transition-colors">
                  Select Image
                </button>
              </div>
            )}

            {activeTab === 'sms' && (
              <div className="space-y-4">
                <label className="block text-sm font-medium text-slate-300">Paste the suspicious SMS or message here...</label>
                <textarea
                  value={inputValue}
                  onChange={(e) => setInputValue(e.target.value)}
                  rows={6}
                  placeholder="URGENT: Your account has been locked. Please verify your identity at https://example.com/verify immediately to restore access."
                  className="w-full bg-slate-950 border border-slate-700 rounded-lg p-4 text-slate-100 placeholder-slate-600 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent transition-all shadow-inner resize-none"
                />
                <div className="flex justify-end mt-4">
                  <button
                    onClick={handleAnalyze}
                    disabled={!inputValue.trim()}
                    className="px-6 py-3 bg-blue-600 hover:bg-blue-500 disabled:opacity-50 text-white rounded-lg font-medium shadow-lg shadow-blue-500/20 transition-all flex items-center"
                  >
                    Analyze Message <ArrowRight className="w-4 h-4 ml-2" />
                  </button>
                </div>
              </div>
            )}
          </div>
        </div>
      )}

      {/* Loading State */}
      {isAnalyzing && (
        <div className="glass-panel p-12 flex flex-col items-center justify-center space-y-8 animate-pulse">
          <Loader2 className="w-12 h-12 text-blue-500 animate-spin" />
          <div className="w-full max-w-md space-y-4">
            <h3 className="text-center text-lg font-medium text-slate-200">Executing Quad-Modal Investigation</h3>
            <div className="space-y-3 text-sm font-mono text-slate-400">
              <div className="flex items-center text-emerald-400"><span className="mr-3">✓</span> Input validated and normalized</div>
              <div className="flex items-center text-emerald-400"><span className="mr-3">✓</span> Lexical feature extraction complete</div>
              <div className="flex items-center text-blue-400"><span className="animate-pulse mr-3">●</span> Performing DOM structure analysis...</div>
              <div className="flex items-center text-slate-500"><span className="mr-3">○</span> Visual brand similarity check...</div>
              <div className="flex items-center text-slate-500"><span className="mr-3">○</span> Querying GraphSAGE Threat Intelligence...</div>
            </div>
          </div>
        </div>
      )}

      {/* Results State */}
      {result && (
        <div className="space-y-6 animate-in fade-in slide-in-from-bottom-4 duration-500">
          <div className="flex justify-between items-center">
            <h2 className="text-xl font-bold">Threat Assessment</h2>
            <button 
              onClick={() => {setResult(null); setInputValue('');}}
              className="text-sm text-slate-400 hover:text-slate-200 bg-slate-800 px-4 py-2 rounded border border-slate-700"
            >
              New Scan
            </button>
          </div>
          
          {/* Top Result Card */}
          <div className={`rounded-xl border ${result.verdict === 'phishing' ? 'bg-red-500/5 border-red-500/20' : 'bg-emerald-500/5 border-emerald-500/20'} p-8 flex flex-col md:flex-row items-center justify-between`}>
            <div className="flex items-center space-x-6">
              <div className="relative">
                {/* Simplified Circular Progress for Demo */}
                <div className="w-32 h-32 rounded-full border-8 flex items-center justify-center text-3xl font-black font-mono shadow-[0_0_15px_rgba(0,0,0,0.5)]" 
                     style={{ borderColor: result.verdict === 'phishing' ? '#ef4444' : '#10b981', color: result.verdict === 'phishing' ? '#ef4444' : '#10b981' }}>
                  {result.risk_score}
                </div>
              </div>
              <div>
                <div className={`text-sm font-bold tracking-widest mb-1 ${result.verdict === 'phishing' ? 'text-red-500' : 'text-emerald-500'}`}>
                  {result.severity} RISK
                </div>
                <h3 className="text-3xl font-bold text-slate-50 mb-2 uppercase">
                  {result.verdict === 'phishing' ? 'PHISHING DETECTED' : 'NO THREATS DETECTED'}
                </h3>
                <div className="text-slate-400 font-mono text-sm break-all max-w-xl">
                  {result.target}
                </div>
              </div>
            </div>
            <div className="mt-6 md:mt-0 md:text-right flex flex-col space-y-4">
              <div className="glass-panel px-4 py-3 bg-slate-900/50">
                <div className="text-xs text-slate-500 uppercase tracking-wider mb-1">AI Confidence</div>
                <div className="text-xl font-bold text-slate-200">{(result.confidence * 100).toFixed(1)}%</div>
              </div>
              <div className="glass-panel px-4 py-3 bg-slate-900/50">
                <div className="text-xs text-slate-500 uppercase tracking-wider mb-1">Threat Category</div>
                <div className="text-md font-medium text-slate-300">{result.threat_category}</div>
              </div>
            </div>
          </div>

          {/* AI Investigation Report */}
          <div className="glass-panel p-6 border-l-4 border-l-blue-500">
            <h3 className="text-sm font-bold uppercase tracking-wider text-slate-400 mb-4 flex items-center">
              <Shield className="w-4 h-4 mr-2 text-blue-500" /> AI Investigation Summary
            </h3>
            <div className="font-mono text-sm text-slate-300 space-y-3 leading-relaxed">
              {result.ai_investigation_report.split('\n\n').map((p, i) => (
                <p key={i}>{p}</p>
              ))}
            </div>
          </div>
          
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            {/* Evidence Breakdown */}
            <div className="space-y-6">
              <h3 className="text-lg font-bold flex items-center"><ShieldCheck className="w-5 h-5 mr-2 text-slate-400" /> Quad-Modal Evidence Breakdown</h3>
              
              <EvidenceCard title="Lexical URL Analysis" data={result.evidence.url} />
              <EvidenceCard title="Structural DOM Analysis" data={result.evidence.html} />
              <EvidenceCard title="Domain Reputation Analysis" data={result.evidence.domain} />
              <EvidenceCard title="Visual Webpage Analysis" data={result.evidence.visual} />
            </div>

            {/* Explainable AI (SHAP) */}
            <div className="space-y-6">
              <h3 className="text-lg font-bold flex items-center"><AlertTriangle className="w-5 h-5 mr-2 text-slate-400" /> Explainable AI (SHAP)</h3>
              <div className="glass-panel p-6">
                <p className="text-sm text-slate-400 mb-6">
                  "Why was this flagged?" The model classified this target based on the following feature importance values. Red pushes the score towards Phishing, Green towards Legitimate.
                </p>
                <div className="space-y-4">
                  {result.shap_values.map((shap, i) => (
                    <div key={i} className="flex flex-col">
                      <div className="flex justify-between text-xs font-mono mb-1 text-slate-300">
                        <span>{shap.feature.replace(/_/g, ' ').toUpperCase()}</span>
                        <span className={shap.value > 0 ? "text-red-400" : "text-emerald-400"}>
                          {shap.value > 0 ? '+' : ''}{(shap.value * 100).toFixed(1)}%
                        </span>
                      </div>
                      <div className="h-4 bg-slate-800 rounded overflow-hidden flex">
                        <div className="w-1/2 flex justify-end">
                          {shap.value < 0 && (
                            <div className="h-full bg-emerald-500" style={{ width: `${Math.abs(shap.value) * 200}%` }}></div>
                          )}
                        </div>
                        <div className="w-1/2 flex justify-start border-l border-slate-700">
                          {shap.value > 0 && (
                            <div className="h-full bg-red-500" style={{ width: `${shap.value * 200}%` }}></div>
                          )}
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          </div>
          
        </div>
      )}
    </div>
  );
};

// Evidence Card Subcomponent
const EvidenceCard = ({ title, data }: any) => {
  return (
    <div className="glass-panel overflow-hidden">
      <div className="bg-slate-900/80 px-4 py-3 flex justify-between items-center border-b border-slate-800">
        <h4 className="font-semibold text-slate-200">{title}</h4>
        <div className={`px-2 py-1 rounded text-xs font-bold font-mono ${data.risk_score > 50 ? 'bg-red-500/10 text-red-400 border border-red-500/20' : 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20'}`}>
          Risk: {data.risk_score}/100
        </div>
      </div>
      <div className="p-4 grid grid-cols-2 gap-4">
        {Object.entries(data.details).map(([key, value]) => (
          <div key={key} className="flex flex-col">
            <span className="text-xs text-slate-500 uppercase tracking-wider">{key}</span>
            <span className="text-sm font-mono text-slate-300">{value?.toString() || 'N/A'}</span>
          </div>
        ))}
      </div>
    </div>
  );
};

export default ThreatAnalysis;

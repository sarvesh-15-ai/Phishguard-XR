import React from 'react';
import { Database, Server, Shield, Globe } from 'lucide-react';

const ThreatIntelligence: React.FC = () => {
  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold tracking-tight">Threat Intelligence</h1>
        <p className="text-slate-400 mt-1">Global infrastructure indicators and blocklists.</p>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        <div className="glass-panel p-6 flex items-center">
          <div className="p-4 bg-red-500/10 border border-red-500/20 rounded-lg mr-4">
            <Globe className="w-8 h-8 text-red-500" />
          </div>
          <div>
            <div className="text-3xl font-bold text-slate-200">12,492</div>
            <div className="text-sm text-slate-400 uppercase tracking-wider">Malicious Domains</div>
          </div>
        </div>
        
        <div className="glass-panel p-6 flex items-center">
          <div className="p-4 bg-orange-500/10 border border-orange-500/20 rounded-lg mr-4">
            <Server className="w-8 h-8 text-orange-500" />
          </div>
          <div>
            <div className="text-3xl font-bold text-slate-200">3,104</div>
            <div className="text-sm text-slate-400 uppercase tracking-wider">High-Risk IPs</div>
          </div>
        </div>
        
        <div className="glass-panel p-6 flex items-center">
          <div className="p-4 bg-blue-500/10 border border-blue-500/20 rounded-lg mr-4">
            <Shield className="w-8 h-8 text-blue-500" />
          </div>
          <div>
            <div className="text-3xl font-bold text-slate-200">156</div>
            <div className="text-sm text-slate-400 uppercase tracking-wider">Threat Families</div>
          </div>
        </div>
      </div>
      
      <div className="glass-panel p-12 text-center flex flex-col items-center justify-center">
        <Database className="w-16 h-16 text-slate-700 mb-4" />
        <h3 className="text-xl font-bold text-slate-300">Global Threat Feed Synced</h3>
        <p className="text-slate-500 mt-2 max-w-md">The GraphSAGE engine is currently connected to the primary threat intelligence feed. Data is updated in real-time.</p>
      </div>
    </div>
  );
};

export default ThreatIntelligence;

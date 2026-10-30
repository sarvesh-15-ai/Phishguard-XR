import React, { useState, useEffect } from 'react';
import { api } from '../services/api';
import { ThreatGraph as GraphType } from '../types/api';
import { Network, Server, Shield, Link, Database } from 'lucide-react';

const ThreatGraph: React.FC = () => {
  const [graphData, setGraphData] = useState<GraphType | null>(null);

  useEffect(() => {
    // Generate mock graph by running a mock analysis
    api.analyze({ target: 'suspicious-login.com', source: 'url' }).then(res => {
      setGraphData(res.threat_graph);
    });
  }, []);

  if (!graphData) return <div className="p-12 text-center text-slate-400">Loading threat intelligence...</div>;

  return (
    <div className="space-y-6 flex flex-col h-[calc(100vh-10rem)]">
      <div>
        <h1 className="text-2xl font-bold tracking-tight">Threat Intelligence Graph</h1>
        <p className="text-slate-400 mt-1">Interactive GraphSAGE infrastructure investigation.</p>
      </div>

      <div className="flex-1 flex space-x-6 overflow-hidden">
        
        {/* Left Panel - Filters */}
        <div className="w-64 glass-panel p-4 flex flex-col space-y-6 overflow-y-auto">
          <div>
            <h3 className="text-sm font-bold uppercase tracking-wider text-slate-400 mb-3">Filters</h3>
            <div className="space-y-2">
              <label className="flex items-center space-x-2 text-sm text-slate-300">
                <input type="checkbox" defaultChecked className="rounded bg-slate-900 border-slate-700 text-blue-500" />
                <span>Domains</span>
              </label>
              <label className="flex items-center space-x-2 text-sm text-slate-300">
                <input type="checkbox" defaultChecked className="rounded bg-slate-900 border-slate-700 text-blue-500" />
                <span>IP Addresses</span>
              </label>
              <label className="flex items-center space-x-2 text-sm text-slate-300">
                <input type="checkbox" defaultChecked className="rounded bg-slate-900 border-slate-700 text-blue-500" />
                <span>Certificates</span>
              </label>
            </div>
          </div>
          
          <div>
            <h3 className="text-sm font-bold uppercase tracking-wider text-slate-400 mb-3">Graph Legend</h3>
            <div className="space-y-3">
              <div className="flex items-center text-sm text-slate-300"><Database className="w-4 h-4 mr-2 text-blue-400" /> Target URL</div>
              <div className="flex items-center text-sm text-slate-300"><Server className="w-4 h-4 mr-2 text-slate-400" /> Infrastructure</div>
              <div className="flex items-center text-sm text-slate-300"><Shield className="w-4 h-4 mr-2 text-red-500" /> Malicious Node</div>
            </div>
          </div>
        </div>

        {/* Center Panel - Graph SVG */}
        <div className="flex-1 glass-panel relative overflow-hidden flex items-center justify-center">
          {/* Simple SVG Graph Representation for Mock UI */}
          <svg width="100%" height="100%" className="absolute inset-0">
            {/* Define connections */}
            {graphData.edges.map((edge, i) => {
              // Mock coordinates just for visual representation
              const isTarget = edge.source === graphData.nodes[0].id;
              const x1 = isTarget ? '50%' : '30%';
              const y1 = isTarget ? '50%' : '70%';
              const x2 = edge.target.includes('192') ? '70%' : '30%';
              const y2 = edge.target.includes('192') ? '30%' : '70%';
              
              return (
                <g key={i}>
                  <line x1={x1} y1={y1} x2={x2} y2={y2} stroke="#334155" strokeWidth="2" />
                  <text x="60%" y="40%" fill="#64748b" fontSize="12" textAnchor="middle">{edge.label}</text>
                </g>
              );
            })}
            
            {/* Draw nodes */}
            <g transform="translate(400, 300)">
              <circle r="30" fill="#0f172a" stroke="#3b82f6" strokeWidth="4" />
              <text y="45" fill="#f8fafc" fontSize="14" textAnchor="middle">{graphData.nodes[0].id}</text>
              <text y="65" fill="#94a3b8" fontSize="12" textAnchor="middle">Target</text>
            </g>
            <g transform="translate(600, 150)">
              <circle r="20" fill="#0f172a" stroke="#64748b" strokeWidth="3" />
              <text y="35" fill="#f8fafc" fontSize="14" textAnchor="middle">192.168.1.100</text>
              <text y="50" fill="#94a3b8" fontSize="12" textAnchor="middle">IP Address</text>
            </g>
            <g transform="translate(200, 450)">
              <circle r="25" fill="#0f172a" stroke="#ef4444" strokeWidth="4" />
              <text y="40" fill="#f8fafc" fontSize="14" textAnchor="middle">malicious-fake.com</text>
              <text y="55" fill="#94a3b8" fontSize="12" textAnchor="middle">Known Phishing</text>
            </g>
          </svg>
          
          <div className="absolute top-4 right-4 bg-slate-900/80 p-2 rounded text-xs text-slate-400 border border-slate-800">
            Interactive GraphSAGE Engine Active
          </div>
        </div>

        {/* Right Panel - Node Details */}
        <div className="w-72 glass-panel p-6 flex flex-col overflow-y-auto">
          <h3 className="text-sm font-bold uppercase tracking-wider text-slate-400 mb-4">Node Details</h3>
          
          <div className="space-y-6">
            <div>
              <div className="text-xs text-slate-500 uppercase">Selected Node</div>
              <div className="font-mono text-lg font-bold text-slate-200 break-all mt-1">suspicious-login.com</div>
            </div>
            
            <div>
              <div className="text-xs text-slate-500 uppercase mb-1">Entity Type</div>
              <div className="inline-block px-2 py-1 bg-blue-500/10 text-blue-400 text-xs font-bold rounded border border-blue-500/20">DOMAIN</div>
            </div>
            
            <div>
              <div className="text-xs text-slate-500 uppercase mb-1">GraphSAGE Risk</div>
              <div className="flex items-center">
                <div className="w-full bg-slate-800 h-2 rounded-full mr-3">
                  <div className="bg-red-500 h-full rounded-full" style={{ width: '94%' }}></div>
                </div>
                <span className="font-mono text-slate-200">94</span>
              </div>
            </div>

            <div className="pt-4 border-t border-slate-800">
              <h4 className="text-sm font-bold text-slate-300 mb-3">Related Entities</h4>
              <ul className="space-y-2 text-sm text-slate-400">
                <li className="flex justify-between items-center">
                  <span className="flex items-center"><Link className="w-4 h-4 mr-2" /> Domains</span>
                  <span className="font-mono">1</span>
                </li>
                <li className="flex justify-between items-center">
                  <span className="flex items-center"><Link className="w-4 h-4 mr-2" /> IP Addresses</span>
                  <span className="font-mono">1</span>
                </li>
                <li className="flex justify-between items-center text-red-400">
                  <span className="flex items-center"><Shield className="w-4 h-4 mr-2" /> Known Malicious</span>
                  <span className="font-mono">1</span>
                </li>
              </ul>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default ThreatGraph;

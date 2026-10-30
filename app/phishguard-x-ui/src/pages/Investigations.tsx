import React from 'react';
import { Search, Filter, ArrowRight } from 'lucide-react';

const Investigations: React.FC = () => {
  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold tracking-tight">Active Investigations</h1>
        <p className="text-slate-400 mt-1">Manage and review flagged threats across your network.</p>
      </div>

      <div className="glass-panel overflow-hidden">
        <div className="p-4 border-b border-slate-800 flex justify-between items-center bg-slate-900/50">
          <div className="flex space-x-2">
            <div className="relative">
              <Search className="w-4 h-4 absolute left-3 top-1/2 transform -translate-y-1/2 text-slate-500" />
              <input type="text" placeholder="Search ID, target..." className="pl-9 pr-4 py-2 bg-slate-950 border border-slate-800 rounded-md text-sm text-slate-200 focus:outline-none focus:border-blue-500" />
            </div>
            <button className="flex items-center px-4 py-2 bg-slate-900 border border-slate-700 rounded-md text-sm text-slate-300 hover:bg-slate-800">
              <Filter className="w-4 h-4 mr-2" /> Filter
            </button>
          </div>
        </div>
        
        <table className="w-full text-sm text-left">
          <thead className="text-xs text-slate-500 bg-slate-900/80 uppercase">
            <tr>
              <th className="px-6 py-4">ID</th>
              <th className="px-6 py-4">Target</th>
              <th className="px-6 py-4">Threat Type</th>
              <th className="px-6 py-4">Risk</th>
              <th className="px-6 py-4">Status</th>
              <th className="px-6 py-4">Created</th>
              <th className="px-6 py-4"></th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-800">
            <tr className="hover:bg-slate-800/30">
              <td className="px-6 py-4 font-mono text-xs text-slate-400">INV-84921</td>
              <td className="px-6 py-4 font-mono text-slate-200">login-paypal-secure.xyz</td>
              <td className="px-6 py-4 text-slate-400">Credential Harvesting</td>
              <td className="px-6 py-4"><span className="text-red-400 font-mono font-bold">94/100</span></td>
              <td className="px-6 py-4"><span className="px-2 py-1 text-xs bg-red-500/10 text-red-400 border border-red-500/20 rounded">Flagged</span></td>
              <td className="px-6 py-4 text-slate-500 text-xs">2 mins ago</td>
              <td className="px-6 py-4 text-right"><button className="text-blue-400 hover:text-blue-300"><ArrowRight className="w-4 h-4" /></button></td>
            </tr>
            <tr className="hover:bg-slate-800/30">
              <td className="px-6 py-4 font-mono text-xs text-slate-400">INV-84920</td>
              <td className="px-6 py-4 font-mono text-slate-200">auth.microsoft.updates.com</td>
              <td className="px-6 py-4 text-slate-400">Spear Phishing</td>
              <td className="px-6 py-4"><span className="text-orange-400 font-mono font-bold">88/100</span></td>
              <td className="px-6 py-4"><span className="px-2 py-1 text-xs bg-orange-500/10 text-orange-400 border border-orange-500/20 rounded">Reviewed</span></td>
              <td className="px-6 py-4 text-slate-500 text-xs">15 mins ago</td>
              <td className="px-6 py-4 text-right"><button className="text-blue-400 hover:text-blue-300"><ArrowRight className="w-4 h-4" /></button></td>
            </tr>
          </tbody>
        </table>
      </div>
    </div>
  );
};

export default Investigations;

import React from 'react';
import { Activity, ShieldAlert, ShieldCheck, Target, AlertTriangle } from 'lucide-react';
import { AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, BarChart, Bar, Cell } from 'recharts';

const Dashboard: React.FC = () => {
  const trendData = [
    { name: 'Mon', threats: 12 },
    { name: 'Tue', threats: 19 },
    { name: 'Wed', threats: 15 },
    { name: 'Thu', threats: 28 },
    { name: 'Fri', threats: 42 },
    { name: 'Sat', threats: 38 },
    { name: 'Sun', threats: 45 },
  ];

  const severityData = [
    { name: 'Safe', value: 450, color: '#10b981' },
    { name: 'Low', value: 120, color: '#3b82f6' },
    { name: 'Medium', value: 85, color: '#f59e0b' },
    { name: 'High', value: 45, color: '#f97316' },
    { name: 'Critical', value: 24, color: '#ef4444' },
  ];

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold tracking-tight">Security Overview</h1>
        <p className="text-slate-400 mt-1">Real-time phishing threat analysis and investigation</p>
      </div>

      {/* Top Metrics */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
        <MetricCard title="URLs Analyzed" value="12,450" trend="+14.2%" trendUp={true} icon={Target} color="blue" />
        <MetricCard title="Threats Detected" value="842" trend="+5.4%" trendUp={true} icon={ShieldAlert} color="orange" />
        <MetricCard title="Critical Threats" value="124" trend="-2.1%" trendUp={false} icon={AlertTriangle} color="red" />
        <MetricCard title="Detection Rate" value="99.4%" trend="+0.1%" trendUp={true} icon={Activity} color="green" />
      </div>

      {/* Charts Row */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="glass-panel p-6 lg:col-span-2">
          <h3 className="text-sm font-medium text-slate-400 mb-4 uppercase tracking-wider">Threat Detection Trend (7 Days)</h3>
          <div className="h-64">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={trendData}>
                <defs>
                  <linearGradient id="colorThreats" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#ef4444" stopOpacity={0.3}/>
                    <stop offset="95%" stopColor="#ef4444" stopOpacity={0}/>
                  </linearGradient>
                </defs>
                <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" vertical={false} />
                <XAxis dataKey="name" stroke="#64748b" fontSize={12} tickLine={false} axisLine={false} />
                <YAxis stroke="#64748b" fontSize={12} tickLine={false} axisLine={false} />
                <Tooltip 
                  contentStyle={{ backgroundColor: '#0f172a', borderColor: '#1e293b', color: '#f8fafc' }}
                  itemStyle={{ color: '#ef4444' }}
                />
                <Area type="monotone" dataKey="threats" stroke="#ef4444" fillOpacity={1} fill="url(#colorThreats)" />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </div>

        <div className="glass-panel p-6">
          <h3 className="text-sm font-medium text-slate-400 mb-4 uppercase tracking-wider">Severity Distribution</h3>
          <div className="h-64">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={severityData} layout="vertical" margin={{ top: 0, right: 0, left: 20, bottom: 0 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" horizontal={false} />
                <XAxis type="number" stroke="#64748b" fontSize={12} tickLine={false} axisLine={false} hide />
                <YAxis dataKey="name" type="category" stroke="#94a3b8" fontSize={12} tickLine={false} axisLine={false} />
                <Tooltip 
                  cursor={{fill: '#1e293b'}}
                  contentStyle={{ backgroundColor: '#0f172a', borderColor: '#1e293b', color: '#f8fafc' }}
                />
                <Bar dataKey="value" radius={[0, 4, 4, 0]} barSize={24}>
                  {severityData.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={entry.color} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>
      </div>

      {/* Recent Investigations Table */}
      <div className="glass-panel overflow-hidden">
        <div className="p-6 border-b border-slate-800 flex justify-between items-center">
          <h3 className="text-sm font-medium text-slate-400 uppercase tracking-wider">Recent Investigations</h3>
          <button className="text-sm text-blue-400 hover:text-blue-300">View All</button>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-sm text-left">
            <thead className="text-xs text-slate-500 bg-slate-900/50 uppercase">
              <tr>
                <th className="px-6 py-4 font-medium">Target</th>
                <th className="px-6 py-4 font-medium">Source</th>
                <th className="px-6 py-4 font-medium">Threat Type</th>
                <th className="px-6 py-4 font-medium">Risk Score</th>
                <th className="px-6 py-4 font-medium">Status</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800">
              <TableRow target="login-paypal-secure.xyz" source="Website" type="Credential Harvesting" risk={94} status="Blocked" color="red" />
              <TableRow target="auth.microsoft.updates.com" source="SMS" type="Spear Phishing" risk={88} status="Flagged" color="orange" />
              <TableRow target="github.com" source="Website" type="None" risk={4} status="Allowed" color="green" />
              <TableRow target="192.168.1.45/invoice.pdf" source="QR Code" type="Malware Dropper" risk={76} status="Blocked" color="orange" />
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};

// Subcomponents
const MetricCard = ({ title, value, trend, trendUp, icon: Icon, color }: any) => {
  const colorClasses: Record<string, string> = {
    blue: 'text-blue-400 bg-blue-400/10 border-blue-400/20',
    green: 'text-emerald-400 bg-emerald-400/10 border-emerald-400/20',
    orange: 'text-orange-400 bg-orange-400/10 border-orange-400/20',
    red: 'text-red-400 bg-red-400/10 border-red-400/20',
  };

  return (
    <div className="glass-panel p-6 flex flex-col">
      <div className="flex justify-between items-start mb-4">
        <div className={`p-3 rounded-lg border ${colorClasses[color]}`}>
          <Icon className="w-6 h-6" />
        </div>
        <div className={`flex items-center text-sm font-medium ${trendUp ? 'text-emerald-400' : 'text-red-400'}`}>
          {trend}
        </div>
      </div>
      <h3 className="text-3xl font-bold text-slate-50 mb-1">{value}</h3>
      <p className="text-sm text-slate-400 font-medium">{title}</p>
    </div>
  );
};

const TableRow = ({ target, source, type, risk, status, color }: any) => {
  const badgeClasses: Record<string, string> = {
    red: 'bg-red-500/10 text-red-400 border-red-500/20',
    orange: 'bg-orange-500/10 text-orange-400 border-orange-500/20',
    green: 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20',
  };

  return (
    <tr className="hover:bg-slate-800/30 transition-colors">
      <td className="px-6 py-4 font-mono text-slate-300">{target}</td>
      <td className="px-6 py-4 text-slate-400">{source}</td>
      <td className="px-6 py-4 text-slate-400">{type}</td>
      <td className="px-6 py-4">
        <div className="flex items-center">
          <div className="w-16 h-2 bg-slate-800 rounded-full mr-3 overflow-hidden">
            <div className={`h-full ${color === 'red' ? 'bg-red-500' : color === 'orange' ? 'bg-orange-500' : 'bg-emerald-500'}`} style={{ width: `${risk}%` }}></div>
          </div>
          <span className="font-mono">{risk}</span>
        </div>
      </td>
      <td className="px-6 py-4">
        <span className={`px-2.5 py-1 text-xs font-semibold rounded border ${badgeClasses[color]}`}>
          {status}
        </span>
      </td>
    </tr>
  );
};

export default Dashboard;

import React from 'react';
import { Outlet, NavLink } from 'react-router-dom';
import { Shield, LayoutDashboard, Search, FileText, Network, BarChart3, Settings, Bell, Search as SearchIcon, User } from 'lucide-react';

const MainLayout: React.FC = () => {
  const navItems = [
    { name: 'Dashboard', icon: LayoutDashboard, path: '/dashboard' },
    { name: 'Analyze', icon: Search, path: '/analyze' },
    { name: 'Investigations', icon: FileText, path: '/investigations' },
    { name: 'Threat Intelligence', icon: Shield, path: '/intelligence' },
    { name: 'Threat Graph', icon: Network, path: '/graph' },
    { name: 'Model Insights', icon: BarChart3, path: '/insights' },
    { name: 'Settings', icon: Settings, path: '/settings' },
  ];

  return (
    <div className="flex h-screen bg-slate-950 text-slate-50 overflow-hidden">
      {/* Sidebar */}
      <aside className="w-64 flex-shrink-0 border-r border-slate-800 bg-slate-900 flex flex-col">
        <div className="h-16 flex items-center px-6 border-b border-slate-800">
          <Shield className="w-6 h-6 text-blue-500 mr-2" />
          <span className="font-bold text-lg tracking-wider">PHISHGUARD<span className="text-blue-500">-X</span></span>
        </div>
        
        <nav className="flex-1 overflow-y-auto py-6 px-4 space-y-1">
          {navItems.map((item) => (
            <NavLink
              key={item.name}
              to={item.path}
              className={({ isActive }) =>
                `flex items-center px-4 py-2.5 text-sm font-medium rounded-md transition-colors ${
                  isActive 
                    ? 'bg-blue-500/10 text-blue-400' 
                    : 'text-slate-400 hover:bg-slate-800 hover:text-slate-50'
                }`
              }
            >
              <item.icon className="w-5 h-5 mr-3" />
              {item.name}
            </NavLink>
          ))}
        </nav>
        
        <div className="p-4 border-t border-slate-800">
          <div className="flex items-center text-sm text-slate-400 mb-4">
            <div className="w-2 h-2 rounded-full bg-green-500 mr-2"></div>
            Backend Connected
          </div>
          <div className="flex items-center">
            <div className="w-8 h-8 rounded-full bg-slate-800 flex items-center justify-center mr-3">
              <User className="w-4 h-4 text-slate-400" />
            </div>
            <div className="flex flex-col">
              <span className="text-sm font-medium text-slate-200">Security Analyst</span>
              <span className="text-xs text-slate-500">SOC Team Alpha</span>
            </div>
          </div>
        </div>
      </aside>

      {/* Main Content */}
      <div className="flex-1 flex flex-col min-w-0 overflow-hidden">
        {/* Topbar */}
        <header className="h-16 flex-shrink-0 border-b border-slate-800 bg-slate-900 flex items-center justify-between px-6">
          <div className="flex-1 flex items-center">
            <div className="relative w-96">
              <span className="absolute inset-y-0 left-0 flex items-center pl-3">
                <SearchIcon className="w-4 h-4 text-slate-500" />
              </span>
              <input
                type="text"
                className="w-full bg-slate-950 border border-slate-800 rounded-md py-1.5 pl-10 pr-4 text-sm text-slate-200 placeholder-slate-500 focus:outline-none focus:ring-1 focus:ring-blue-500 focus:border-blue-500"
                placeholder="Search IPs, domains, investigations..."
              />
            </div>
          </div>
          
          <div className="flex items-center space-x-4">
            <button className="text-slate-400 hover:text-slate-50 relative">
              <Bell className="w-5 h-5" />
              <span className="absolute top-0 right-0 block h-2 w-2 rounded-full bg-red-500 ring-2 ring-slate-900"></span>
            </button>
            <div className="px-3 py-1 bg-blue-500/10 text-blue-400 rounded text-xs font-semibold border border-blue-500/20">
              ML Model: XGBoost v2.4 (Active)
            </div>
          </div>
        </header>

        {/* Scrollable Content Area */}
        <main className="flex-1 overflow-y-auto p-6 lg:p-8 bg-slate-950">
          <Outlet />
        </main>
      </div>
    </div>
  );
};

export default MainLayout;

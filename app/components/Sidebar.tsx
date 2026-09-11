'use client';

import Link from 'next/link';
import { usePathname } from 'next/navigation';
import {
  LayoutDashboard,
  Mail,
  Briefcase,
  Network,
  Shield,
  GitBranch,
  FileText,
  ClipboardList,
  Settings,
  ShieldCheck,
  ChevronDown,
  Activity,
} from 'lucide-react';

interface NavItem {
  label: string;
  href: string;
  icon: React.ReactNode;
  badge?: number;
  section?: string;
}

const navItems: NavItem[] = [
  { label: 'Overview', href: '/overview', icon: <LayoutDashboard className="w-4 h-4" />, section: 'WORKSPACE' },
  { label: 'Analyze Email', href: '/analyze', icon: <Mail className="w-4 h-4" /> },
  { label: 'Cases', href: '/cases', icon: <Briefcase className="w-4 h-4" />, badge: 24 },
  { label: 'Route Trace', href: '/route-trace', icon: <Network className="w-4 h-4" /> },
  { label: 'Threat Intelligence', href: '/threat-intelligence', icon: <Shield className="w-4 h-4" /> },
  { label: 'Campaign Graph', href: '/campaign-graph', icon: <GitBranch className="w-4 h-4" /> },
  { label: 'Reports', href: '/reports', icon: <FileText className="w-4 h-4" /> },
  { label: 'Audit Logs', href: '/audit-logs', icon: <ClipboardList className="w-4 h-4" /> },
  { label: 'Settings', href: '/settings', icon: <Settings className="w-4 h-4" />, section: 'SYSTEM' },
];

export default function Sidebar() {
  const pathname = usePathname();

  return (
    <aside className="fixed inset-y-0 left-0 w-[280px] bg-[#0f172a] flex flex-col shadow-xl z-30 border-r border-slate-800">
      {/* Logo */}
      <div className="h-16 flex items-center px-5 border-b border-slate-800">
        <div className="flex items-center gap-3">
          <div className="w-8 h-8 bg-blue-600 rounded-lg flex items-center justify-center relative flex-shrink-0">
            <ShieldCheck className="w-4 h-4 text-white" />
          </div>
          <span className="text-lg font-bold text-white">
            MailTrace <span className="text-blue-400">AI</span>
          </span>
        </div>
      </div>

      {/* Workspace selector */}
      <div className="px-3 py-3 border-b border-slate-800">
        <button className="w-full flex items-center gap-3 px-3 py-2.5 rounded-xl hover:bg-slate-800 transition-colors group">
          <div className="w-8 h-8 bg-blue-600/20 border border-blue-500/30 rounded-lg flex items-center justify-center text-blue-400 text-xs font-bold flex-shrink-0">
            AC
          </div>
          <div className="flex-1 text-left min-w-0">
            <div className="text-sm font-semibold text-white truncate">Acme Corporation</div>
            <div className="text-xs text-slate-500">Enterprise workspace</div>
          </div>
          <ChevronDown className="w-3.5 h-3.5 text-slate-500 group-hover:text-slate-400 transition-colors flex-shrink-0" />
        </button>
      </div>

      {/* Navigation */}
      <nav className="flex-1 overflow-y-auto py-3 px-3">
        {navItems.map((item, idx) => {
          const isActive = pathname === item.href || pathname.startsWith(item.href + '/');
          const prevItem = navItems[idx - 1];
          const showSection = item.section && item.section !== prevItem?.section;

          return (
            <div key={item.href}>
              {showSection && (
                <div className="px-3 py-2 mt-2">
                  <span className="text-[10px] font-semibold text-slate-600 uppercase tracking-widest">
                    {item.section}
                  </span>
                </div>
              )}
              <Link
                href={item.href}
                className={`flex items-center gap-3 px-3 py-2.5 rounded-xl mb-0.5 transition-all duration-150 group relative ${
                  isActive
                    ? 'bg-slate-800 text-white'
                    : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/50'
                }`}
              >
                {isActive && (
                  <div className="absolute left-0 top-1/2 -translate-y-1/2 w-0.5 h-5 bg-blue-500 rounded-r-full" />
                )}
                <span className={isActive ? 'text-blue-400' : 'text-slate-500 group-hover:text-slate-400'}>{item.icon}</span>
                <span className="text-sm font-medium flex-1">{item.label}</span>
                {item.badge && (
                  <span className="text-xs bg-slate-700 text-slate-300 px-2 py-0.5 rounded-full font-medium">
                    {item.badge}
                  </span>
                )}
              </Link>
            </div>
          );
        })}
      </nav>

      {/* Status footer */}
      <div className="px-3 pb-4 pt-2 border-t border-slate-800">
        <div className="flex items-center gap-2 px-3 py-2">
          <div className="w-2 h-2 bg-emerald-500 rounded-full animate-pulse" />
          <span className="text-xs text-slate-400 font-medium">All systems operational</span>
        </div>
        <div className="px-3">
          <span className="text-xs text-slate-600">Last checked just now</span>
        </div>

        {/* User profile */}
        <div className="mt-3 flex items-center gap-2.5 px-3 py-2 rounded-xl hover:bg-slate-800 transition-colors cursor-pointer">
          <div className="w-7 h-7 rounded-full bg-blue-600 flex items-center justify-center text-white text-xs font-bold flex-shrink-0">
            N
          </div>
          <div className="flex items-center gap-1.5">
            <Activity className="w-3 h-3 text-slate-500" />
          </div>
        </div>
      </div>
    </aside>
  );
}

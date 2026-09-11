'use client';

import Link from 'next/link';
import { usePathname, useRouter } from 'next/navigation';
import { useEffect, useState } from 'react';
import {
  LayoutDashboard,
  Mail,
  Inbox,
  Briefcase,
  Network,
  Shield,
  GitBranch,
  FileText,
  ClipboardList,
  Settings,
  ShieldCheck,
  ChevronDown,
  LogOut,
  Activity,
  User,
} from 'lucide-react';
import { authAPI } from '@/lib/api';

interface NavItem {
  label: string;
  href: string;
  icon: React.ReactNode;
  badge?: number | null;
  section?: string;
}

const navItems: NavItem[] = [
  { label: 'Overview', href: '/overview', icon: <LayoutDashboard className="w-4 h-4" />, section: 'WORKSPACE' },
  { label: 'Analyze Email', href: '/analyze', icon: <Mail className="w-4 h-4" /> },
  { label: 'Gmail Inbox', href: '/gmail-inbox', icon: <Inbox className="w-4 h-4" /> },
  { label: 'Cases', href: '/cases', icon: <Briefcase className="w-4 h-4" />, section: 'INVESTIGATION' },
  { label: 'Route Trace', href: '/route-trace', icon: <Network className="w-4 h-4" /> },
  { label: 'Threat Intelligence', href: '/threat-intelligence', icon: <Shield className="w-4 h-4" /> },
  { label: 'Campaign Graph', href: '/campaign-graph', icon: <GitBranch className="w-4 h-4" /> },
  { label: 'Reports', href: '/reports', icon: <FileText className="w-4 h-4" />, section: 'REPORTING' },
  { label: 'Evidence', href: '/evidence', icon: <ClipboardList className="w-4 h-4" /> },
  { label: 'Audit Logs', href: '/audit-logs', icon: <Activity className="w-4 h-4" /> },
  { label: 'Settings', href: '/settings', icon: <Settings className="w-4 h-4" />, section: 'SYSTEM' },
];

export default function Sidebar() {
  const pathname = usePathname();
  const router = useRouter();
  const [user, setUser] = useState<{ name: string; role: string; initials: string; email?: string } | null>(null);
  const [showUserMenu, setShowUserMenu] = useState(false);
  const [caseBadge] = useState<number | null>(null);

  useEffect(() => {
    if (typeof window !== 'undefined') {
      const stored = localStorage.getItem('mt_user');
      if (stored) {
        const u = JSON.parse(stored);
        setUser({
          name: u.name || 'User',
          role: u.role || 'ANALYST',
          email: u.email,
          initials: u.initials || u.name?.split(' ').map((n: string) => n[0]).join('').toUpperCase() || 'U',
        });
      }
    }
  }, []);

  const handleLogout = async () => {
    try {
      await authAPI.logout();
    } catch { /* ignore */ }
    localStorage.removeItem('mt_token');
    localStorage.removeItem('mt_user');
    router.push('/login');
  };

  const getRoleLabel = (role: string) => {
    switch (role) {
      case 'ADMINISTRATOR': return 'Administrator';
      case 'SENIOR_ANALYST': return 'Senior Analyst';
      case 'ANALYST': return 'Analyst';
      default: return role;
    }
  };

  return (
    <aside className="fixed inset-y-0 left-0 w-[260px] bg-[#0f172a] flex flex-col shadow-xl z-30 border-r border-slate-800">
      {/* Logo */}
      <div className="h-14 flex items-center px-5 border-b border-slate-800 flex-shrink-0">
        <div className="flex items-center gap-2.5">
          <div className="w-8 h-8 bg-blue-600 rounded-lg flex items-center justify-center relative flex-shrink-0">
            <ShieldCheck className="w-4 h-4 text-white" />
            <div className="absolute -top-0.5 -right-0.5 w-3 h-3 bg-emerald-400 rounded-full border-2 border-[#0f172a]" />
          </div>
          <div>
            <span className="text-base font-bold text-white">
              MailTrace <span className="text-blue-400">AI</span>
            </span>
            <div className="text-[9px] text-slate-500 font-medium -mt-0.5">SIH 2026 PROTOTYPE</div>
          </div>
        </div>
      </div>

      {/* Navigation */}
      <nav className="flex-1 overflow-y-auto py-3 px-2.5">
        {navItems.map((item, idx) => {
          const isActive = pathname === item.href || pathname.startsWith(item.href + '/');
          const prevItem = navItems[idx - 1];
          const showSection = item.section && item.section !== prevItem?.section;

          return (
            <div key={item.href}>
              {showSection && (
                <div className="px-3 pt-4 pb-1.5">
                  <span className="text-[9px] font-bold text-slate-600 uppercase tracking-widest">
                    {item.section}
                  </span>
                </div>
              )}
              <Link
                href={item.href}
                className={`flex items-center gap-2.5 px-3 py-2 rounded-lg mb-0.5 transition-all duration-150 group relative text-sm ${
                  isActive
                    ? 'bg-blue-600/15 text-white border border-blue-500/20'
                    : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/60'
                }`}
              >
                {isActive && (
                  <div className="absolute left-0 top-1/2 -translate-y-1/2 w-0.5 h-4 bg-blue-400 rounded-r-full" />
                )}
                <span className={`flex-shrink-0 ${isActive ? 'text-blue-400' : 'text-slate-500 group-hover:text-slate-400'}`}>
                  {item.icon}
                </span>
                <span className="font-medium flex-1 text-sm">{item.label}</span>
                {item.badge !== null && item.badge !== undefined && (
                  <span className="text-[10px] bg-slate-700 text-slate-300 px-1.5 py-0.5 rounded-full font-medium">
                    {item.badge}
                  </span>
                )}
                {caseBadge !== null && item.href === '/cases' && (
                  <span className="text-[10px] bg-red-500/20 text-red-400 border border-red-500/30 px-1.5 py-0.5 rounded-full font-medium">
                    {caseBadge}
                  </span>
                )}
              </Link>
            </div>
          );
        })}
      </nav>

      {/* System status */}
      <div className="px-4 py-2 border-t border-slate-800">
        <div className="flex items-center gap-2">
          <div className="w-1.5 h-1.5 bg-emerald-500 rounded-full animate-pulse" />
          <span className="text-[10px] text-slate-500 font-medium">All systems operational</span>
        </div>
      </div>

      {/* User profile */}
      <div className="px-2.5 pb-3 border-t border-slate-800 pt-2 relative">
        <button
          onClick={() => setShowUserMenu(!showUserMenu)}
          className="w-full flex items-center gap-2.5 px-3 py-2 rounded-lg hover:bg-slate-800 transition-colors group"
        >
          <div className="w-7 h-7 rounded-full bg-blue-600 flex items-center justify-center text-white text-xs font-bold flex-shrink-0">
            {user?.initials ?? 'U'}
          </div>
          <div className="flex-1 text-left min-w-0">
            <div className="text-sm font-semibold text-slate-300 truncate">{user?.name ?? 'User'}</div>
            <div className="text-[10px] text-slate-500">{getRoleLabel(user?.role ?? 'ANALYST')}</div>
          </div>
          <ChevronDown className={`w-3.5 h-3.5 text-slate-500 group-hover:text-slate-400 transition-all duration-200 ${showUserMenu ? 'rotate-180' : ''}`} />
        </button>

        {showUserMenu && (
          <div className="absolute bottom-full left-2 right-2 mb-1 bg-[#1e293b] border border-slate-700 rounded-xl shadow-2xl overflow-hidden z-50">
            <div className="px-4 py-3 border-b border-slate-700">
              <div className="text-sm font-semibold text-white">{user?.name}</div>
              <div className="text-xs text-slate-400">{user?.email}</div>
              <div className="text-[10px] text-blue-400 font-medium mt-0.5">{getRoleLabel(user?.role ?? '')}</div>
            </div>
            <div className="p-1.5">
              <Link
                href="/settings"
                onClick={() => setShowUserMenu(false)}
                className="flex items-center gap-2.5 px-3 py-2 rounded-lg text-sm text-slate-300 hover:bg-slate-700 hover:text-white transition-colors"
              >
                <User className="w-4 h-4 text-slate-400" />
                Account settings
              </Link>
              <button
                onClick={handleLogout}
                className="w-full flex items-center gap-2.5 px-3 py-2 rounded-lg text-sm text-red-400 hover:bg-red-500/10 hover:text-red-300 transition-colors"
              >
                <LogOut className="w-4 h-4" />
                Sign out
              </button>
            </div>
          </div>
        )}
      </div>
    </aside>
  );
}

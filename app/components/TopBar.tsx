'use client';

import { Bell, Search, X, ChevronRight, Shield, Briefcase, Globe } from 'lucide-react';
import { useEffect, useState, useRef, useCallback } from 'react';
import { useRouter } from 'next/navigation';
import { searchAPI, notificationsAPI, type SearchResult, type Notification } from '@/lib/api';

interface TopBarProps {
  breadcrumb: string;
}

export default function TopBar({ breadcrumb }: TopBarProps) {
  const router = useRouter();
  const [user, setUser] = useState<{ name: string; role: string; initials: string } | null>(null);
  const [searchQuery, setSearchQuery] = useState('');
  const [searchResults, setSearchResults] = useState<SearchResult[]>([]);
  const [showSearch, setShowSearch] = useState(false);
  const [searchLoading, setSearchLoading] = useState(false);
  const [notifications, setNotifications] = useState<Notification[]>([]);
  const [showNotifs, setShowNotifs] = useState(false);
  const [unreadCount, setUnreadCount] = useState(0);
  const searchRef = useRef<HTMLDivElement>(null);
  const notifRef = useRef<HTMLDivElement>(null);
  const searchTimeout = useRef<NodeJS.Timeout | null>(null);

  useEffect(() => {
    if (typeof window !== 'undefined') {
      const stored = localStorage.getItem('mt_user');
      if (stored) {
        setUser(JSON.parse(stored));
      } else {
        setUser({ name: 'Alex Morgan', role: 'Administrator', initials: 'AM' });
      }
    }
    loadNotifications();
  }, []);

  const loadNotifications = async () => {
    try {
      const data = await notificationsAPI.list();
      setNotifications(data);
      setUnreadCount(data.filter(n => !n.read).length);
    } catch {
      // Use demo notifications if backend unavailable
      setNotifications(DEMO_NOTIFICATIONS);
      setUnreadCount(DEMO_NOTIFICATIONS.filter(n => !n.read).length);
    }
  };

  const DEMO_NOTIFICATIONS: Notification[] = [
    { id: 'n1', user_id: '', title: 'Critical Threat Detected', message: 'BEC email from micros0ft-secure.com scored 94/100', type: 'critical', read: false, created_at: new Date(Date.now() - 3600000).toISOString(), case_id: 'MT-2026-00124' },
    { id: 'n2', user_id: '', title: 'Case Escalated', message: 'Case MT-2026-00120 escalated to Senior Analyst', type: 'warning', read: false, created_at: new Date(Date.now() - 7200000).toISOString() },
    { id: 'n3', user_id: '', title: 'Analysis Complete', message: 'Demo email analysis completed successfully', type: 'info', read: true, created_at: new Date(Date.now() - 86400000).toISOString() },
  ];

  const handleSearch = useCallback(async (q: string) => {
    setSearchQuery(q);
    if (searchTimeout.current) clearTimeout(searchTimeout.current);
    if (q.length < 2) { setSearchResults([]); return; }
    
    searchTimeout.current = setTimeout(async () => {
      setSearchLoading(true);
      try {
        const results = await searchAPI.global(q);
        setSearchResults(results);
      } catch {
        // Demo results if backend unavailable
        setSearchResults([
          { type: 'case', id: 'MT-2026-00124', title: 'MT-2026-00124', subtitle: 'Urgent Vendor Payment Approval', url: '/cases' },
          { type: 'ioc', id: '1', title: 'micros0ft-secure.com', subtitle: 'domain', url: '/threat-intelligence' },
        ].filter(r => r.title.toLowerCase().includes(q.toLowerCase()) || r.subtitle.toLowerCase().includes(q.toLowerCase())));
      } finally {
        setSearchLoading(false);
      }
    }, 300);
  }, []);

  // Close on outside click
  useEffect(() => {
    const handler = (e: MouseEvent) => {
      if (searchRef.current && !searchRef.current.contains(e.target as Node)) {
        setShowSearch(false);
        setSearchQuery('');
        setSearchResults([]);
      }
      if (notifRef.current && !notifRef.current.contains(e.target as Node)) {
        setShowNotifs(false);
      }
    };
    document.addEventListener('mousedown', handler);
    return () => document.removeEventListener('mousedown', handler);
  }, []);

  const getNotifIcon = (type: string) => {
    switch (type) {
      case 'critical': return <span className="w-2 h-2 bg-red-500 rounded-full" />;
      case 'warning': return <span className="w-2 h-2 bg-orange-400 rounded-full" />;
      default: return <span className="w-2 h-2 bg-blue-400 rounded-full" />;
    }
  };

  const getResultIcon = (type: string) => {
    switch (type) {
      case 'case': return <Briefcase className="w-3.5 h-3.5 text-blue-500" />;
      case 'ioc': return <Shield className="w-3.5 h-3.5 text-red-500" />;
      default: return <Globe className="w-3.5 h-3.5 text-slate-400" />;
    }
  };

  const timeAgo = (iso: string) => {
    const diff = Date.now() - new Date(iso).getTime();
    if (diff < 3600000) return `${Math.floor(diff / 60000)}m ago`;
    if (diff < 86400000) return `${Math.floor(diff / 3600000)}h ago`;
    return `${Math.floor(diff / 86400000)}d ago`;
  };

  return (
    <header className="h-14 bg-white border-b border-slate-200 flex items-center justify-between px-5 fixed top-0 right-0 left-[260px] z-20 shadow-sm">
      {/* Breadcrumb */}
      <div className="flex items-center gap-2 text-sm">
        <span className="text-slate-400">Workspace</span>
        <ChevronRight className="w-3.5 h-3.5 text-slate-300" />
        <span className="text-slate-700 font-semibold">{breadcrumb}</span>
      </div>

      {/* Right section */}
      <div className="flex items-center gap-2">
        {/* Search */}
        <div className="relative" ref={searchRef}>
          <div
            className="flex items-center gap-2 px-3 py-1.5 bg-slate-50 border border-slate-200 rounded-lg text-sm text-slate-400 hover:bg-slate-100 transition-colors cursor-pointer w-56"
            onClick={() => setShowSearch(true)}
          >
            <Search className="w-3.5 h-3.5 flex-shrink-0" />
            {showSearch ? (
              <input
                autoFocus
                value={searchQuery}
                onChange={e => handleSearch(e.target.value)}
                placeholder="Search cases, IOCs, domains..."
                className="flex-1 bg-transparent outline-none text-slate-700 text-sm"
                onClick={e => e.stopPropagation()}
              />
            ) : (
              <span className="flex-1">Search anything</span>
            )}
            {searchQuery && (
              <button onClick={() => { setSearchQuery(''); setSearchResults([]); }} className="text-slate-400 hover:text-slate-600">
                <X className="w-3 h-3" />
              </button>
            )}
            {!showSearch && (
              <div className="flex items-center gap-0.5 bg-white border border-slate-200 rounded px-1 py-0.5 text-[10px] text-slate-400">
                ⌘K
              </div>
            )}
          </div>

          {/* Search results dropdown */}
          {showSearch && searchQuery.length >= 2 && (
            <div className="absolute top-full left-0 right-0 mt-1 bg-white border border-slate-200 rounded-xl shadow-lg z-50 overflow-hidden">
              {searchLoading ? (
                <div className="px-4 py-3 text-sm text-slate-400 flex items-center gap-2">
                  <div className="w-3 h-3 border-2 border-slate-300 border-t-blue-500 rounded-full animate-spin" />
                  Searching...
                </div>
              ) : searchResults.length > 0 ? (
                <div>
                  {searchResults.map(r => (
                    <button
                      key={r.id}
                      onClick={() => { router.push(r.url); setShowSearch(false); setSearchQuery(''); setSearchResults([]); }}
                      className="w-full flex items-center gap-3 px-4 py-2.5 hover:bg-slate-50 transition-colors text-left"
                    >
                      {getResultIcon(r.type)}
                      <div className="flex-1 min-w-0">
                        <div className="text-sm font-medium text-slate-700 truncate">{r.title}</div>
                        <div className="text-xs text-slate-400 truncate">{r.subtitle}</div>
                      </div>
                      <span className="text-[10px] bg-slate-100 text-slate-500 px-1.5 py-0.5 rounded capitalize">{r.type}</span>
                    </button>
                  ))}
                </div>
              ) : (
                <div className="px-4 py-3 text-sm text-slate-400">No results for &ldquo;{searchQuery}&rdquo;</div>
              )}
            </div>
          )}
        </div>

        {/* Notifications */}
        <div className="relative" ref={notifRef}>
          <button
            onClick={() => setShowNotifs(!showNotifs)}
            className="relative w-8 h-8 flex items-center justify-center rounded-lg hover:bg-slate-100 transition-colors"
          >
            <Bell className="w-4 h-4 text-slate-600" />
            {unreadCount > 0 && (
              <span className="absolute top-1 right-1 w-2 h-2 bg-red-500 rounded-full border border-white" />
            )}
          </button>

          {showNotifs && (
            <div className="absolute top-full right-0 mt-1 w-80 bg-white border border-slate-200 rounded-xl shadow-lg z-50 overflow-hidden">
              <div className="px-4 py-3 border-b border-slate-100 flex items-center justify-between">
                <span className="text-sm font-semibold text-slate-700">Notifications</span>
                {unreadCount > 0 && <span className="text-xs text-blue-600 font-medium">{unreadCount} unread</span>}
              </div>
              <div className="max-h-72 overflow-y-auto">
                {notifications.length > 0 ? notifications.map(n => (
                  <div
                    key={n.id}
                    className={`px-4 py-3 border-b border-slate-50 hover:bg-slate-50 transition-colors cursor-pointer ${!n.read ? 'bg-blue-50/40' : ''}`}
                    onClick={async () => {
                      try { await notificationsAPI.markRead(n.id); } catch {}
                      setNotifications(prev => prev.map(x => x.id === n.id ? { ...x, read: true } : x));
                      setUnreadCount(prev => Math.max(0, prev - 1));
                      if (n.case_id) { router.push('/cases'); setShowNotifs(false); }
                    }}
                  >
                    <div className="flex items-start gap-2.5">
                      <div className="mt-1.5">{getNotifIcon(n.type)}</div>
                      <div className="flex-1 min-w-0">
                        <div className="text-sm font-medium text-slate-700">{n.title}</div>
                        <div className="text-xs text-slate-500 mt-0.5 truncate">{n.message}</div>
                        <div className="text-[10px] text-slate-400 mt-1">{timeAgo(n.created_at)}</div>
                      </div>
                    </div>
                  </div>
                )) : (
                  <div className="px-4 py-6 text-center text-sm text-slate-400">No notifications</div>
                )}
              </div>
              <div className="px-4 py-2.5 border-t border-slate-100">
                <span className="text-xs text-slate-400">Showing {notifications.length} notifications</span>
              </div>
            </div>
          )}
        </div>

        {/* System status indicator */}
        <div className="flex items-center gap-1.5 px-2 py-1 bg-emerald-50 border border-emerald-200 rounded-lg">
          <div className="w-1.5 h-1.5 bg-emerald-500 rounded-full animate-pulse" />
          <span className="text-[10px] text-emerald-700 font-medium hidden lg:block">Online</span>
        </div>

        {/* Profile display */}
        <div className="flex items-center gap-2 px-2 py-1 rounded-lg bg-slate-50 border border-slate-200">
          <div className="w-6 h-6 rounded-full bg-blue-600 flex items-center justify-center text-white text-xs font-bold">
            {user?.initials ?? 'AM'}
          </div>
          <span className="text-xs font-medium text-slate-700 hidden md:block">{user?.name?.split(' ')[0] ?? ''}</span>
        </div>
      </div>
    </header>
  );
}

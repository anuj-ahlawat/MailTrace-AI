'use client';

import { Bell, Search, ChevronDown, Command } from 'lucide-react';
import { useEffect, useState } from 'react';

interface TopBarProps {
  breadcrumb: string;
}

export default function TopBar({ breadcrumb }: TopBarProps) {
  const [user, setUser] = useState<{ name: string; role: string; initials: string } | null>(null);

  useEffect(() => {
    if (typeof window !== 'undefined') {
      const stored = localStorage.getItem('mt_user');
      if (stored) {
        setUser(JSON.parse(stored));
      } else {
        setUser({ name: 'Alex Morgan', role: 'Administrator', initials: 'AM' });
      }
    }
  }, []);

  return (
    <header className="h-14 bg-white border-b border-slate-200 flex items-center justify-between px-6 fixed top-0 right-0 left-[280px] z-20">
      {/* Breadcrumb */}
      <div className="flex items-center gap-2 text-sm">
        <span className="text-slate-400">Workspace</span>
        <span className="text-slate-300">›</span>
        <span className="text-slate-700 font-semibold">{breadcrumb}</span>
      </div>

      {/* Right section */}
      <div className="flex items-center gap-3">
        {/* Search */}
        <div className="flex items-center gap-2 px-3 py-1.5 bg-slate-50 border border-slate-200 rounded-lg text-sm text-slate-400 hover:bg-slate-100 transition-colors cursor-pointer w-52">
          <Search className="w-3.5 h-3.5 flex-shrink-0" />
          <span className="flex-1">Search anything</span>
          <div className="flex items-center gap-0.5 bg-white border border-slate-200 rounded px-1 py-0.5">
            <Command className="w-2.5 h-2.5" />
            <span className="text-xs">K</span>
          </div>
        </div>

        {/* Notifications */}
        <button className="relative w-8 h-8 flex items-center justify-center rounded-lg hover:bg-slate-100 transition-colors">
          <Bell className="w-4 h-4 text-slate-600" />
          <span className="absolute top-1.5 right-1.5 w-1.5 h-1.5 bg-red-500 rounded-full" />
        </button>

        {/* Profile */}
        <button className="flex items-center gap-2 px-2 py-1 rounded-lg hover:bg-slate-100 transition-colors">
          <div className="w-7 h-7 rounded-full bg-blue-600 flex items-center justify-center text-white text-xs font-bold">
            {user?.initials ?? 'AM'}
          </div>
          <ChevronDown className="w-3.5 h-3.5 text-slate-400" />
        </button>
      </div>
    </header>
  );
}

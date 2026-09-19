'use client';
import Link from 'next/link';
import { usePathname, useRouter } from 'next/navigation';
import { createContext, useContext, useEffect, useState } from 'react';
import { ShieldCheck, LayoutDashboard, Mail, Briefcase, Network, MapPin, Shield, Bell, FileText, Fingerprint, Settings, Users, ScrollText, Inbox, LogOut, Search, Menu } from 'lucide-react';
import { api, post, User, ApiError } from '@/lib/platform';
const UserContext = createContext<User | null>(null);
export const useUser = () => useContext(UserContext);
const nav = [
  ['/overview', 'Overview', LayoutDashboard], ['/analyze', 'Ingest email', Mail], ['/emails', 'Email investigations', Mail],
  ['/cases', 'Cases', Briefcase], ['/alerts', 'Alerts', Bell], ['/graph', 'Infrastructure', Network], ['/geolocation', 'Network locations', MapPin],
  ['/threat-intelligence', 'Threat intelligence', Shield], ['/evidence', 'Evidence', Fingerprint], ['/reports', 'Reports', FileText],
  ['/gmail-inbox', 'Gmail import', Inbox], ['/account', 'Account security', ShieldCheck], ['/admin/users', 'Users', Users], ['/audit-logs', 'Audit trail', ScrollText], ['/settings', 'Settings', Settings],
] as const;
export default function Workspace({ children }: { children: React.ReactNode }) {
  const [user, setUser] = useState<User | null>(null); const [error, setError] = useState(''); const [open, setOpen] = useState(false);
  const [query, setQuery] = useState(''); const [results, setResults] = useState<{ id: string; title: string; type: string; url: string }[]>([]);
  const router = useRouter(); const path = usePathname();
  useEffect(() => { api<User>('/auth/me').then(setUser).catch(e => { if (e instanceof ApiError && e.status === 401) router.replace('/login'); else setError(e.message); }); }, [router]);
  useEffect(() => { if (query.length < 2) return; let active = true; const timer = setTimeout(() => { api<typeof results>(`/search?q=${encodeURIComponent(query)}`).then(r => { if (active) setResults(r); }).catch(() => { if (active) setResults([]); }); }, 250); return () => { active = false; clearTimeout(timer); }; }, [query]);
  if (!user) return <div className="soc-loading"><ShieldCheck size={32}/><h1>MailTrace AI</h1><p>{error || 'Verifying your session…'}</p>{error && <button onClick={() => location.reload()}>Retry connection</button>}</div>;
  const restricted = ['/settings', '/admin', '/audit-logs'].some(p => path.startsWith(p));
  return <UserContext.Provider value={user}><div className="soc-shell">
    <aside className={`soc-sidebar ${open ? 'is-open' : ''}`}><Link className="soc-brand" href="/overview"><ShieldCheck/><span>MailTrace <b>AI</b><small>EMAIL FORENSICS WORKSPACE</small></span></Link>
      <div className="soc-nav-label">INVESTIGATION WORKSPACE</div><nav>{nav.filter(([href]) => user.role === 'ADMINISTRATOR' || !['/admin/users', '/settings', '/audit-logs'].includes(href)).map(([href,label,Icon]) => <Link key={href} href={href} onClick={() => setOpen(false)} className={path === href || path.startsWith(href + '/') ? 'active' : ''}><Icon size={17}/>{label}</Link>)}</nav>
      <div className="soc-profile"><strong>{user.name}</strong><small>{user.role.replaceAll('_',' ')}</small><button onClick={async () => { try { await post('/auth/logout'); router.replace('/login'); } catch(e) { setError((e as Error).message); } }}><LogOut size={14}/> Sign out</button>{error && <p role="alert">{error}</p>}</div>
    </aside><div className="soc-main"><header className="soc-topbar"><button className="soc-menu" onClick={() => setOpen(!open)} aria-label="Toggle navigation"><Menu/></button><div className="soc-search"><Search size={16}/><input aria-label="Global search" placeholder="Search cases, email IDs, senders, domains, hashes…" value={query} onChange={e => {setQuery(e.target.value);setResults([]);}}/>{query.length >= 2 && <div className="soc-search-results">{results.length ? results.map(r => <Link key={r.type+r.id} href={r.url} onClick={() => setQuery('')}><small>{r.type}</small>{r.title || r.id}</Link>) : <span>No matching records</span>}</div>}</div><span className="soc-passive">PASSIVE ANALYSIS</span></header>
      <main className="soc-content">{restricted && user.role !== 'ADMINISTRATOR' ? <div className="soc-error">Administrator access required.</div> : children}</main>
    </div></div></UserContext.Provider>;
}

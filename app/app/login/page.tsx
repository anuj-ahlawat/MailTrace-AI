'use client';
import { useState } from 'react';
import { useRouter } from 'next/navigation';
import { ShieldCheck } from 'lucide-react';
import { post } from '@/lib/platform';
export default function Login() {
  const router = useRouter(); const [email,setEmail]=useState(''); const [password,setPassword]=useState('');const [error,setError]=useState('');const [busy,setBusy]=useState(false);
  return <div className="soc-login"><div className="soc-login-panel"><ShieldCheck size={40}/><p className="soc-eyebrow">MAILTRACE AI / SECURE WORKSPACE</p><h1>Email evidence.<br/>Clearer investigations.</h1><p>Sign in to examine threats, connect infrastructure, and preserve your findings.</p><form onSubmit={async e => {e.preventDefault();setBusy(true);setError('');try{await post('/auth/login',{email,password});router.replace('/overview');}catch(e){setError((e as Error).message);}finally{setBusy(false);}}}><label>Work email<input type="email" autoComplete="username" required value={email} onChange={e=>setEmail(e.target.value)}/></label><label>Password<input type="password" autoComplete="current-password" required value={password} onChange={e=>setPassword(e.target.value)}/></label>{error && <p className="soc-error" role="alert">{error}</p>}<button className="soc-primary" disabled={busy}>{busy?'Signing in…':'Sign in to workspace'}</button></form><small>Access is provisioned by your administrator. All investigation activity is audited.</small></div><div className="soc-login-art"><div className="soc-orbit"><ShieldCheck size={90}/></div><span>OBSERVE · CORRELATE · EXPLAIN</span><h2>Follow the evidence.</h2><p>One connected workflow from original email to forensic report.</p></div></div>;
}
